package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type config struct {
	path, listen string
	china, other upstream
}

type upstream struct {
	address, network string
}

type runningServer struct {
	server *dns.Server
	done   chan error
}

type service struct {
	cancel  context.CancelFunc
	servers []runningServer
}

var (
	lifecycle sync.Mutex
	settings  config
	active    *service
)

func configure(name int, value string) bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if name == TYPE_REST {
		stopLocked()
		settings = config{}
		return true
	}
	// A running service owns an immutable configuration. Reset it before editing.
	if active != nil {
		return false
	}
	switch name {
	case TYPE_LIST:
		settings.path = value
	case TYPE_LISN:
		settings.listen = value
	case TYPE_CDNS, TYPE_ODNS:
		u, err := parseUpstream(value)
		if err != nil {
			fmt.Printf("[aiodns] invalid upstream: %v\n", err)
			return false
		}
		if name == TYPE_CDNS {
			settings.china = u
		} else {
			settings.other = u
		}
	default:
		return false
	}
	return true
}

func parseUpstream(value string) (upstream, error) {
	u, err := url.Parse(value)
	if err != nil {
		return upstream{}, err
	}
	// Preserve the existing tcp:// and tls:// configuration format and the
	// historical TCP fallback for non-TLS schemes.
	if u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return upstream{}, fmt.Errorf("invalid DNS URL %q", value)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return upstream{}, fmt.Errorf("invalid DNS port in %q", value)
	}
	network := "tcp"
	if u.Scheme == "tls" {
		network = "tcp-tls"
	}
	return upstream{address: u.Host, network: network}, nil
}

func initialize() bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	stopLocked()
	s, err := startService(settings)
	if err != nil {
		fmt.Printf("[aiodns] start failed: %v\n", err)
		return false
	}
	active = s
	fmt.Println("[aiodns] Started")
	return true
}

// Caller must hold lifecycle. Cancel in-flight upstream exchanges before
// shutting down the servers, including accepted TCP connections and handlers.
func stopLocked() {
	if active != nil {
		active.stop()
		active = nil
	}
}

func (s *service) stop() {
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, running := range s.servers {
		if err := running.server.ShutdownContext(ctx); err != nil {
			fmt.Printf("[aiodns] shutdown: %v\n", err)
		}
		select {
		case <-running.done:
		case <-ctx.Done():
		}
	}
}

func startService(cfg config) (_ *service, err error) {
	if cfg.listen == "" || cfg.china.address == "" || cfg.other.address == "" {
		return nil, fmt.Errorf("listen address and both upstreams are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{cancel: cancel}
	// Also roll back resources if a recoverable panic reaches the export boundary.
	committed := false
	defer func() {
		if !committed {
			s.stop()
		}
	}()
	mux, err := newHandler(ctx, cfg)
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !committed {
			tcp.Close()
		}
	}()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if !committed {
			udp.Close()
		}
	}()

	for _, server := range []*dns.Server{
		{Listener: tcp, Handler: protectHandler(mux)},
		{PacketConn: udp, Handler: protectHandler(mux)},
	} {
		ready := make(chan struct{})
		done := make(chan error, 1)
		server.NotifyStartedFunc = func() { close(ready) }
		go serve(server, done)
		select {
		case <-ready:
			s.servers = append(s.servers, runningServer{server, done})
		case err := <-done:
			return nil, fmt.Errorf("DNS listener failed to start: %v", err)
		}
	}
	committed = true
	return s, nil
}

func serve(server *dns.Server, done chan error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[aiodns] DNS serve panic: %v\n", err)
			done <- fmt.Errorf("DNS serve panic: %v", err)
		}
	}()
	err := server.ActivateAndServe()
	if err != nil {
		fmt.Printf("[aiodns] DNS serve: %v\n", err)
	}
	done <- err
}

func newHandler(ctx context.Context, cfg config) (*dns.ServeMux, error) {
	mux := dns.NewServeMux()
	china := forward(ctx, cfg.china)
	if cfg.path != "" {
		file, err := os.Open(cfg.path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scan := bufio.NewScanner(file)
		for scan.Scan() {
			domain := strings.TrimSpace(strings.TrimPrefix(scan.Text(), "\uFEFF"))
			if domain == "" || strings.HasPrefix(domain, "#") {
				continue
			}
			if _, ok := dns.IsDomainName(domain); !ok {
				return nil, fmt.Errorf("invalid DNS rule %q", domain)
			}
			mux.Handle(dns.Fqdn(domain), china)
		}
		if err := scan.Err(); err != nil {
			return nil, fmt.Errorf("read DNS rules: %w", err)
		}
	}
	mux.HandleFunc("in-addr.arpa.", handleServerName)
	mux.Handle(".", forward(ctx, cfg.other))
	return mux, nil
}

func forward(ctx context.Context, target upstream) dns.Handler {
	// Per-service values are never reset under an in-flight request.
	client := dns.Client{Net: target.network, Timeout: 3 * time.Second}
	return dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		r, err := exchange(ctx, &client, m, target.address)
		if err != nil || r == nil {
			fmt.Printf("[aiodns] upstream %s: %v\n", target.address, err)
			r = new(dns.Msg)
			r.SetRcode(m, dns.RcodeServerFailure)
		}
		_ = w.WriteMsg(r)
	})
}

func exchange(ctx context.Context, client *dns.Client, m *dns.Msg, address string) (*dns.Msg, error) {
	var conn *dns.Conn
	var err error
	if client.Net == "tcp-tls" {
		// v1.1.51's TLS DialContext does not propagate cancellation to the
		// handshake. Use the standard library's context-aware TLS dialer.
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: client.Timeout}, Config: client.TLSConfig}
		var raw net.Conn
		raw, err = dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn = &dns.Conn{Conn: raw}
		}
	} else {
		conn, err = client.DialContext(ctx, address)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	finished := make(chan struct{})
	defer close(finished)
	// This DNS library version only uses context cancellation while dialing.
	// Explicitly interrupt a read from a connected but unresponsive upstream.
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-finished:
		}
	}()
	r, _, err := client.ExchangeWithConn(m, conn)
	return r, err
}

func handleServerName(w dns.ResponseWriter, m *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(m)
	for _, q := range m.Question {
		if q.Qtype == dns.TypePTR {
			r.Answer = append(r.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: q.Qclass},
				Ptr: "Netch.",
			})
		}
	}
	_ = w.WriteMsg(r)
}

// Recovery has to run on the DNS request goroutine. Recovering in aiodns_init
// cannot contain a later handler panic in a c-shared library.
func protectHandler(next dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("[aiodns] handler panic: %v\n", err)
				writeFailure(w, m)
			}
		}()
		next.ServeDNS(w, m)
	})
}

func writeFailure(w dns.ResponseWriter, m *dns.Msg) {
	// A closed or broken writer must not panic again inside the recovery path.
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[aiodns] writing failure response: %v\n", err)
		}
	}()
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeServerFailure)
	_ = w.WriteMsg(r)
}
