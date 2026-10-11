package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureWriter struct {
	dns.ResponseWriter
	reply        *dns.Msg
	panicOnWrite bool
}

func (w *captureWriter) WriteMsg(m *dns.Msg) error {
	if w.panicOnWrite {
		panic("broken writer")
	}
	if m == nil {
		panic("nil DNS reply")
	}
	w.reply = m
	return nil
}

func question(name string) *dns.Msg {
	return new(dns.Msg).SetQuestion(name, dns.TypeA)
}

func TestHandlerRecovery(t *testing.T) {
	for _, broken := range []bool{false, true} {
		w := &captureWriter{panicOnWrite: broken}
		h := protectHandler(dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { panic("handler failure") }))
		m := question("example.org.")
		h.ServeDNS(w, m)
		if !broken && (w.reply == nil || w.reply.Rcode != dns.RcodeServerFailure || w.reply.Id != m.Id) {
			t.Fatalf("expected matching SERVFAIL, got %v", w.reply)
		}
	}
}

func TestFailedUpstreamReturnsServfail(t *testing.T) {
	// A canceled context deterministically exercises the actual client error path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &captureWriter{}
	protectHandler(forward(ctx, upstream{"127.0.0.1:1", "tcp"})).ServeDNS(w, question("example.org."))
	if w.reply == nil || w.reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("reply = %v", w.reply)
	}
}

func testUpstream(t *testing.T, address string) upstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	s := &dns.Server{Listener: listener, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		r := new(dns.Msg).SetReply(m)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(address)}}
		_ = w.WriteMsg(r)
	})}
	go func() { done <- s.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = s.Shutdown(); <-done })
	return upstream{listener.Addr().String(), "tcp"}
}

func testConfig(t *testing.T) config {
	t.Helper()
	return config{listen: "127.0.0.1:0", china: testUpstream(t, "192.0.2.1"), other: testUpstream(t, "192.0.2.2")}
}

func TestRoutingTCPAndUDP(t *testing.T) {
	cfg := testConfig(t)
	cfg.path = filepath.Join(t.TempDir(), "规则.conf")
	if err := os.WriteFile(cfg.path, []byte("\uFEFFExample.cn.\n\n# comment\nexample.CN.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := startService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	for _, network := range []string{"tcp", "udp"} {
		for name, expected := range map[string]string{"sub.example.cn.": "192.0.2.1", "example.org.": "192.0.2.2"} {
			client := dns.Client{Net: network, Timeout: time.Second}
			r, _, err := client.Exchange(question(name), s.servers[0].server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != expected {
				t.Fatalf("%s/%s: %v", network, name, r)
			}
		}
	}
}

func TestRulesReadFailure(t *testing.T) {
	cfg := testConfig(t)
	cfg.path = filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(cfg.path, []byte(strings.Repeat("a", 70*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := startService(cfg); err == nil {
		s.stop()
		t.Fatal("scanner error was ignored")
	}
}

func TestUDPBindFailureReleasesTCP(t *testing.T) {
	cfg := testConfig(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	cfg.listen = udp.LocalAddr().String()
	if s, err := startService(cfg); err == nil {
		s.stop()
		t.Fatal("expected occupied UDP port to fail")
	}
	tcp, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		t.Fatalf("TCP listener leaked: %v", err)
	}
	tcp.Close()
}

func TestStopCancelsActiveRequestsAndConnections(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := up.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	cfg := config{listen: "127.0.0.1:0", china: upstream{up.Addr().String(), "tcp"}, other: upstream{up.Addr().String(), "tcp"}}
	s, err := startService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	address := s.servers[0].server.Listener.Addr().String()
	idle, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		client := dns.Client{Net: "tcp", Timeout: 2 * time.Second}
		_, _, _ = client.Exchange(question("example.org."), address)
	}()
	select {
	case c := <-accepted:
		defer c.Close() // Intentionally never answer the forwarded query.
	case <-time.After(2 * time.Second):
		s.stop()
		t.Fatal("upstream did not receive request")
	}
	started := time.Now()
	s.stop()
	if time.Since(started) > time.Second {
		t.Fatal("shutdown did not cancel the upstream read")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DNS request survived shutdown")
	}
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle accepted connection survived shutdown")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("idle connection was not closed")
	}
	cfg.listen = address
	next, err := startService(cfg)
	if err != nil {
		t.Fatalf("port cannot be reused: %v", err)
	}
	next.stop()
}

func TestConcurrentLifecycle(t *testing.T) {
	cfg := testConfig(t)
	aiodns_free()
	if !configure(TYPE_REST, "") || !configure(TYPE_LISN, cfg.listen) || !configure(TYPE_CDNS, "tcp://"+cfg.china.address) || !configure(TYPE_ODNS, "tcp://"+cfg.other.address) {
		t.Fatal("configuration failed")
	}
	t.Cleanup(aiodns_free)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if !aiodns_init() {
					t.Error("initialization failed")
				}
				aiodns_free()
			}
		}()
	}
	wg.Wait()
}

func TestRepeatedInitAndResetReleasePort(t *testing.T) {
	cfg := testConfig(t)
	aiodns_free()
	configure(TYPE_REST, "")
	configure(TYPE_LISN, cfg.listen)
	configure(TYPE_CDNS, "tcp://"+cfg.china.address)
	configure(TYPE_ODNS, "tcp://"+cfg.other.address)
	t.Cleanup(aiodns_free)
	if !aiodns_init() {
		t.Fatal("first init failed")
	}
	lifecycle.Lock()
	address := active.servers[0].server.Listener.Addr().String()
	settings.listen = address
	lifecycle.Unlock()
	if !aiodns_init() {
		t.Fatal("repeated init leaked port")
	}
	if configure(TYPE_ODNS, "tcp://127.0.0.1:1") {
		t.Fatal("changed a live configuration")
	}
	if !configure(TYPE_REST, "") {
		t.Fatal("reset failed")
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tcp.Close()
	if aiodns_init() {
		t.Fatal("empty configuration started")
	}
}

func TestUpstreamConfiguration(t *testing.T) {
	for _, input := range []string{"tcp://127.0.0.1:53", "tls://dns.example:853", "tcp://[::1]:53", "udp://127.0.0.1:53"} {
		u, err := parseUpstream(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if strings.HasPrefix(input, "tls://") && u.network != "tcp-tls" {
			t.Fatal("lost DNS-over-TLS")
		}
		if strings.HasPrefix(input, "udp://") && u.network != "tcp" {
			t.Fatal("changed legacy TCP fallback")
		}
	}
	for _, input := range []string{"", "127.0.0.1:53", "tcp://", "tcp://127.0.0.1:0", "tcp://127.0.0.1:65536", "tls://dns.example:abc"} {
		if _, err := parseUpstream(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestCancelTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := exchange(ctx, &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second}, question("example.org."), listener.Addr().String())
		done <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("TLS client did not connect")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled TLS handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt TLS handshake")
	}
}

func TestBundledRules(t *testing.T) {
	cfg := config{
		path:  "../../Storage/aiodns.conf",
		china: upstream{"127.0.0.1:1", "tcp"},
		other: upstream{"127.0.0.1:1", "tcp"},
	}
	if _, err := newHandler(context.Background(), cfg); err != nil {
		t.Fatalf("existing bundled rules are incompatible: %v", err)
	}
}
