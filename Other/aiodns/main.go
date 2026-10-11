package main

import "C"

import "fmt"

const (
	TYPE_REST = iota
	TYPE_LIST
	TYPE_LISN
	TYPE_CDNS
	TYPE_ODNS
)

// The C ABI must match the managed enum (32 bits), not Go's pointer-sized int.
// The bool result is a GoUint8, marshalled as UnmanagedType.I1 by Netch.
//
//export aiodns_dial
func aiodns_dial(name C.int, value *C.char) (ok bool) {
	defer recoverExport(&ok)
	return configure(int(name), C.GoString(value))
}

//export aiodns_init
func aiodns_init() (ok bool) {
	defer recoverExport(&ok)
	return initialize()
}

//export aiodns_free
func aiodns_free() {
	defer recoverExport(nil)
	lifecycle.Lock()
	defer lifecycle.Unlock()
	stopLocked()
}

func recoverExport(ok *bool) {
	if err := recover(); err != nil {
		fmt.Printf("[aiodns] native call panic: %v\n", err)
		if ok != nil {
			*ok = false
		}
	}
}

func main() {}
