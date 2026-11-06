package main

/*
#include <stdlib.h>
#include "warp_transport.h"

static inline bool amneziaWarpProtect(amnezia_warp_protect protect, int32_t socket, void *context)
{
	return protect == NULL || protect(socket, context);
}
*/
import "C"

import (
	"sync"
	"unsafe"

	"amnezia/warptransport"
)

var warpSessions = struct {
	sync.RWMutex
	next   int32
	values map[int32]*warptransport.Session
}{values: make(map[int32]*warptransport.Session)}

//export amneziaWarpStart
func amneziaWarpStart(underlay, protocol, configuration *C.char, protect C.amnezia_warp_protect, context unsafe.Pointer) C.int32_t {
	session, err := warptransport.Start(C.GoString(underlay), C.GoString(protocol), C.GoString(configuration),
		func(socket int) bool { return bool(C.amneziaWarpProtect(protect, C.int32_t(socket), context)) })
	if err != nil {
		return -1
	}
	warpSessions.Lock()
	defer warpSessions.Unlock()
	warpSessions.next++
	if warpSessions.next < 1 {
		session.Close()
		return -1
	}
	handle := warpSessions.next
	warpSessions.values[handle] = session
	return C.int32_t(handle)
}

func warpSession(handle C.int32_t) *warptransport.Session {
	warpSessions.RLock()
	defer warpSessions.RUnlock()
	return warpSessions.values[int32(handle)]
}

//export amneziaWarpConfiguration
func amneziaWarpConfiguration(handle C.int32_t) *C.char {
	session := warpSession(handle)
	if session == nil {
		return nil
	}
	return C.CString(session.Configuration())
}

//export amneziaWarpState
func amneziaWarpState(handle C.int32_t) C.int32_t {
	session := warpSession(handle)
	if session == nil {
		return -1
	}
	return C.int32_t(session.State())
}

//export amneziaWarpRebind
func amneziaWarpRebind(handle C.int32_t) C.int32_t {
	session := warpSession(handle)
	if session == nil || session.Rebind() != nil {
		return -1
	}
	return 0
}

//export amneziaWarpStop
func amneziaWarpStop(handle C.int32_t) {
	warpSessions.Lock()
	session := warpSessions.values[int32(handle)]
	delete(warpSessions.values, int32(handle))
	warpSessions.Unlock()
	if session != nil {
		session.Close()
	}
}

//export amneziaWarpFree
func amneziaWarpFree(value *C.char) { C.free(unsafe.Pointer(value)) }
