package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#include <stdio.h>
#import <LocalAuthentication/LocalAuthentication.h>

int touchid_auth(char const* reason) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSString *nsReason = [NSString stringWithUTF8String:reason];
    __block int result = 0;

    if ([ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) {
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:nsReason
            reply:^(BOOL success, NSError *error) {
                result = success ? 1 : 0;
                dispatch_semaphore_signal(sema);
            }];
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    }
    return result;
}
*/
import "C"

import (
	"sync"
	"time"
	"unsafe"
)

var (
	authMu       sync.Mutex
	lastAuthTime time.Time
)

// authenticateTouchID prompts for Touch ID, with a TTL cache to avoid re-prompting.
func authenticateTouchID(reason string, ttl time.Duration) (bool, error) {
	authMu.Lock()
	defer authMu.Unlock()

	if time.Since(lastAuthTime) < ttl {
		return true, nil
	}

	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	result := C.touchid_auth(cReason)
	if result == 1 {
		lastAuthTime = time.Now()
		return true, nil
	}
	return false, nil
}
