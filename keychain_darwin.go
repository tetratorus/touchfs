package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation -framework LocalAuthentication

#include <stdlib.h>
#include <libproc.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

// touchid_auth prompts for Touch ID. Returns 1 on success, 0 on failure.
int touchid_auth(const char *reason) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSString *nsReason = [NSString stringWithUTF8String:reason];
    __block int result = 0;

    if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) {
        NSLog(@"touchfs: canEvaluatePolicy failed: %@", err);
        return 0;
    }

    [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
        localizedReason:nsReason
        reply:^(BOOL success, NSError *error) {
            if (success) {
                result = 1;
            } else {
                NSLog(@"touchfs: evaluatePolicy failed: %@ (code=%ld)", error.localizedDescription, (long)error.code);
                result = 0;
            }
            dispatch_semaphore_signal(sema);
        }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return result;
}

// keychain_store adds or updates the AES key in the Keychain with biometric protection.
int keychain_store(const void *data, int dataLen) {
    CFStringRef service = CFSTR("touchfs");
    CFStringRef account = CFSTR("default");

    // Create access control requiring biometry.
    CFErrorRef acError = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryAny,
        &acError);
    if (acError != NULL) {
        if (ac) CFRelease(ac);
        return -1;
    }

    CFDataRef cfData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)data, dataLen);

    const void *addKeys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount,
        kSecValueData, kSecAttrAccessControl,
    };
    const void *addValues[] = {
        kSecClassGenericPassword, service, account,
        cfData, ac,
    };
    CFDictionaryRef addQuery = CFDictionaryCreate(
        kCFAllocatorDefault, addKeys, addValues, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    OSStatus status = SecItemAdd(addQuery, NULL);
    CFRelease(addQuery);

    if (status == errSecDuplicateItem) {
        // Update existing item.
        const void *matchKeys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
        const void *matchValues[] = {kSecClassGenericPassword, service, account};
        CFDictionaryRef matchQuery = CFDictionaryCreate(
            kCFAllocatorDefault, matchKeys, matchValues, 3,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        const void *updateKeys[] = {kSecValueData, kSecAttrAccessControl};
        const void *updateValues[] = {cfData, ac};
        CFDictionaryRef updateAttrs = CFDictionaryCreate(
            kCFAllocatorDefault, updateKeys, updateValues, 2,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        status = SecItemUpdate(matchQuery, updateAttrs);
        CFRelease(matchQuery);
        CFRelease(updateAttrs);
    }

    CFRelease(cfData);
    CFRelease(ac);
    return (status == errSecSuccess) ? 0 : (int)status;
}

// keychain_load retrieves the AES key from the Keychain (triggers Touch ID).
// Returns 0 on success, 1 if not found, negative on error.
int keychain_load(void **outBuf, int *outLen) {
    CFStringRef service = CFSTR("touchfs");
    CFStringRef account = CFSTR("default");

    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount,
        kSecReturnData, kSecMatchLimit,
    };
    const void *values[] = {
        kSecClassGenericPassword, service, account,
        kCFBooleanTrue, kSecMatchLimitOne,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDataRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);
    CFRelease(query);

    if (status == errSecItemNotFound) {
        return 1;
    }
    if (status != errSecSuccess) {
        return -(int)status;
    }

    CFIndex len = CFDataGetLength(result);
    void *buf = malloc(len);
    CFDataGetBytes(result, CFRangeMake(0, len), (UInt8 *)buf);
    CFRelease(result);

    *outBuf = buf;
    *outLen = (int)len;
    return 0;
}

// keychain_delete removes the key from the Keychain.
int keychain_delete(void) {
    CFStringRef service = CFSTR("touchfs");
    CFStringRef account = CFSTR("default");

    const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
    const void *values[] = {kSecClassGenericPassword, service, account};
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);

    if (status == errSecItemNotFound) {
        return 0;
    }
    return (status == errSecSuccess) ? 0 : (int)status;
}

// keychain_has checks if a Keychain item exists without triggering Touch ID.
// Returns 1 if found, 0 if not.
int keychain_has(void) {
    CFStringRef service = CFSTR("touchfs");
    CFStringRef account = CFSTR("default");

    const void *keys[] = {
        kSecClass, kSecAttrService, kSecAttrAccount,
        kSecUseAuthenticationUI,
    };
    const void *values[] = {
        kSecClassGenericPassword, service, account,
        kSecUseAuthenticationUISkip,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    OSStatus status = SecItemCopyMatching(query, NULL);
    CFRelease(query);

    // errSecInteractionNotAllowed means the item exists but needs auth.
    return (status == errSecSuccess || status == errSecInteractionNotAllowed) ? 1 : 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// authenticateTouchID prompts for Touch ID via LAContext. Works from FUSE threads.
func authenticateTouchID(reason string) bool {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	return C.touchid_auth(cReason) == 1
}

// processName returns the name of the process with the given PID.
func processName(pid int) string {
	var buf [256]C.char
	n := C.proc_name(C.int(pid), unsafe.Pointer(&buf[0]), 256)
	if n <= 0 {
		return ""
	}
	return C.GoString(&buf[0])
}

// keychainStore saves the AES key in the macOS Keychain with biometric protection.
func keychainStore(key []byte) error {
	rc := C.keychain_store(unsafe.Pointer(&key[0]), C.int(len(key)))
	if rc != 0 {
		return fmt.Errorf("keychain store failed (OSStatus %d)", int(rc))
	}
	return nil
}

// keychainLoad retrieves the AES key from the Keychain, triggering Touch ID.
// Returns (nil, nil) if no Keychain entry exists.
func keychainLoad() ([]byte, error) {
	var buf unsafe.Pointer
	var length C.int

	rc := C.keychain_load(&buf, &length)
	if rc == 1 {
		return nil, nil // not found
	}
	if rc != 0 {
		return nil, fmt.Errorf("keychain load failed (code %d)", int(rc))
	}
	defer C.free(buf)

	return C.GoBytes(buf, length), nil
}

// keychainDelete removes the key from the Keychain.
func keychainDelete() error {
	rc := C.keychain_delete()
	if rc != 0 {
		return fmt.Errorf("keychain delete failed (OSStatus %d)", int(rc))
	}
	return nil
}

// keychainHas checks if a Keychain entry exists without triggering Touch ID.
func keychainHas() bool {
	return C.keychain_has() == 1
}
