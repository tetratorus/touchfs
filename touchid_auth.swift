import LocalAuthentication
import Foundation

let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
    fputs("Touch ID not available: \(error?.localizedDescription ?? "unknown")\n", stderr)
    exit(2)
}

let semaphore = DispatchSemaphore(value: 0)
var authSuccess = false

context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "Access .env secrets"
) { success, error in
    authSuccess = success
    if let error = error {
        fputs("Auth failed: \(error.localizedDescription)\n", stderr)
    }
    semaphore.signal()
}

semaphore.wait()
exit(authSuccess ? 0 : 1)
