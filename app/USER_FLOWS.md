# TouchFS App — User Flows

## 1. App Launch

1. App opens → "Checking..." → calls `touchfs status`
2. **Key exists** → Touch ID → Main view. Mount starts automatically.
3. **No key** → Onboarding.

## 2. Onboarding (No Key)

1. Welcome screen → "Continue"
2. Set password → enter + confirm → key stored in Keychain
3. → Main view (empty file list)

## 3. Protect Files

1. Click "Protect Files" in main view
2. File picker opens (multiselect, files only, no folders)
3. Selected files get sealed (encrypted in place)
4. Files appear in protected list
5. Mount restarts to include new files

## 4. Find Sealed Files (Scan)

1. Click "Find Sealed Files"
2. Directory picker → choose directory to scan
3. Progress indicator while scanning
4. Results shown — sealed files not yet managed
5. User selects which to import → added to list
6. Mount restarts

## 5. Unprotect File

1. Right-click file → "Unprotect"
2. File unsealed (decrypted back to plaintext)
3. Removed from list
4. Mount restarts

## 5a. Unprotect Fails (Wrong Key)

1. Right-click file → "Unprotect"
2. Decrypt fails (wrong password was used to create current key)
3. Error shown: "Decryption failed — file was sealed with a different password"
4. File stays in list, still sealed, unchanged
5. User needs to change password back to the original one, then retry

## 6. File Access (External App)

1. External app reads a sealed file
2. Touch ID prompt (500ms cache per file)
3. Authenticated → decrypted content served
4. Logged in Activity: file, time, "Opened"
5. Denied → access blocked, logged as "Denied"

## 7. File Modified (External App)

1. External app writes to a mounted file
2. On close → re-encrypted
3. Logged as "Modified" in Activity

## 8. Close Window

1. Close window (Cmd+W or red X)
2. App keeps running in menu bar
3. Mount stays active
4. Menu bar → "Open TouchFS" to reopen

## 9. Quit App

1. Cmd+Q or menu bar → "Quit"
2. SIGINT to mount → clean shutdown
3. Symlinks restored to sealed files
4. App exits

## 10. Crash / Force Quit

1. Mount dies without cleanup
2. Files left as broken symlinks
3. Next launch → auto-recovers from xattrs

## 11. Change Password

1. Settings → "Change Password"
2. Enter new password + confirm
3. Unseal all → set new key → re-seal all

## 12. Reset

1. Settings → "Reset TouchFS"
2. Confirmation dialog
3. All files unsealed, key deleted, config cleared
4. Back to onboarding

## 13. Menu Bar

- "Protecting N files"
- "Open TouchFS" → focus window
- "Quit TouchFS" → graceful shutdown

## 14. Open at Login

- Settings → toggle "Open at Login"
- Launches on login, sits in menu bar, mount starts
