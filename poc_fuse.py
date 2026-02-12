#!/usr/bin/env python3
"""
POC: FUSE filesystem that serves a virtual .env file, gated by Touch ID.
Every read triggers Touch ID — if you don't authenticate, the read fails.

Usage:
    python3 poc_fuse.py /tmp/secure-env
    # Then in another terminal: cat /tmp/secure-env/.env
"""

import os
import sys
import errno
import stat
import time
import subprocess

# Point fusepy to FUSE-T
os.environ['FUSE_LIBRARY_PATH'] = '/usr/local/lib/libfuse-t.dylib'

from fuse import FUSE, FuseOSError, Operations

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOUCHID_BIN = os.path.join(SCRIPT_DIR, 'touchid-auth')

# Hardcoded .env content for the POC
ENV_CONTENT = b"SECRET=hello123\nDB_HOST=localhost\n"


def require_touchid():
    """Returns True if Touch ID authentication succeeds."""
    try:
        result = subprocess.run([TOUCHID_BIN], timeout=30)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


class SecureEnvFS(Operations):
    """FUSE filesystem that serves .env gated by Touch ID."""

    def getattr(self, path, fh=None):
        now = time.time()
        if path == '/':
            return {
                'st_mode': stat.S_IFDIR | 0o755,
                'st_nlink': 2,
                'st_atime': now,
                'st_mtime': now,
                'st_ctime': now,
            }
        elif path == '/.env':
            return {
                'st_mode': stat.S_IFREG | 0o444,
                'st_nlink': 1,
                'st_size': len(ENV_CONTENT),
                'st_atime': now,
                'st_mtime': now,
                'st_ctime': now,
            }
        else:
            raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        if path == '/':
            return ['.', '..', '.env']
        raise FuseOSError(errno.ENOENT)

    def open(self, path, flags):
        if path == '/.env':
            ts = time.strftime('%H:%M:%S')
            print(f"[{ts}] OPEN  .env — requesting Touch ID...")
            if not require_touchid():
                print(f"[{ts}] DENIED — Touch ID failed")
                raise FuseOSError(errno.EACCES)
            print(f"[{ts}] GRANTED — Touch ID succeeded")
            return 0
        raise FuseOSError(errno.ENOENT)

    def read(self, path, size, offset, fh):
        if path == '/.env':
            ts = time.strftime('%H:%M:%S')
            print(f"[{ts}] READ  .env (offset={offset}, size={size})")
            return ENV_CONTENT[offset:offset + size]
        raise FuseOSError(errno.ENOENT)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <mountpoint>")
        sys.exit(1)

    mountpoint = sys.argv[1]
    os.makedirs(mountpoint, exist_ok=True)

    print(f"Mounting SecureEnvFS at {mountpoint}")
    print(f"Virtual file: {mountpoint}/.env")
    print(f"Touch ID required for every read.")
    print("Press Ctrl+C to unmount.\n")

    FUSE(SecureEnvFS(), mountpoint, foreground=True, nothreads=True)


if __name__ == '__main__':
    main()
