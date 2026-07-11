#!/usr/bin/python3
import base64
import json
import errno
import os
import stat
import sys

MAX_SYMLINK_DEPTH = 4
PLATFORM_SYMLINKS = {
    "darwin": {
        "/etc": "private/etc",
        "/tmp": "private/tmp",
        "/var": "private/var",
    }
}


def fail(message):
    print(f"ERROR {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def split_absolute(path):
    return [component for component in os.path.normpath(path).split(os.sep) if component]


def hook(name, enabled):
    if name not in enabled:
        return
    print(f"HOOK {name}", file=sys.stderr, flush=True)
    if sys.stdin.buffer.read(1) != b"1":
        fail(f"owned JSON test hook {name} synchronization failed")


def verify_directory(path, metadata, expected_uid):
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"unsafe parent is not a directory: {path}")
    if metadata.st_uid not in (0, expected_uid):
        fail(f"owned JSON owner mismatch (unsafe parent owner): {path}")
    writable_by_others = metadata.st_mode & 0o022 != 0
    root_sticky = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX != 0
    if writable_by_others and not root_sticky:
        fail(f"unsafe parent mode: {path}")


def open_verified_parent(path, expected_uid):
    components = split_absolute(path)
    if not components:
        fail("owned JSON path invalid")
    final_name = components.pop()
    platform_links = PLATFORM_SYMLINKS.get(sys.platform, {})
    for _ in range(MAX_SYMLINK_DEPTH + 1):
        current_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        verify_directory(os.sep, os.fstat(current_fd), expected_uid)
        logical = ""
        restarted = False
        for index, component in enumerate(components):
            logical += os.sep + component
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except OSError as error:
                try:
                    metadata = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except OSError:
                    os.close(current_fd)
                    raise error
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(component, dir_fd=current_fd)
                    expected_target = platform_links.get(logical)
                    os.close(current_fd)
                    if metadata.st_uid != 0 or expected_target is None or target != expected_target:
                        fail(f"unsafe parent symbolic link: {logical}")
                    components = split_absolute(target) + components[index + 1 :]
                    restarted = True
                    break
                os.close(current_fd)
                raise error
            os.close(current_fd)
            current_fd = next_fd
            verify_directory(logical, os.fstat(current_fd), expected_uid)
        if not restarted:
            return current_fd, final_name
    fail("unsafe parent symbolic link depth exceeded")


def validate_file(path, metadata, expected_uid, max_bytes):
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"owned JSON must be a regular file: {path}")
    if metadata.st_nlink != 1:
        fail(f"owned JSON link count must be one: {path}")
    if metadata.st_uid != expected_uid:
        fail(f"owned JSON owner mismatch: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"owned JSON mode must be 0600: {path}")
    if metadata.st_size > max_bytes:
        fail(f"owned JSON size limit exceeded: {path}")


def stable_metadata(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
    )


def main():
    if len(sys.argv) != 4:
        fail("owned JSON secure-open helper arguments invalid")
    path = os.path.abspath(sys.argv[1])
    expected_uid = int(sys.argv[2])
    max_bytes = int(sys.argv[3])
    enabled_hooks = set(filter(None, os.environ.get("AGNET_SECURE_OPEN_HOOKS", "").split(",")))
    parent_fd, final_name = open_verified_parent(path, expected_uid)
    try:
        hook("afterParentVerified", enabled_hooks)
        try:
            file_fd = os.open(
                final_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent_fd,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                fail(f"owned JSON no-follow open rejected symbolic link: {path}")
            raise
    finally:
        os.close(parent_fd)
    try:
        initial = os.fstat(file_fd)
        validate_file(path, initial, expected_uid, max_bytes)
        hook("afterInitialStat", enabled_hooks)
        chunks = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(file_fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            fail(f"owned JSON size limit exceeded: {path}")
        hook("afterRead", enabled_hooks)
        completed = os.fstat(file_fd)
        if stable_metadata(initial) != stable_metadata(completed):
            fail(f"owned JSON changed during read: {path}")
        data = b"".join(chunks)
        print(json.dumps({
            "data": base64.urlsafe_b64encode(data).decode("ascii").rstrip("="),
            "evidence": {
                "path": path,
                "device": initial.st_dev,
                "inode": initial.st_ino,
                "uid": initial.st_uid,
                "mode": stat.S_IMODE(initial.st_mode),
                "nlink": initial.st_nlink,
            },
        }, separators=(",", ":")))
    finally:
        os.close(file_fd)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as error:
        fail(str(error))
