#!/usr/bin/python3
import base64
import ctypes
import errno
import json
import os
import platform
import re
import stat
import sys

MAX_SYMLINK_DEPTH = 4
PLATFORM_SYMLINKS = {
    "darwin": {"/etc": "private/etc", "/tmp": "private/tmp", "/var": "private/var"},
}
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
RENAME_SWAP = 0x2
RENAME_EXCL = 0x4
RENAME_NOFOLLOW_ANY = 0x10


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
    if metadata.st_mode & 0o022 and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX):
        fail(f"unsafe parent mode: {path}")


def parse_expected_parent(device, inode):
    if device == "-" and inode == "-":
        return None
    try:
        expected = (int(device), int(inode))
    except ValueError:
        fail("owned JSON expected parent identity invalid")
    if expected[0] < 0 or expected[1] < 0:
        fail("owned JSON expected parent identity invalid")
    return expected


def open_verified_parent(path, expected_uid, expected_parent=None):
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
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current_fd)
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
                    components = split_absolute(target) + components[index + 1:]
                    restarted = True
                    break
                os.close(current_fd)
                raise error
            os.close(current_fd)
            current_fd = next_fd
            verify_directory(logical, os.fstat(current_fd), expected_uid)
        if not restarted:
            metadata = os.fstat(current_fd)
            if expected_parent is not None and (metadata.st_dev, metadata.st_ino) != expected_parent:
                os.close(current_fd)
                fail("owned JSON parent identity changed")
            return current_fd, final_name
    fail("unsafe parent symbolic link depth exceeded")
def same_parent_paths(left, right, expected_uid, expected_parent=None):
    if os.path.dirname(left) != os.path.dirname(right):
        fail("atomic helper paths must share a directory")
    parent_fd, first = open_verified_parent(left, expected_uid, expected_parent)
    second = os.path.basename(right)
    if not second or second in (".", ".."):
        os.close(parent_fd)
        fail("atomic helper leaf name invalid")
    return parent_fd, first, second


def validate_file(path, metadata, expected_uid, max_bytes, nlink=1):
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"owned JSON must be a regular file: {path}")
    allowed_nlinks = (nlink,) if isinstance(nlink, int) else nlink
    if allowed_nlinks is not None and metadata.st_nlink not in allowed_nlinks:
        expected_links = " or ".join(str(value) for value in sorted(allowed_nlinks))
        fail(f"owned JSON link count must be {expected_links}: {path}")
    if metadata.st_uid != expected_uid:
        fail(f"owned JSON owner mismatch: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"owned JSON mode must be 0600: {path}")
    if max_bytes is not None and metadata.st_size > max_bytes:
        fail(f"owned JSON size limit exceeded: {path}")


def stable_metadata(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode, metadata.st_nlink, metadata.st_size)


def open_file(parent_fd, name, flags=os.O_RDONLY):
    try:
        return os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            fail("atomic helper no-follow open rejected symbolic link")
        raise


def rename_atomic(parent_fd, source, target, kind, force_unsupported_atomic_rename=False):
    if force_unsupported_atomic_rename:
        fail("atomic rename primitive unsupported by test hook")
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            func = libc.renameatx_np
        except AttributeError:
            fail("atomic rename primitive unsupported on this platform")
        func.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        func.restype = ctypes.c_int
        flags = (RENAME_EXCL if kind == "exclusive" else RENAME_SWAP) | RENAME_NOFOLLOW_ANY
        result = func(parent_fd, source.encode(), parent_fd, target.encode(), flags)
    elif sys.platform == "linux":
        machine = platform.machine().lower()
        syscall_number = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}.get(machine)
        if syscall_number is None:
            fail("atomic rename primitive unsupported on this architecture")
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.syscall(syscall_number, parent_fd, source.encode(), parent_fd, target.encode(), RENAME_NOREPLACE if kind == "exclusive" else RENAME_EXCHANGE)
    else:
        fail("atomic rename primitive unsupported on this platform")
    if result == 0:
        return
    code = ctypes.get_errno()
    if code in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)):
        fail("atomic rename primitive unsupported by filesystem")
    raise OSError(code, os.strerror(code))


def publish(temp_path, canonical_path, expected_uid, swap, enabled_hooks, force_unsupported_atomic_rename, expected_parent=None):
    parent_fd, temp_name, canonical_name = same_parent_paths(temp_path, canonical_path, expected_uid, expected_parent)
    try:
        temp_fd = open_file(parent_fd, temp_name)
        try:
            validate_file(temp_path, os.fstat(temp_fd), expected_uid, None, 1)
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        destination_exists = False
        if swap:
            try:
                canonical_fd = open_file(parent_fd, canonical_name)
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
            else:
                try:
                    validate_file(canonical_path, os.fstat(canonical_fd), expected_uid, None, 1)
                    destination_exists = True
                finally:
                    os.close(canonical_fd)
        hook("beforePublish", enabled_hooks)
        try:
            rename_atomic(parent_fd, temp_name, canonical_name, "swap" if destination_exists else "exclusive", force_unsupported_atomic_rename)
        except OSError as error:
            if not swap or destination_exists or error.errno != errno.EEXIST:
                raise
            canonical_fd = open_file(parent_fd, canonical_name)
            try:
                validate_file(canonical_path, os.fstat(canonical_fd), expected_uid, None, 1)
            finally:
                os.close(canonical_fd)
            hook("beforePublish", enabled_hooks)
            rename_atomic(parent_fd, temp_name, canonical_name, "swap", force_unsupported_atomic_rename)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def recovery_temp_identity(canonical_name, candidate_name):
    temp_pattern = re.compile(rf"^\.{re.escape(canonical_name)}\.[0-9]+\.[0-9]+\.[0-9a-f]+\.tmp$")
    if temp_pattern.fullmatch(candidate_name):
        return candidate_name, f"{candidate_name}.recover", False
    if candidate_name.endswith(".recover") and temp_pattern.fullmatch(candidate_name[:-len(".recover")]):
        return candidate_name[:-len(".recover")], candidate_name, True
    fail("recovery temp name invalid")


def read_bounded(fd, max_bytes, path):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while total <= max_bytes:
        chunk = os.read(fd, min(65536, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
    fail(f"owned JSON size limit exceeded: {path}")

def write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            fail("recovery repair write failed")
        offset += written


def repair_legacy(canonical_path, candidate_path, expected_uid, max_bytes, enabled_hooks, expected_parent=None):
    parent_fd, canonical_name, candidate_name = same_parent_paths(canonical_path, candidate_path, expected_uid, expected_parent)
    try:
        temp_name, quarantine_name, detached = recovery_temp_identity(canonical_name, candidate_name)
        canonical_fd = open_file(parent_fd, canonical_name)
        try:
            source_stat = os.fstat(canonical_fd)
            if source_stat.st_nlink not in (2, 3):
                fail("recovery canonical link count must be 2 or 3")
            validate_file(canonical_path, source_stat, expected_uid, max_bytes, source_stat.st_nlink)
            mates = [quarantine_name] if detached else ([temp_name, quarantine_name] if source_stat.st_nlink == 3 else [temp_name])
            mate_fds = []
            try:
                for name in mates:
                    fd = open_file(parent_fd, name)
                    mate_fds.append(fd)
                    mate_stat = os.fstat(fd)
                    validate_file(name, mate_stat, expected_uid, max_bytes, source_stat.st_nlink)
                    if (mate_stat.st_dev, mate_stat.st_ino) != (source_stat.st_dev, source_stat.st_ino):
                        fail("recovery temp does not match canonical file")
                if detached and source_stat.st_nlink != 2:
                    fail("recovery canonical link count must be 2")
                hook("afterRecoveryInitialStat", enabled_hooks)
                source_bytes = read_bounded(canonical_fd, max_bytes, canonical_path)
                if stable_metadata(os.fstat(canonical_fd)) != stable_metadata(source_stat):
                    fail("recovery canonical changed during read")
                repair_name = f".{canonical_name}.{os.getpid()}.{os.urandom(8).hex()}.repair"
                repair_fd = os.open(repair_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
                try:
                    write_all(repair_fd, source_bytes)
                    os.fsync(repair_fd)
                    validate_file(repair_name, os.fstat(repair_fd), expected_uid, max_bytes, 1)
                finally:
                    os.close(repair_fd)
                hook("beforeRecoverySwap", enabled_hooks)
                if stable_metadata(os.fstat(canonical_fd)) != stable_metadata(source_stat):
                    fail("recovery canonical changed before swap")
                rename_atomic(parent_fd, repair_name, canonical_name, "swap")
                os.fsync(parent_fd)
                repaired_fd = open_file(parent_fd, canonical_name)
                try:
                    repaired_stat = os.fstat(repaired_fd)
                    validate_file(canonical_path, repaired_stat, expected_uid, max_bytes, 1)
                    if read_bounded(repaired_fd, max_bytes, canonical_path) != source_bytes:
                        fail("recovery canonical bytes changed during repair")
                finally:
                    os.close(repaired_fd)
            finally:
                for fd in mate_fds:
                    os.close(fd)
        finally:
            os.close(canonical_fd)
    finally:
        os.close(parent_fd)


def hold_lock(lock_path, expected_uid, expected_parent=None):
    parent_fd, lock_name = open_verified_parent(lock_path, expected_uid, expected_parent)
    try:
        try:
            fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            fd = open_file(parent_fd, lock_name, os.O_RDWR)
        try:
            validate_file(lock_path, os.fstat(fd), expected_uid, None, 1)
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fail("generation install already in progress")
            print("READY", flush=True)
            sys.stdin.buffer.read()
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)

def secure_open(path, expected_uid, max_bytes, enabled_hooks, expected_parent=None, allowed_nlinks=(1,)):
    parent_fd, final_name = open_verified_parent(path, expected_uid, expected_parent)
    try:
        hook("afterParentVerified", enabled_hooks)
        file_fd = open_file(parent_fd, final_name)
    finally:
        os.close(parent_fd)
    try:
        initial = os.fstat(file_fd)
        validate_file(path, initial, expected_uid, max_bytes, allowed_nlinks)
        hook("afterInitialStat", enabled_hooks)
        chunks, total = [], 0
        while total <= max_bytes:
            chunk = os.read(file_fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            fail(f"owned JSON size limit exceeded: {path}")
        hook("afterRead", enabled_hooks)
        if stable_metadata(initial) != stable_metadata(os.fstat(file_fd)):
            fail(f"owned JSON changed during read: {path}")
        print(json.dumps({"data": base64.urlsafe_b64encode(b"".join(chunks)).decode("ascii").rstrip("="), "evidence": {"path": path, "device": initial.st_dev, "inode": initial.st_ino, "uid": initial.st_uid, "mode": stat.S_IMODE(initial.st_mode), "nlink": initial.st_nlink}}, separators=(",", ":")))
    finally:
        os.close(file_fd)


def main():
    args = sys.argv[1:]
    hooks = set(filter(None, os.environ.get("AGNET_SECURE_OPEN_HOOKS", "").split(",")))
    try:
        force_unsupported_atomic_rename = os.environ.get("AGNET_SECURE_OPEN_FORCE_UNSUPPORTED_ATOMIC_RENAME") == "1"
        if len(args) == 6 and args[0] == "--publish-exclusive":
            publish(os.path.abspath(args[1]), os.path.abspath(args[2]), int(args[3]), False, hooks, force_unsupported_atomic_rename, parse_expected_parent(args[4], args[5]))
            return
        if len(args) == 6 and args[0] == "--publish-swap":
            publish(os.path.abspath(args[1]), os.path.abspath(args[2]), int(args[3]), True, hooks, force_unsupported_atomic_rename, parse_expected_parent(args[4], args[5]))
            return
        if len(args) == 7 and args[0] == "--repair-legacy":
            repair_legacy(os.path.abspath(args[1]), os.path.abspath(args[2]), int(args[3]), int(args[4]), hooks, parse_expected_parent(args[5], args[6]))
            return
        if len(args) == 5 and args[0] == "--hold-generation-lock":
            hold_lock(os.path.abspath(args[1]), int(args[2]), parse_expected_parent(args[3], args[4]))
            return
        if len(args) != 6:
            fail("owned JSON secure-open helper arguments invalid")
        try:
            allowed_nlinks = tuple(int(value) for value in args[5].split(","))
        except ValueError:
            fail("owned JSON allowed link counts invalid")
        if not allowed_nlinks or any(value < 1 or value > 3 for value in allowed_nlinks):
            fail("owned JSON allowed link counts invalid")
        secure_open(os.path.abspath(args[0]), int(args[1]), int(args[2]), hooks, parse_expected_parent(args[3], args[4]), allowed_nlinks)
    except OSError as error:
        if error.errno == errno.EEXIST:
            fail("atomic destination already exists")
        fail(f"atomic helper system error: {error.strerror or error}")


if __name__ == "__main__":
    main()
