package managedkey

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type durableFault func(point string) error

type durableWriteOptions struct {
	Mode                 os.FileMode
	PointPrefix          string
	Fault                durableFault
	Exclusive            bool
	KeepAfterRenameFault bool
}

func maybeDurableFault(fault durableFault, point string) error {
	if fault == nil {
		return nil
	}
	return fault(point)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func durableWriteFile(path string, data []byte, options durableWriteOptions) error {
	mode := options.Mode
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(path)
	leaf := filepath.Base(path)
	temp := filepath.Join(dir, fmt.Sprintf(".%s.%d.%d.tmp", leaf, os.Getpid(), time.Now().UnixNano()))
	tempCreated := false
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	tempCreated = true
	defer func() {
		if tempCreated {
			_ = os.Remove(temp)
		}
	}()
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = maybeDurableFault(options.Fault, options.PointPrefix+"-after-temp-write")
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr == nil {
		writeErr = maybeDurableFault(options.Fault, options.PointPrefix+"-file-sync")
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(temp, mode); err != nil {
		return err
	}
	if err := maybeDurableFault(options.Fault, options.PointPrefix+"-before-rename"); err != nil {
		return err
	}
	if options.Exclusive {
		if err := os.Link(temp, path); err != nil {
			if os.IsExist(err) {
				existing, readErr := readPrivateFile(path, options.PointPrefix+" file")
				if readErr == nil && bytes.Equal(existing, data) {
					if removeErr := os.Remove(temp); removeErr != nil {
						return removeErr
					}
					tempCreated = false
					if syncErr := syncDir(filepath.Dir(path)); syncErr != nil {
						return syncErr
					}
					return nil
				}
				return fmt.Errorf("%s already exists", options.PointPrefix)
			}
			return err
		}
		if err := os.Remove(temp); err != nil {
			return err
		}
		tempCreated = false
	} else {
		if err := os.Rename(temp, path); err != nil {
			return err
		}
		tempCreated = false
	}
	if err := maybeDurableFault(options.Fault, options.PointPrefix+"-after-rename"); err != nil {
		if !options.KeepAfterRenameFault {
			_ = os.Remove(path)
		}
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := maybeDurableFault(options.Fault, options.PointPrefix+"-after-dir-sync"); err != nil {
		return err
	}
	return nil
}

func durableWriteFileAt(directory *os.File, leaf string, data []byte, options durableWriteOptions) error {
	mode := options.Mode
	if mode == 0 {
		mode = 0o600
	}
	directoryFD := int(directory.Fd())
	temporaryLeaf := fmt.Sprintf(".%s.%d.%d.tmp", leaf, os.Getpid(), time.Now().UnixNano())
	temporaryCreated := false
	fd, err := unix.Openat(directoryFD, temporaryLeaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, uint32(mode))
	if err != nil {
		return err
	}
	temporaryCreated = true
	defer func() {
		if temporaryCreated {
			_ = unix.Unlinkat(directoryFD, temporaryLeaf, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporaryLeaf)
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = maybeDurableFault(options.Fault, options.PointPrefix+"-after-temp-write")
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr == nil {
		writeErr = maybeDurableFault(options.Fault, options.PointPrefix+"-file-sync")
	}
	if writeErr == nil {
		writeErr = file.Chmod(mode)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if options.Exclusive {
		if err := unix.Linkat(directoryFD, temporaryLeaf, directoryFD, leaf, 0); err != nil {
			if err == unix.EEXIST {
				existing, readErr := readPrivateFileAt(directory, leaf, options.PointPrefix+" file")
				if readErr == nil && bytes.Equal(existing, data) {
					if removeErr := unix.Unlinkat(directoryFD, temporaryLeaf, 0); removeErr != nil {
						return removeErr
					}
					temporaryCreated = false
					return directory.Sync()
				}
				return fmt.Errorf("%s already exists", options.PointPrefix)
			}
			return err
		}
		if err := unix.Unlinkat(directoryFD, temporaryLeaf, 0); err != nil {
			return err
		}
		temporaryCreated = false
	} else {
		if err := unix.Renameat(directoryFD, temporaryLeaf, directoryFD, leaf); err != nil {
			return err
		}
		temporaryCreated = false
	}
	if err := maybeDurableFault(options.Fault, options.PointPrefix+"-after-rename"); err != nil {
		if !options.KeepAfterRenameFault {
			_ = unix.Unlinkat(directoryFD, leaf, 0)
		}
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return maybeDurableFault(options.Fault, options.PointPrefix+"-after-dir-sync")
}
