// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build functionaltests

package tests

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/iceber/iouring-go"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"gotest.tools/assert"

	"github.com/DataDog/datadog-agent/pkg/security/rules"
)

func TestOpen(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/test-open" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	testFile, testFilePtr, err := test.Path("test-open")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("open", func(t *testing.T) {
		fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(testFilePtr), syscall.O_CREAT, 0755)
		if errno != 0 {
			t.Fatal(error(errno))
		}
		defer os.Remove(testFile)
		defer syscall.Close(int(fd))

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0755)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	t.Run("openat", func(t *testing.T) {
		fd, _, errno := syscall.Syscall6(syscall.SYS_OPENAT, 0, uintptr(testFilePtr), syscall.O_CREAT, 0711, 0, 0)
		if errno != 0 {
			t.Fatal(error(errno))
		}
		defer os.Remove(testFile)
		defer syscall.Close(int(fd))

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0711)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	openHow := unix.OpenHow{
		Flags: unix.O_CREAT,
		Mode:  0711,
	}

	t.Run("openat2", func(t *testing.T) {
		fd, _, errno := syscall.Syscall6(unix.SYS_OPENAT2, 0, uintptr(testFilePtr), uintptr(unsafe.Pointer(&openHow)), unix.SizeofOpenHow, 0, 0)
		if errno != 0 {
			if errno == unix.ENOSYS {
				t.Skip("openat2 is not supported")
			}
			t.Fatal(errno)
		}
		defer os.Remove(testFile)
		defer syscall.Close(int(fd))

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0711)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	t.Run("creat", func(t *testing.T) {
		fd, _, errno := syscall.Syscall(syscall.SYS_CREAT, uintptr(testFilePtr), 0711, 0)
		if errno != 0 {
			t.Fatal(error(errno))
		}
		defer syscall.Close(int(fd))
		defer os.Remove(testFile)

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0711)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	t.Run("truncate", func(t *testing.T) {
		f, err := os.OpenFile(testFile, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		}

		syscall.Write(int(f.Fd()), []byte("this data will soon be truncated\n"))

		// truncate
		fd, _, errno := syscall.Syscall(syscall.SYS_TRUNCATE, uintptr(testFilePtr), 4, 0)
		if errno != 0 {
			t.Fatal(error(errno))
		}
		defer syscall.Close(int(fd))

		event, _, err = test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, "wrong flags")
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	t.Run("open_by_handle_at", func(t *testing.T) {
		h, mountID, err := unix.NameToHandleAt(unix.AT_FDCWD, testFile, 0)
		if err != nil {
			if err == unix.ENOTSUP {
				t.Skip("NameToHandleAt is not supported")
			}
			t.Fatalf("NameToHandleAt: %v", err)
		}
		mount, err := openMountByID(mountID)
		if err != nil {
			t.Fatalf("openMountByID: %v", err)
		}
		defer mount.Close()

		fdInt, err := unix.OpenByHandleAt(int(mount.Fd()), h, unix.O_CREAT)
		if err != nil {
			if err == unix.EINVAL {
				t.Skip("open_by_handle_at not supported")
			}
			t.Fatalf("OpenByHandleAt: %v", err)
		}
		defer unix.Close(fdInt)

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assert.Equal(t, int(event.Open.Flags), syscall.O_CREAT, "wrong flags")
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	t.Run("io_uring", func(t *testing.T) {
		iour, err := iouring.New(1)
		if err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				t.Fatal(err)
			}
			t.Skip("io_uring not supported")
		}

		prepRequest, err := iouring.Openat(unix.AT_FDCWD, testFile, syscall.O_CREAT, 0747)
		if err != nil {
			t.Fatal(err)
		}

		ch := make(chan iouring.Result, 1)
		if _, err := iour.SubmitRequest(prepRequest, ch); err != nil {
			t.Fatal(err)
		}

		result := <-ch
		fd, err := result.ReturnInt()
		if err != nil {
			if err != syscall.EBADF {
				t.Fatal(err)
			}
			t.Skip("openat not supported by io_uring")
		}
		defer iour.Close()

		if fd < 0 {
			t.Fatalf("failed to open file with io_uring: %d", fd)
		}

		if err := unix.Close(fd); err != nil {
			t.Error(err)
		}

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			// O_LARGEFILE is added by io_uring during __io_openat_prep
			assert.Equal(t, int(event.Open.Flags&0xfff), syscall.O_CREAT, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0747)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}

		// same with openat2

		prepRequest, err = iouring.Openat2(unix.AT_FDCWD, testFile, &openHow)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := iour.SubmitRequest(prepRequest, ch); err != nil {
			t.Fatal(err)
		}

		result = <-ch
		fd, err = result.ReturnInt()
		if err != nil {
			t.Fatal(err)
		}

		if fd < 0 {
			t.Fatalf("failed to open file with io_uring: %d", fd)
		}

		defer unix.Close(fd)

		event, _, err = test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			// O_LARGEFILE is added by io_uring during __io_openat_prep
			assert.Equal(t, int(event.Open.Flags&0xfff), syscall.O_CREAT, "wrong flags")
			assertRights(t, uint16(event.Open.Mode), 0711)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			testContainerPath(t, event, "open.file.container_path")
		}
	})

	_ = os.Remove(testFile)
}

func TestOpenMetadata(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/test-open" && open.file.uid == 98 && open.file.gid == 99`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	fileMode := 0o447
	expectedMode := uint16(applyUmask(fileMode))
	testFile, _, err := test.CreateWithOptions("test-open", 98, 99, fileMode)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("metadata", func(t *testing.T) {
		// CreateWithOptions creates the file and then chmod the user / group. When the file was created it didn't
		// have the right uid / gid, thus didn't match the rule. Open the file again to trigger the rule.
		f, err := os.Open(testFile)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(testFile)
		defer f.Close()

		event, _, err := test.GetEvent()
		if err != nil {
			t.Error(err)
		} else {
			assert.Equal(t, event.GetType(), "open", "wrong event type")
			assertRights(t, uint16(event.Open.File.Mode), expectedMode)
			assert.Equal(t, event.Open.File.Inode, getInode(t, testFile), "wrong inode")

			assertNearTime(t, event.Open.File.MTime)
			assertNearTime(t, event.Open.File.CTime)
		}
	})
}

func openMountByID(mountID int) (f *os.File, err error) {
	mi, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer mi.Close()
	bs := bufio.NewScanner(mi)
	wantPrefix := []byte(fmt.Sprintf("%v ", mountID))
	for bs.Scan() {
		if !bytes.HasPrefix(bs.Bytes(), wantPrefix) {
			continue
		}
		fields := strings.Fields(bs.Text())
		dev := fields[4]
		return os.Open(dev)
	}
	if err := bs.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("mountID not found")
}

func benchmarkOpenSameFile(b *testing.B, disableFilters bool, rules ...*rules.RuleDefinition) {
	test, err := newTestModule(nil, rules, testOpts{disableFilters: disableFilters})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	testFile, _, err := test.Path("benchtest")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fd, err := syscall.Open(testFile, syscall.O_CREAT, 0777)
		if err != nil {
			b.Fatal(err)
		}

		if err := syscall.Close(fd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenNoApprover(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.filename == "{{.Root}}/donotmatch"`,
	}

	benchmarkOpenSameFile(b, true, rule)
}

func BenchmarkOpenWithApprover(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.filename == "{{.Root}}/donotmatch"`,
	}

	benchmarkOpenSameFile(b, false, rule)
}

func BenchmarkOpenNoKprobe(b *testing.B) {
	benchmarkOpenSameFile(b, true)
}

func createFolder(current string, filesPerFolder, maxDepth int) error {
	os.MkdirAll(current, 0777)

	for i := 0; i < filesPerFolder; i++ {
		f, err := os.Create(path.Join(current, fmt.Sprintf("file%d", i)))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	if maxDepth > 0 {
		if err := createFolder(path.Join(current, fmt.Sprintf("dir%d", maxDepth)), filesPerFolder, maxDepth-1); err != nil {
			return err
		}
	}

	return nil
}

func benchmarkFind(b *testing.B, filesPerFolder, maxDepth int, rules ...*rules.RuleDefinition) {
	test, err := newTestModule(nil, rules, testOpts{})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	if err := createFolder(test.Root(), filesPerFolder, maxDepth); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findCmd := exec.Command("/usr/bin/find", test.Root())
		if err := findCmd.Run(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFind(b *testing.B) {
	benchmarkFind(b, 128, 8, &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/donotmatch"`,
	})
}

func BenchmarkFindNoKprobe(b *testing.B) {
	benchmarkFind(b, 128, 8)
}
