// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build stresstests

package tests

import (
	"flag"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/security/model"
	"github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/security/rules"
)

var (
	keepProfile bool
	reportFile  string
	diffBase    string
	duration    int
)

// Stress test of open syscalls
func stressOpen(t *testing.T, rule *rules.RuleDefinition, pathname string, size int) {
	var rules []*rules.RuleDefinition
	if rule != nil {
		rules = append(rules, rule)
	}

	test, err := newTestModule(nil, rules, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	testFolder, _, err := test.Path(path.Dir(pathname))
	if err != nil {
		t.Fatal(err)
	}

	os.MkdirAll(testFolder, os.ModePerm)

	testFile, _, err := test.Path(pathname)
	if err != nil {
		t.Fatal(err)
	}

	perfBufferMonitor := test.probe.GetMonitor().GetPerfBufferMonitor()
	perfBufferMonitor.GetAndResetLostCount("events", -1)
	perfBufferMonitor.GetAndResetKernelLostCount("events", -1)

	events := 0
	go func() {
		for range test.events {
			events++
		}
	}()

	var prevLogLevel seelog.LogLevel

	pre := func() (err error) {
		prevLogLevel, err = test.SwapLogLevel(seelog.ErrorLvl)
		return err
	}

	post := func() error {
		_, err := test.SwapLogLevel(prevLogLevel)
		return err
	}

	fnc := func() error {
		f, err := os.Create(testFile)
		if err != nil {
			return err
		}

		if size > 0 {
			data := make([]byte, size, size)
			if n, err := f.Write(data); err != nil || n != 1024 {
				return err
			}
		}

		if err := f.Close(); err != nil {
			return err
		}

		return nil
	}

	opts := StressOpts{
		Duration:    time.Duration(duration) * time.Second,
		KeepProfile: keepProfile,
		DiffBase:    diffBase,
		TopFrom:     "probe",
		ReportFile:  reportFile,
	}

	report, err := StressIt(t, pre, post, fnc, opts)
	if err != nil {
		t.Fatal(err)
	}

	report.AddMetric("lost", float64(perfBufferMonitor.GetLostCount("events", -1)), "lost")
	report.AddMetric("kernel_lost", float64(perfBufferMonitor.GetAndResetKernelLostCount("events", -1)), "lost")
	report.AddMetric("events", float64(events), "events")
	report.AddMetric("events/sec", float64(events)/report.Duration.Seconds(), "event/s")

	report.Print()

	if report.Delta() < -2.0 {
		t.Error("unexpected performance degradation")

		cmdOutput, _ := exec.Command("pstree").Output()
		fmt.Println(string(cmdOutput))

		cmdOutput, _ = exec.Command("ps", "aux").Output()
		fmt.Println(string(cmdOutput))
	}
}

// goal: measure host abality to handle open syscall without any kprobe, act as a reference
// this benchmark generate syscall but without having kprobe installed

func TestStress_E2EOpenNoKprobe(t *testing.T) {
	stressOpen(t, nil, "folder1/folder2/folder1/folder2/test", 0)
}

// goal: measure the impact of an event catched and passed from the kernel to the userspace
// this benchmark generate event that passs from the kernel to the userspace
func TestStress_E2EOpenEvent(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/folder1/folder2/test" && open.flags & O_CREAT != 0`,
	}

	stressOpen(t, rule, "folder1/folder2/test", 0)
}

// goal: measure the impact on the kprobe only
// this benchmark generate syscall but without having event generated
func TestStress_E2EOpenNoEvent(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/folder1/folder2/test-no-event" && open.flags & O_APPEND != 0`,
	}

	stressOpen(t, rule, "folder1/folder2/test", 0)
}

// goal: measure the impact of an event catched and passed from the kernel to the userspace
// this benchmark generate event that passs from the kernel to the userspace
func TestStress_E2EOpenWrite1KEvent(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/folder1/folder2/test" && open.flags & O_CREAT != 0`,
	}

	stressOpen(t, rule, "folder1/folder2/test", 1024)
}

// goal: measure host abality to handle open syscall without any kprobe, act as a reference
// this benchmark generate syscall but without having kprobe installed

func TestStress_E2EOpenWrite1KNoKprobe(t *testing.T) {
	stressOpen(t, nil, "folder1/folder2/test", 1024)
}

// goal: measure the impact on the kprobe only
// this benchmark generate syscall but without having event generated
func TestStress_E2EOpenWrite1KNoEvent(t *testing.T) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/folder1/folder2/test-no-event" && open.flags & O_APPEND != 0`,
	}

	stressOpen(t, rule, "folder1/folder2/test", 1024)
}

// Stress test of fork/exec syscalls
func stressExec(t *testing.T, rule *rules.RuleDefinition, pathname string, executable string) {
	var rules []*rules.RuleDefinition
	if rule != nil {
		rules = append(rules, rule)
	}

	test, err := newTestModule(nil, rules, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	testFolder, _, err := test.Path(path.Dir(pathname))
	if err != nil {
		t.Fatal(err)
	}

	os.MkdirAll(testFolder, os.ModePerm)

	testFile, _, err := test.Path(pathname)
	if err != nil {
		t.Fatal(err)
	}

	perfBufferMonitor := test.probe.GetMonitor().GetPerfBufferMonitor()
	perfBufferMonitor.GetAndResetLostCount("events", -1)
	perfBufferMonitor.GetAndResetKernelLostCount("events", -1)

	events := 0
	go func() {
		for range test.events {
			events++
		}
	}()

	var prevLogLevel seelog.LogLevel

	pre := func() (err error) {
		prevLogLevel, err = test.SwapLogLevel(seelog.ErrorLvl)
		return err
	}

	post := func() error {
		_, err := test.SwapLogLevel(prevLogLevel)
		return err
	}

	fnc := func() error {
		cmd := exec.Command(executable, testFile)
		if _, err := cmd.CombinedOutput(); err != nil {
			return err
		}

		return nil
	}

	opts := StressOpts{
		Duration:    40 * time.Second,
		KeepProfile: keepProfile,
		DiffBase:    diffBase,
		TopFrom:     "probe",
		ReportFile:  reportFile,
	}

	report, err := StressIt(t, pre, post, fnc, opts)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	report.AddMetric("lost", float64(perfBufferMonitor.GetLostCount("events", -1)), "lost")
	report.AddMetric("kernel_lost", float64(perfBufferMonitor.GetAndResetKernelLostCount("events", -1)), "lost")
	report.AddMetric("events", float64(events), "events")
	report.AddMetric("events/sec", float64(events)/report.Duration.Seconds(), "event/s")

	report.Print()

	if report.Delta() < -2.0 {
		t.Error("unexpected performance degradation")

		cmdOutput, _ := exec.Command("pstree").Output()
		fmt.Println(string(cmdOutput))

		cmdOutput, _ = exec.Command("ps", "aux").Output()
		fmt.Println(string(cmdOutput))
	}
}

// goal: measure host abality to handle open syscall without any kprobe, act as a reference
// this benchmark generate syscall but without having kprobe installed

func TestStress_E2EOExecNoKprobe(t *testing.T) {
	executable := "/usr/bin/touch"
	if resolved, err := os.Readlink(executable); err == nil {
		executable = resolved
	} else {
		if os.IsNotExist(err) {
			executable = "/bin/touch"
		}
	}

	stressExec(t, nil, "folder1/folder2/folder1/folder2/test", executable)
}

// goal: measure the impact of an event catched and passed from the kernel to the userspace
// this benchmark generate event that passs from the kernel to the userspace
func TestStress_E2EExecEvent(t *testing.T) {
	executable := "/usr/bin/touch"
	if resolved, err := os.Readlink(executable); err == nil {
		executable = resolved
	} else {
		if os.IsNotExist(err) {
			executable = "/bin/touch"
		}
	}

	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: fmt.Sprintf(`open.file.path == "{{.Root}}/folder1/folder2/test-ancestors" && process.file.name == "%s"`, "touch"),
	}

	stressExec(t, rule, "folder1/folder2/test-ancestors", executable)
}

func BenchmarkERPCDentryResolutionSegment(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/aa/bb/cc/dd/ee" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	testFile, testFilePtr, err := test.Path("aa/bb/cc/dd/ee")
	if err != nil {
		b.Fatal(err)
	}
	_ = os.MkdirAll(path.Dir(testFile), 0755)

	segment, err := unix.Mmap(0, 0, 2 * os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANON)
	if err != nil {
		b.Fatal(errors.Wrap(err, "failed to mmap memory segment"))
	}

	erpcClient, err := probe.NewERPC()
	if err != nil {
		b.Fatal(err)
	}

	fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(testFilePtr), syscall.O_CREAT, 0755)
	if errno != 0 {
		b.Fatal(error(errno))
	}
	defer os.Remove(testFile)
	defer syscall.Close(int(fd))

	event, _, err := test.GetEvent()
	if err != nil {
		b.Fatal(err)
	}

	req := probe.ERPCRequest{
		OP: probe.ResolveSegmentOp,
	}
	model.ByteOrder.PutUint64(req.Data[0:8], event.Open.File.Inode)
	model.ByteOrder.PutUint32(req.Data[8:12], event.Open.File.MountID)
	model.ByteOrder.PutUint32(req.Data[12:16], event.Open.File.PathID)
	model.ByteOrder.PutUint64(req.Data[16:24], uint64(uintptr(unsafe.Pointer(&segment[0]))))

	// for some reason if we don't try to access the segment, the eBPF program can't write to it ... does it have something to do with unsafe.Pointer ?
	b.Log(segment[0])

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if err := erpcClient.Request(&req); err != nil {
			b.Fatal(err)
		}

		if segment[0] == 0 {
			b.Fatal("couldn't retrieve segment")
		}
	}

	test.Close()
}

func BenchmarkERPCDentryResolutionPath(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/aa/bb/cc/dd/ee" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	testFile, testFilePtr, err := test.Path("aa/bb/cc/dd/ee")
	if err != nil {
		b.Fatal(err)
	}
	_ = os.MkdirAll(path.Dir(testFile), 0755)

	fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(testFilePtr), syscall.O_CREAT, 0755)
	if errno != 0 {
		b.Fatal(error(errno))
	}
	defer os.Remove(testFile)
	defer syscall.Close(int(fd))

	event, _, err := test.GetEvent()
	if err != nil {
		b.Fatal(err)
	}

	// create a new dentry resolver to avoid concurrent map access errors
	resolver, err := probe.NewDentryResolver(test.probe)
	if err != nil {
		b.Fatal(err)
	}

	if err := resolver.Start(); err != nil {
		b.Fatal(err)
	}
	f, err := resolver.ResolveFromERPC(event.Open.File.MountID, event.Open.File.Inode, event.Open.File.PathID)
	if err != nil {
		b.Fatal(err)
	}
	b.Log(f)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f, err := resolver.ResolveFromERPC(event.Open.File.MountID, event.Open.File.Inode, event.Open.File.PathID)
		if err != nil {
			b.Fatal(err)
		}
		if f[0] == 0 {
			b.Fatal("couldn't resolve file")
		}
	}

	test.Close()
}

func BenchmarkMapDentryResolutionSegment(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/aa/bb/cc/dd/ee" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	testFile, testFilePtr, err := test.Path("aa/bb/cc/dd/ee")
	if err != nil {
		b.Fatal(err)
	}
	_ = os.MkdirAll(path.Dir(testFile), 0755)

	fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(testFilePtr), syscall.O_CREAT, 0755)
	if errno != 0 {
		b.Fatal(error(errno))
	}
	defer os.Remove(testFile)
	defer syscall.Close(int(fd))

	event, _, err := test.GetEvent()
	if err != nil {
		b.Fatal(err)
	}

	var path probe.PathValue
	key := probe.PathKey{
		Inode:   event.Open.File.Inode,
		MountID: event.Open.File.MountID,
		PathID:  event.Open.File.PathID,
	}

	keyBuffer, err := key.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	key.Write(keyBuffer)

	eMap, err := test.probe.Map("pathnames")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if err = eMap.Lookup(keyBuffer, &path); err != nil {
			b.Fatal(err)
		}
		if path.Name[0] == 0 {
			b.Fatal("couldn't retrieve segment")
		}
	}

	test.Close()
}

func BenchmarkMapDentryResolutionPath(b *testing.B) {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/aa/bb/cc/dd/ee" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		b.Fatal(err)
	}
	defer test.Close()

	testFile, testFilePtr, err := test.Path("aa/bb/cc/dd/ee")
	if err != nil {
		b.Fatal(err)
	}
	_ = os.MkdirAll(path.Dir(testFile), 0755)

	fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(testFilePtr), syscall.O_CREAT, 0755)
	if errno != 0 {
		b.Fatal(error(errno))
	}
	defer os.Remove(testFile)
	defer syscall.Close(int(fd))

	event, _, err := test.GetEvent()
	if err != nil {
		b.Fatal(err)
	}

	// create a new dentry resolver to avoid concurrent map access errors
	resolver, err := probe.NewDentryResolver(test.probe)
	if err != nil {
		b.Fatal(err)
	}

	if err := resolver.Start(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f, err := resolver.ResolveFromMap(event.Open.File.MountID, event.Open.File.Inode, event.Open.File.PathID)
		if err != nil {
			b.Fatal(err)
		}
		if f[0] == 0 {
			b.Fatal("couldn't resolve file")
		}
	}

	test.Close()
}

func init() {
	flag.BoolVar(&keepProfile, "keep-profile", false, "do not delete profile after run")
	flag.StringVar(&reportFile, "report-file", "", "save report of the stress test")
	flag.StringVar(&diffBase, "diff-base", "", "source of base stress report for comparison")
	flag.IntVar(&duration, "duration", 30, "duration of the run in second")
}
