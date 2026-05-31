//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang sched_switch ./sched_switch.bpf.c -- -I../../internal

package watch_task_traced

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Pid   uint32
	State uint32
}

type ebpfHandles struct {
	objs *sched_switchObjects
	tp   link.Link
}

func (h *ebpfHandles) Close() {
	h.tp.Close()
	h.objs.Close()
}

func setupEBPF() (*ebpfHandles, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := &sched_switchObjects{}
	if err := loadSched_switchObjects(objs, nil); err != nil {
		objs.Close()
		return nil, err
	}

	tp, err := link.AttachTracing(link.TracingOptions{Program: objs.HandleSwitch})
	if err != nil {
		objs.Close()
		return nil, err
	}

	return &ebpfHandles{objs: objs, tp: tp}, nil
}

func Run() {
	if os.Getenv("CHILD") != "" {
		behaveChild()
	} else {
		behaveParent()
	}
}

func behaveChild() {
	// ptrace前にexitしないよう、killを待つ
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	<-sig
}

func behaveParent() {
	hdl, err := setupEBPF()
	panicIf(err, "setupEBPF")
	defer hdl.Close()

	pReader, err := ringbuf.NewReader(hdl.objs.RingbuffP)
	panicIf(err, "NewReader(parent)")
	defer pReader.Close()

	cReader, err := ringbuf.NewReader(hdl.objs.RingbuffC)
	panicIf(err, "NewReader(child)")
	defer cReader.Close()

	// ---------------------
	// Print parent info
	// ---------------------
	err = hdl.objs.TargetPid.Put(uint32(0), uint32(syscall.Gettid())) // use tid
	panicIf(err, "Put pid (parent)")

	fmt.Println("\n=== eBPF observation <Parent> ===")
	err = printRingBuff(pReader, "parent")
	panicIf(err, "PrintRingBuff (parent)")

	err = hdl.objs.TargetPid.Put(uint32(0), uint32(0))
	panicIf(err, "Clear pid (parent)")

	// ---------------------
	// Handle child
	// ---------------------
	// ptrace相手は制約を避けるために子プロセスを使用する。
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "CHILD=1")
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	panicIf(err, "cmd.Start")
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// 子がちゃんと立ち上がってsleepに入るように
	time.Sleep(300 * time.Millisecond)

	childPid := cmd.Process.Pid
	err = hdl.objs.TargetPid.Put(uint32(1), uint32(childPid))
	panicIf(err, "Put pid (child)")

	// ptrace(PTRACE_ATTACH, ...)
	err = syscall.PtraceAttach(childPid)
	panicIf(err, "PtraceAttach")
	_, err = syscall.Wait4(childPid, nil, 0, nil) // 簡略化。SIGSTOPのはず
	panicIf(err, "Wait4")
	fmt.Println("\nSuccessfully PtraceAttached")

	// 出力。ptraceで__TASK_TRACEDが立ち、
	// その後sched_switchで書き込まれてるはず。
	fmt.Println("\n=== eBPF observation <Child> ===")
	err = printRingBuff(cReader, "child ")
	panicIf(err, "PrintRingBuff (child)")

	syscall.PtraceDetach(childPid)
}

func panicIf(err error, label string) {
	if err != nil {
		panic(label + ": " + err.Error())
	}
}

func printRingBuff(reader *ringbuf.Reader, label string) error {
	record, err := reader.Read()
	if err != nil {
		return fmt.Errorf("ringbuf read: %w", err)
	}
	var ev event
	if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
		return fmt.Errorf("binary.Read: %w", err)
	}
	fmt.Printf("[%s] pid=%d  state=0x%08x\n", label, ev.Pid, ev.State)
	return nil
}
