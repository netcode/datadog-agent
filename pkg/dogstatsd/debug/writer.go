// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package debug

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/dogstatsd/debug/pb"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/packets"

	"github.com/golang/protobuf/proto"
)

const (
	fileTemplate = "datadog-capture-%d"
)

type CaptureBuffer struct {
	Pb   pb.UnixDogstatsdMsg
	Oob  *[]byte
	Buff *packets.Packet
}

var CapPool = sync.Pool{
	New: func() interface{} {
		return new(CaptureBuffer)
	},
}

type TrafficCaptureWriter struct {
	File     *os.File
	writer   *bufio.Writer
	Traffic  chan *CaptureBuffer
	Duration time.Duration
	written  int
	shutdown chan struct{}
	ongoing  bool

	sharedPacketPoolManager *packets.PoolManager
	oobPacketPoolManager    *packets.PoolManager

	sync.RWMutex
}

func NewTrafficCaptureWriter(p string, dur time.Duration, depth int) (*TrafficCaptureWriter, error) {

	fp, err := os.Create(path.Join(p, fmt.Sprintf(fileTemplate, time.Now().Unix())))
	if err != nil {
		return nil, err
	}

	return &TrafficCaptureWriter{
		File:     fp,
		writer:   bufio.NewWriter(fp),
		Traffic:  make(chan *CaptureBuffer, depth),
		Duration: dur,
	}, nil
}

func (tc *TrafficCaptureWriter) Path() (string, error) {
	tc.RLock()
	defer tc.RUnlock()

	if tc.File == nil {
		return "", fmt.Errorf("No file set in writer")
	}

	return filepath.Abs(filepath.Dir(tc.File.Name()))
}

func (tc *TrafficCaptureWriter) Capture() {
	tc.Lock()
	tc.shutdown = make(chan struct{})
	tc.ongoing = true
	if tc.sharedPacketPoolManager != nil {
		tc.sharedPacketPoolManager.SetPassthru(false)
	}
	if tc.oobPacketPoolManager != nil {
		tc.oobPacketPoolManager.SetPassthru(false)
	}
	tc.Unlock()

	go func() {
		tc.RLock()
		d := tc.Duration
		tc.RUnlock()

		<-time.After(d)
		tc.StopCapture()
	}()

	for {
		select {
		case msg := <-tc.Traffic:
			err := tc.WriteNext(msg)
			if err != nil {
				tc.StopCapture()
			}

			if tc.sharedPacketPoolManager != nil {
				tc.sharedPacketPoolManager.Put(msg.Buff)
			}

			if tc.oobPacketPoolManager != nil {
				tc.oobPacketPoolManager.Put(msg.Oob)
			}
		case <-tc.shutdown:
			return
		}
	}

	// discard packets in queue, empty the channel when depth > 1
cleanup:
	for {
		select {
		case msg := <-tc.Traffic:
			if tc.sharedPacketPoolManager != nil {
				tc.sharedPacketPoolManager.Put(msg.Buff)
			}

			if tc.oobPacketPoolManager != nil {
				tc.oobPacketPoolManager.Put(msg.Oob)
			}
		default:
			break cleanup
		}
	}
}

func (tc *TrafficCaptureWriter) StopCapture() error {
	tc.Lock()
	defer tc.Unlock()

	tc.writer.Flush()

	if tc.sharedPacketPoolManager != nil {
		tc.sharedPacketPoolManager.SetPassthru(false)
	}
	if tc.oobPacketPoolManager != nil {
		tc.oobPacketPoolManager.SetPassthru(false)
	}

	close(tc.shutdown)
	tc.ongoing = false

	return tc.File.Close()
}

func (tc *TrafficCaptureWriter) Enqueue(msg *CaptureBuffer) {
	tc.RLock()
	if tc.ongoing {
		tc.Traffic <- msg
	}
	tc.Unlock()
}

func (tc *TrafficCaptureWriter) RegisterSharedPoolManager(p *packets.PoolManager) error {
	if tc.sharedPacketPoolManager != nil {
		return fmt.Errorf("OOB Pool Manager already registered with the writer")
	}

	tc.sharedPacketPoolManager = p

	return nil
}

func (tc *TrafficCaptureWriter) RegisterOOBPoolManager(p *packets.PoolManager) error {
	if tc.oobPacketPoolManager != nil {
		return fmt.Errorf("OOB Pool Manager already registered with the writer")
	}

	tc.oobPacketPoolManager = p

	return nil
}

func (tc *TrafficCaptureWriter) IsOngoing() bool {
	tc.RLock()
	defer tc.RUnlock()

	return tc.ongoing
}

func (tc *TrafficCaptureWriter) WriteNext(msg *CaptureBuffer) error {
	buff, err := proto.Marshal(&msg.Pb)
	if err != nil {
		return err
	}

	n, err := tc.Write(buff)
	if err != nil {
		// continuing writes after this would result in a corrupted file
		return err
	}

	tc.Lock()
	defer tc.Unlock()

	tc.written += n + 4 // buffer + record length

	return nil
}

func (tc *TrafficCaptureWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(p)))

	// Record size
	if n, err := tc.writer.Write(buf); err != nil {
		return n, err
	}

	// Record
	n, err := tc.writer.Write(p)

	return n + 4, err
}

func Read(r io.Reader) ([]byte, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	size := binary.LittleEndian.Uint32(buf)

	msg := make([]byte, size)

	_, err := io.ReadFull(r, msg)
	if err != nil {
		return nil, err
	}

	return msg, err
}
