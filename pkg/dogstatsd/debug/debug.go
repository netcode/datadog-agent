// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package debug

import (
	"encoding/binary"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/dogstatsd/debug/pb"

	"github.com/golang/protobuf/proto"
)

const (
	maxCaptureSize = 2 * 1 << 20
	fileTemplate   = "datadog-capture-%d"
)

type TrafficCapture struct {
	Path     string
	Traffic  <-chan *pb.UnixDogstatsdMsg
	activeFp os.File
	written  uint32
	shutdown <-chan struct{}
	sync.Mutex
}

func NewTrafficCapture(path string, depth int) (*TrafficCatpure, error) {
	return TrafficCapture{
		path:    path,
		traffic: make(chan *pb.UnixDogstatsdMsg, depth),
	}
}

func (tc *TrafficCapture) Capture() {
	tc.shutdown = make(chan struct{})
	for {
		select {
		case msg := <-tc.traffic:
			tc.WriteNext(msg)
		case <-shutdown:
			return
		}
	}
}

func (tc *TrafficCapture) StopCapture() {
	close(tc.shutdown)
}

func (tc *TrafficCapture) WriteNext(msg *pb.UnixDogstatsdMsg) error {
	buff, err := proto.Marshal(*msg)
	if err != nil {
		return err
	}

	err = Write(tc.activeFp, buff)
	if err != nil {
		return err
	}

	tc.Lock()
	defer tc.Unlock()

	tc.written += len(buff) + 4 // buffer + record length
	if tc.written > maxCaptureSize {
		tc.activeFp.Close()
	}

	fp, err := os.Open(path.Join(tc.path, fmt.Sprintf(fileTemplate, time.Now().Unix())))
	if err != nil {
		return err
	}
	tc.activeFp = fp
	tc.written = 0
}

func (tc *TrafficCapture) ReadNext() (*pb.UnixDogstatsdMsg, error) {
	buff, err := Read(tc.fp)
	if err != nil {
		return nil, err
	}

	msg := pb.UnixDogstatsdMsg{}
	err = proto.Unmarshal(buff, msg)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}

func Write(w io.Writer, msg []byte) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutInt32(buf, Uint32(len(msg)))

	// Record size
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// Record
	if _, err := w.Write(msg); err != nil {
		return err
	}
}

func Read(r io.Reader) ([]byte, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	size := binary.LittleEndian.Uint32(buf)

	msg := make([]byte, size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}

	return msg, err
}
