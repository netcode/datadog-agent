// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package debug

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/dogstatsd/debug/pb"

	"github.com/golang/protobuf/proto"
)

const (
	fileTemplate = "datadog-capture-%d"
)

type TrafficCaptureWriter struct {
	captureFile *os.File
	writer      *bufio.Writer
	Traffic     <-chan *pb.UnixDogstatsdMsg
	written     int
	size        int
	shutdown    <-chan struct{}
	sync.Mutex
}

func NewTrafficCaptureWriter(path string, size, depth int) (*TrafficCatpure, error) {

	fp, err := os.Create(path.Join(tc.path, fmt.Sprintf(fileTemplate, time.Now().Unix())))
	if err != nil {
		return nil, err
	}

	return TrafficCaptureWriter{
		captureFile: fp,
		writer:      bufio.NewWriter(fp),
		Traffic:     make(chan *pb.UnixDogstatsdMsg, depth),
		size:        size,
	}
}

func (tc *TrafficCaptureWriter) Capture() {
	tc.shutdown = make(chan struct{})
	for {
		select {
		case msg := <-tc.traffic:
			err := tc.WriteNext(msg)
			if err != nil {
				tc.StopCapture()
			}
		case <-shutdown:
			return
		}
	}
}

func (tc *TrafficCaptureWriter) StopCapture() err {
	tc.writer.Flush()
	close(tc.shutdown)

	return tc.captureFile.Close()
}

func (tc *TrafficCaptureWriter) WriteNext(msg *pb.UnixDogstatsdMsg) error {
	buff, err := proto.Marshal(*msg)
	if err != nil {
		return err
	}

	tc.Lock()
	if tc.written+len(buff)+4 > tc.size {
		err = errors.New("writing record would exceed maximum size")
		tc.Unlock()

		return err
	}
	tc.Unlock()

	n, err = Write(tc.activeFp, buff)
	if err != nil {
		// continuing writes after this would result in a corrupted file
		return err
	}

	tc.Lock()
	defer tc.Unlock()

	tc.written += n + 4 // buffer + record length

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

func (tc *TrafficCapture) Write(p []byte) (int, error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutInt32(buf, Uint32(len(p)))

	// Record size
	if n, err := tc.writer.Write(buf); err != nil {
		return n, err
	}

	// Record
	n, err = tc.writer.Write(p)

	return n + 4, nil
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
