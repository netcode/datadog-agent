/// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package settings

import (
	"fmt"

	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/profiling"
)

// dsdCaptureRuntimeSetting wraps operations to change log level at runtime
type dsdCaptureRuntimeSetting string

func (l dsdCaptureRuntimeSetting) Description() string {
	return "Enable/disable dogstatsd traffic captures. Possible values are: start, stop"
}

func (l dsdCaptureRuntimeSetting) Hidden() bool {
	return false
}

func (l dsdCaptureRuntimeSetting) Name() string {
	return string(l)
}

func (l dsdCaptureRuntimeSetting) Get() (interface{}, error) {
	return atomic.LoadUint64(&common.DSD.Debug.Enabled) == 1, nil
}

func (l dsdCaptureRuntimeSetting) Set(v interface{}) error {
	var profile bool
	var err error

	capture, err = getBool(v)

	if err != nil {
		return fmt.Errorf("Unsupported type for profile runtime setting: %v", err)
	}

	if capture {

		v, _ := version.Agent()
		err := profiling.Start(
			config.Datadog.GetString("api_key"),
			site,
			config.Datadog.GetString("env"),
			profiling.ProfileCoreService,
			fmt.Sprintf("version:%v", v),
		)
	} else {
		profiling.Stop()
	}

	return nil
}
