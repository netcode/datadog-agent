// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build linux

package probes

import "github.com/DataDog/ebpf/manager"

// getDentryResolverTailCallRoutes is the list of routes used during the dentry resolution process
func getDentryResolverTailCallRoutes() []manager.TailCallRoute {
	return []manager.TailCallRoute{
		// dentry resolver programs
		{
			ProgArrayName: "dentry_resolver_progs",
			Key: DentryResolverKernKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dentry_resolver_kern",
			},
		},

		// dentry resolver callbacks
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverOpenCallbackKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_open_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverSetAttrCallbackKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_setattr_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverMkdirCallbackKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_mkdir_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverMountCallbackKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_mount_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverSecurityInodeRmdirCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_security_inode_rmdir_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverSetXAttrCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_setxattr_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverUnlinkCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_unlink_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverLinkSrcCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_link_src_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverLinkDstCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_link_dst_callback",
			},
		},
		{
			ProgArrayName: "dentry_resolver_callbacks",
			Key: DentryResolverRenameCallbackJet,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/dr_rename_callback",
			},
		},
	}
}
