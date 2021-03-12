// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package forwarder

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/filesystem"
	"github.com/hashicorp/go-multierror"
)

// FailedTransactionRemovalPolicy handles the removal policy for failed transactions
type FailedTransactionRemovalPolicy struct {
	rootPath           string
	knownDomainFolders map[string]struct{}
	outdatedFileTime   time.Time
	telemetry          FailedTransactionRemovalPolicyTelemetry
}

// NewFailedTransactionRemovalPolicy creates a new instance of FailedTransactionRemovalPolicy
func NewFailedTransactionRemovalPolicy(
	rootPath string,
	outdatedFileDayCount int,
	telemetry FailedTransactionRemovalPolicyTelemetry) (*FailedTransactionRemovalPolicy, error) {
	if err := os.MkdirAll(rootPath, 0700); err != nil {
		return nil, err
	}

	permission, err := filesystem.NewPermission()
	if err != nil {
		return nil, err
	}
	if err := permission.RestrictAccessToUser(rootPath); err != nil {
		return nil, err
	}

	telemetry.addNewRemovalPolicyCount()

	return &FailedTransactionRemovalPolicy{
		rootPath:           rootPath,
		knownDomainFolders: make(map[string]struct{}),
		outdatedFileTime:   time.Now().Add(time.Duration(-outdatedFileDayCount*24) * time.Hour),
		telemetry:          telemetry,
	}, nil
}

// RegisterDomain registers a domain name.
func (p *FailedTransactionRemovalPolicy) RegisterDomain(domainName string) (string, error) {
	folder, err := p.getFolderPathForDomain(domainName)
	if err != nil {
		return "", err
	}

	p.telemetry.addRegisteredDomainCount()
	p.knownDomainFolders[folder] = struct{}{}
	return folder, nil
}

// RemoveOutdatedFiles removes the outdated files when a file is
// older than outDatedFileDayCount days.
func (p *FailedTransactionRemovalPolicy) RemoveOutdatedFiles() ([]string, error) {
	return p.forEachDomainPath(func(folderPath string) ([]string, error) {
		files, err := p.removeOutdatedRetryFiles(folderPath)
		p.telemetry.addOutdatedFilesCount(len(files))
		return files, err
	})
}

// RemoveUnknownDomains remove unknown domains.
func (p *FailedTransactionRemovalPolicy) RemoveUnknownDomains() ([]string, error) {
	return p.forEachDomainPath(func(folderPath string) ([]string, error) {
		if _, found := p.knownDomainFolders[folderPath]; !found {
			files, err := p.removeUnknownDomain(folderPath)
			p.telemetry.addFilesFromUnknownDomainCount(len(files))
			return files, err
		}
		return nil, nil
	})
}

func (p *FailedTransactionRemovalPolicy) forEachDomainPath(callback func(folderPath string) ([]string, error)) ([]string, error) {
	entries, err := ioutil.ReadDir(p.rootPath)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, domain := range entries {
		if domain.Mode().IsDir() {
			folderPath := path.Join(p.rootPath, domain.Name())
			files, err := callback(folderPath)

			if err != nil {
				return nil, err
			}
			paths = append(paths, files...)
		}
	}
	return paths, nil
}

func (p *FailedTransactionRemovalPolicy) getFolderPathForDomain(domainName string) (string, error) {
	// Use md5 for the folder name as the domainName is an url which can contain invalid charaters for a file path.
	h := md5.New()
	if _, err := io.WriteString(h, domainName); err != nil {
		return "", err
	}
	folder := fmt.Sprintf("%x", h.Sum(nil))

	return path.Join(p.rootPath, folder), nil
}

func (p *FailedTransactionRemovalPolicy) removeUnknownDomain(folderPath string) ([]string, error) {
	files, err := p.removeRetryFiles(folderPath, func(filename string) bool { return true })

	// Try to remove the folder if it is empty
	_ = os.Remove(folderPath)
	return files, err
}

func (p *FailedTransactionRemovalPolicy) removeOutdatedRetryFiles(folderPath string) ([]string, error) {
	return p.removeRetryFiles(folderPath, func(filename string) bool {
		modTime, err := util.GetFileModTime(filename)
		if err != nil {
			return false
		}
		return modTime.Before(p.outdatedFileTime)
	})
}

func (p *FailedTransactionRemovalPolicy) removeRetryFiles(folderPath string, shouldRemove func(string) bool) ([]string, error) {
	files, err := p.getRetryFiles(folderPath)
	if err != nil {
		return nil, err
	}

	var filesRemoved []string
	var errs error
	for _, f := range files {
		if shouldRemove(f) {
			if err = os.Remove(f); err != nil {
				errs = multierror.Append(errs, err)
			} else {
				filesRemoved = append(filesRemoved, f)
			}
		}
	}
	return filesRemoved, errs
}

func (p *FailedTransactionRemovalPolicy) getRetryFiles(folder string) ([]string, error) {
	entries, err := ioutil.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.Mode().IsRegular() && filepath.Ext(entry.Name()) == retryTransactionsExtension {
			files = append(files, path.Join(folder, entry.Name()))
		}
	}
	return files, nil
}
