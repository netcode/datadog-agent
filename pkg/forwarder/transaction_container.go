// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package forwarder

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/filesystem"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/hashicorp/go-multierror"
)

// TransactionStorage is an interface to serialize / deserialize transactions
type TransactionStorage interface {
	Serialize([]Transaction) error
	Deserialize() ([]Transaction, error)
}

// TransactionPrioritySorter is an interface to sort transactions.
type TransactionPrioritySorter interface {
	Sort([]Transaction)
}

// TransactionContainer stores transactions in memory and flush them to disk when the memory
// limit is exceeded.
type TransactionContainer struct {
	transactions               []Transaction
	currentMemSizeInBytes      int
	maxMemSizeInBytes          int
	flushToStorageRatio        float64
	dropPrioritySorter         TransactionPrioritySorter
	optionalTransactionStorage TransactionStorage
	telemetry                  TransactionContainerTelemetry
	mutex                      sync.RWMutex
}

// BuildTransactionContainer builds a new instance of TransactionContainer
func BuildTransactionContainer(
	maxMemSizeInBytes int,
	flushToStorageRatio float64,
	optionalDomainFolderPath string,
	storageMaxSize int64,
	dropPrioritySorter TransactionPrioritySorter,
	domain string,
	apiKeys []string) *TransactionContainer {
	var storage TransactionStorage
	var err error

	if optionalDomainFolderPath != "" && storageMaxSize > 0 {
		serializer := NewTransactionsSerializer(domain, apiKeys)
		diskRatio := config.Datadog.GetFloat64("forwarder_storage_max_disk_ratio")

		maxStorage := newForwarderMaxStorage(optionalDomainFolderPath, filesystem.NewDisk(), storageMaxSize, diskRatio)
		storage, err = newTransactionsFileStorage(serializer, optionalDomainFolderPath, maxStorage, transactionsFileStorageTelemetry{})

		// If the storage on disk cannot be used, log the error and continue.
		// Returning `nil, err` would mean not using `TransactionContainer` and so not using `forwarder_retry_queue_payloads_max_size` config.
		if err != nil {
			log.Errorf("Error when creating the file storage: %v", err)
		}
	}

	return NewTransactionContainer(dropPrioritySorter, storage, maxMemSizeInBytes, flushToStorageRatio, TransactionContainerTelemetry{})
}

// NewTransactionContainer creates a new instance of NewTransactionContainer
func NewTransactionContainer(
	dropPrioritySorter TransactionPrioritySorter,
	optionalTransactionStorage TransactionStorage,
	maxMemSizeInBytes int,
	flushToStorageRatio float64,
	telemetry TransactionContainerTelemetry) *TransactionContainer {
	return &TransactionContainer{
		maxMemSizeInBytes:          maxMemSizeInBytes,
		flushToStorageRatio:        flushToStorageRatio,
		dropPrioritySorter:         dropPrioritySorter,
		optionalTransactionStorage: optionalTransactionStorage,
		telemetry:                  telemetry,
	}
}

// Add adds a new transaction and flush transactions to disk if the memory limit is exceeded.
// The amount of transactions flushed to disk is control by
// `flushToStorageRatio` which is the ratio of the transactions to be flushed.
// Consider the following payload sizes 10, 20, 30, 40, 15 with `maxMemSizeInBytes=100` and
// `flushToStorageRatio=0.6`
// When adding the last payload `15`, the buffer becomes full (10+20+30+40+15 > 100) and
// 100*0.6=60 bytes must be flushed on disk.
// The first 3 transactions are flushed to the disk as 10 + 20 + 30 >= 60
// If disk serialization failed or is not enabled, remove old transactions such as
// `currentMemSizeInBytes` <= `maxMemSizeInBytes`
func (tc *TransactionContainer) Add(t Transaction) (int, error) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	var diskErr error
	payloadSize := t.GetPayloadSize()
	if tc.optionalTransactionStorage != nil {
		payloadsGroupToFlush := tc.extractTransactionsForDisk(payloadSize)
		for _, payloads := range payloadsGroupToFlush {
			if err := tc.optionalTransactionStorage.Serialize(payloads); err != nil {
				diskErr = multierror.Append(diskErr, err)
			}
		}
		if diskErr != nil {
			diskErr = fmt.Errorf("Cannot store transactions on disk: %v", diskErr)
			tc.telemetry.incErrorsCount()
		}
	}

	// If disk serialization failed or is not enabled, make sure `currentMemSizeInBytes` <= `maxMemSizeInBytes`
	payloadSizeInBytesToDrop := (tc.currentMemSizeInBytes + payloadSize) - tc.maxMemSizeInBytes
	inMemTransactionDroppedCount := 0
	if payloadSizeInBytesToDrop > 0 {
		transactions := tc.extractTransactionsFromMemory(payloadSizeInBytesToDrop)
		inMemTransactionDroppedCount = len(transactions)
		tc.telemetry.addTransactionsDroppedCount(inMemTransactionDroppedCount)
	}

	tc.transactions = append(tc.transactions, t)
	tc.currentMemSizeInBytes += payloadSize
	tc.telemetry.setCurrentMemSizeInBytes(tc.currentMemSizeInBytes)
	tc.telemetry.setTransactionsCount(len(tc.transactions))

	return inMemTransactionDroppedCount, diskErr
}

// ExtractTransactions extracts transactions from the container.
// If some transactions exist in memory extract them otherwise extract transactions
// from the disk.
// No transactions are in memory after calling this method.
func (tc *TransactionContainer) ExtractTransactions() ([]Transaction, error) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	var transactions []Transaction
	var err error
	if len(tc.transactions) > 0 {
		transactions = tc.transactions
		tc.transactions = nil
	} else if tc.optionalTransactionStorage != nil {
		transactions, err = tc.optionalTransactionStorage.Deserialize()
		if err != nil {
			tc.telemetry.incErrorsCount()
			return nil, err
		}
	}
	tc.currentMemSizeInBytes = 0
	tc.telemetry.setCurrentMemSizeInBytes(tc.currentMemSizeInBytes)
	tc.telemetry.setTransactionsCount(len(tc.transactions))
	return transactions, nil
}

// GetCurrentMemSizeInBytes gets the current memory usage in bytes
func (tc *TransactionContainer) getCurrentMemSizeInBytes() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	return tc.currentMemSizeInBytes
}

// GetTransactionCount gets the number of transactions in the container
func (tc *TransactionContainer) GetTransactionCount() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	return len(tc.transactions)
}

// GetMaxMemSizeInBytes gets the maximum memory usage for storing transactions
func (tc *TransactionContainer) GetMaxMemSizeInBytes() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	return tc.maxMemSizeInBytes
}

func (tc *TransactionContainer) extractTransactionsForDisk(payloadSize int) [][]Transaction {
	sizeInBytesToFlush := int(float64(tc.maxMemSizeInBytes) * tc.flushToStorageRatio)
	var payloadsGroupToFlush [][]Transaction
	for tc.currentMemSizeInBytes+payloadSize > tc.maxMemSizeInBytes && len(tc.transactions) > 0 {
		// Flush the N first transactions whose payload size sum is greater than `sizeInBytesToFlush`
		transactions := tc.extractTransactionsFromMemory(sizeInBytesToFlush)

		if len(transactions) == 0 {
			// Happens when `sizeInBytesToFlush == 0`
			// Avoid infinite loop
			break
		}
		payloadsGroupToFlush = append(payloadsGroupToFlush, transactions)
	}

	return payloadsGroupToFlush
}

func (tc *TransactionContainer) extractTransactionsFromMemory(payloadSizeInBytesToExtract int) []Transaction {
	i := 0
	sizeInBytesExtracted := 0
	var transactionsExtracted []Transaction

	tc.dropPrioritySorter.Sort(tc.transactions)
	for ; i < len(tc.transactions) && sizeInBytesExtracted < payloadSizeInBytesToExtract; i++ {
		transaction := tc.transactions[i]
		sizeInBytesExtracted += transaction.GetPayloadSize()
		transactionsExtracted = append(transactionsExtracted, transaction)
	}

	tc.transactions = tc.transactions[i:]
	tc.currentMemSizeInBytes -= sizeInBytesExtracted
	return transactionsExtracted
}
