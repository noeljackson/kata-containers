// Copyright (c) 2022 Databricks Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package volume

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAdd(t *testing.T) {
	var err error
	kataDirectVolumeRootPath = t.TempDir()
	var volumePath = "/a/b/c"
	actual := MountInfo{
		VolumeType: "block",
		Device:     "/dev/sda",
		FsType:     "ext4",
		Metadata: map[string]string{
			FSGroupMetadataKey:             "3000",
			FSGroupChangePolicyMetadataKey: string(FSGroupChangeOnRootMismatch),
		},
		Options: []string{"journal_dev", "noload"},
	}
	buf, err := json.Marshal(actual)
	assert.Nil(t, err)

	// Add the mount info
	assert.Nil(t, Add(volumePath, string(buf)))

	// Validate the mount info
	expected, err := VolumeMountInfo(volumePath)
	assert.Nil(t, err)
	assert.Equal(t, expected.Device, actual.Device)
	assert.Equal(t, expected.FsType, actual.FsType)
	assert.Equal(t, expected.Options, actual.Options)
	assert.Equal(t, expected.Metadata, actual.Metadata)

	_, err = os.Stat(filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath))))
	assert.Nil(t, err)
	// Remove the file
	err = Remove(volumePath)
	assert.Nil(t, err)
	_, err = os.Stat(filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath))))
	assert.True(t, errors.Is(err, os.ErrNotExist))
	_, err = os.Stat(filepath.Join(kataDirectVolumeRootPath))
	assert.Nil(t, err)
}

func TestRecordSandboxID(t *testing.T) {
	var err error
	kataDirectVolumeRootPath = t.TempDir()

	var volumePath = "/a/b/c"
	mntInfo := MountInfo{
		VolumeType: "block",
		Device:     "/dev/sda",
		FsType:     "ext4",
		Options:    []string{"journal_dev", "noload"},
	}
	buf, err := json.Marshal(mntInfo)
	assert.Nil(t, err)

	// Add the mount info
	assert.Nil(t, Add(volumePath, string(buf)))

	sandboxID := uuid.Generate().String()
	err = RecordSandboxID(sandboxID, volumePath)
	assert.Nil(t, err)

	id, err := GetSandboxIDForVolume(volumePath)
	assert.Nil(t, err)
	assert.Equal(t, sandboxID, id)
}

func TestRecordSandboxIDNoMountInfoFile(t *testing.T) {
	var err error
	kataDirectVolumeRootPath = t.TempDir()

	var volumePath = "/a/b/c"
	sandboxID := uuid.Generate().String()
	err = RecordSandboxID(sandboxID, volumePath)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

const testConfidentialStorageKeyID = "01981234-5678-7abc-8def-0123456789ab"

func confidentialStorageMountInfo() MountInfo {
	return MountInfo{
		VolumeType: "block",
		Device:     "/dev/sda",
		FsType:     "ext4",
		Metadata: map[string]string{
			ConfidentialStorageEncryptionMetadataKey: ConfidentialStorageEncryptionValue,
			ConfidentialStorageSourceMetadataKey:     ConfidentialStorageSourceValue,
			ConfidentialStorageKeyURIMetadataKey:     ConfidentialStorageKeyURIPrefix + testConfidentialStorageKeyID,
			ConfidentialStorageFilesystemMetadataKey: ConfidentialStorageFilesystemValue,
			ConfidentialStorageGrowMetadataKey:       ConfidentialStorageGrowValue,
		},
	}
}

func TestConfidentialStorageMetadata(t *testing.T) {
	mountInfo := confidentialStorageMountInfo()
	mountInfo.Metadata[FSGroupMetadataKey] = "3000"

	metadata, err := mountInfo.ConfidentialStorage()

	assert.NoError(t, err)
	assert.Equal(t, testConfidentialStorageKeyID, metadata.KeyID)
	assert.Equal(t, ConfidentialStorageKeyURIPrefix+testConfidentialStorageKeyID, metadata.KeyURI)
	assert.Equal(t, []string{
		ConfidentialStorageEncryptionMetadataKey + "=" + ConfidentialStorageEncryptionValue,
		ConfidentialStorageSourceMetadataKey + "=" + ConfidentialStorageSourceValue,
		ConfidentialStorageKeyURIMetadataKey + "=" + ConfidentialStorageKeyURIPrefix + testConfidentialStorageKeyID,
		ConfidentialStorageFilesystemMetadataKey + "=" + ConfidentialStorageFilesystemValue,
		ConfidentialStorageGrowMetadataKey + "=" + ConfidentialStorageGrowValue,
	}, metadata.DriverOptions())
}

func TestConfidentialStorageMetadataLeavesOrdinaryVolumesUnchanged(t *testing.T) {
	mountInfo := MountInfo{
		VolumeType: "block",
		FsType:     "xfs",
		Metadata: map[string]string{
			EncryptionKeyMetadataKey: "ephemeral",
			FSGroupMetadataKey:       "3000",
		},
	}

	metadata, err := mountInfo.ConfidentialStorage()

	assert.NoError(t, err)
	assert.Nil(t, metadata)
}

func TestConfidentialStorageMetadataRejectsInvalidContracts(t *testing.T) {
	tests := map[string]func(*MountInfo){
		"missing key": func(m *MountInfo) {
			delete(m.Metadata, ConfidentialStorageGrowMetadataKey)
		},
		"unknown codewire key": func(m *MountInfo) {
			m.Metadata[ConfidentialStorageMetadataPrefix+"unexpected"] = "value"
		},
		"wrong value": func(m *MountInfo) {
			m.Metadata[ConfidentialStorageSourceMetadataKey] = "empty"
		},
		"wrong filesystem": func(m *MountInfo) {
			m.FsType = "xfs"
		},
		"wrong URI namespace": func(m *MountInfo) {
			m.Metadata[ConfidentialStorageKeyURIMetadataKey] = "kbs:///default/other/" + testConfidentialStorageKeyID
		},
		"noncanonical UUID": func(m *MountInfo) {
			m.Metadata[ConfidentialStorageKeyURIMetadataKey] = ConfidentialStorageKeyURIPrefix + "01981234-5678-7ABC-8def-0123456789ab"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			mountInfo := confidentialStorageMountInfo()
			mutate(&mountInfo)

			metadata, err := mountInfo.ConfidentialStorage()

			assert.Nil(t, metadata)
			assert.ErrorIs(t, err, ErrInvalidConfidentialStorageMetadata)
		})
	}
}

func TestAddRejectsInvalidConfidentialStorageBeforePersistence(t *testing.T) {
	kataDirectVolumeRootPath = t.TempDir()
	volumePath := "/a/confidential"
	mountInfo := confidentialStorageMountInfo()
	delete(mountInfo.Metadata, ConfidentialStorageGrowMetadataKey)
	encoded, err := json.Marshal(mountInfo)
	assert.NoError(t, err)

	err = Add(volumePath, string(encoded))

	assert.ErrorIs(t, err, ErrInvalidConfidentialStorageMetadata)
	_, statErr := os.Stat(filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath))))
	assert.True(t, errors.Is(statErr, os.ErrNotExist))
}

func TestConfidentialStorageMountInfoRoundTripTamperAndCleanup(t *testing.T) {
	kataDirectVolumeRootPath = t.TempDir()
	volumePath := "/a/confidential"
	mountInfo := confidentialStorageMountInfo()
	encoded, err := json.Marshal(mountInfo)
	assert.NoError(t, err)
	assert.NoError(t, Add(volumePath, string(encoded)))

	stored, err := VolumeMountInfo(volumePath)
	assert.NoError(t, err)
	assert.Equal(t, mountInfo, *stored)

	delete(mountInfo.Metadata, ConfidentialStorageGrowMetadataKey)
	tampered, err := json.Marshal(mountInfo)
	assert.NoError(t, err)
	volumeDir := filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath)))
	assert.NoError(t, os.WriteFile(filepath.Join(volumeDir, mountInfoFileName), tampered, 0600))

	_, err = VolumeMountInfo(volumePath)
	assert.ErrorIs(t, err, ErrInvalidConfidentialStorageMetadata)
	assert.NoError(t, Remove(volumePath))
	_, err = os.Stat(volumeDir)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
