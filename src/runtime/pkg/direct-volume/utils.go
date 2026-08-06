// Copyright (c) 2022 Databricks Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package volume

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/uuid"
)

const (
	mountInfoFileName = "mountInfo.json"

	EncryptionKeyMetadataKey       = "encryptionKey"
	CreateFilesystemMetadataKey    = "createFilesystem"
	FSGroupMetadataKey             = "fsGroup"
	FSGroupChangePolicyMetadataKey = "fsGroupChangePolicy"
	BlockVolumeCreateFsDriverKey   = "create_filesystem"

	ConfidentialStorageMetadataPrefix        = "io.codewire.storage."
	ConfidentialStorageEncryptionMetadataKey = ConfidentialStorageMetadataPrefix + "encryption"
	ConfidentialStorageSourceMetadataKey     = ConfidentialStorageMetadataPrefix + "source"
	ConfidentialStorageKeyURIMetadataKey     = ConfidentialStorageMetadataPrefix + "key-uri"
	ConfidentialStorageFilesystemMetadataKey = ConfidentialStorageMetadataPrefix + "filesystem"
	ConfidentialStorageGrowMetadataKey       = ConfidentialStorageMetadataPrefix + "grow"

	ConfidentialStorageEncryptionValue = "luks2"
	ConfidentialStorageSourceValue     = "auto"
	ConfidentialStorageFilesystemValue = "ext4"
	ConfidentialStorageGrowValue       = "true"
	ConfidentialStorageKeyURIPrefix    = "kbs:///default/codewire-workspace-luks/"
)

var ErrInvalidConfidentialStorageMetadata = errors.New("invalid confidential storage metadata")

// FSGroupChangePolicy holds policies that will be used for applying fsGroup to a volume.
// This type and the allowed values are tracking the PodFSGroupChangePolicy defined in
// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/api/core/v1/types.go
// It is up to the client using the direct-assigned volume feature (e.g. CSI drivers) to determine
// the optimal setting for this change policy (i.e. from Pod spec or assuming volume ownership
// based on the storage offering).
type FSGroupChangePolicy string

const (
	// FSGroupChangeAlways indicates that volume's ownership should always be changed.
	FSGroupChangeAlways FSGroupChangePolicy = "Always"
	// FSGroupChangeOnRootMismatch indicates that volume's ownership will be changed
	// only when ownership of root directory does not match with the desired group id.
	FSGroupChangeOnRootMismatch FSGroupChangePolicy = "OnRootMismatch"
)

var kataDirectVolumeRootPath = "/run/kata-containers/shared/direct-volumes"

// MountInfo contains the information needed by Kata to consume a host block device and mount it as a filesystem inside the guest VM.
type MountInfo struct {
	// The type of the volume (ie. block)
	VolumeType string `json:"volume-type"`
	// The device backing the volume.
	Device string `json:"device"`
	// The filesystem type to be mounted on the volume.
	FsType string `json:"fstype"`
	// Additional metadata to pass to the agent regarding this volume.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Additional mount options.
	Options []string `json:"options,omitempty"`
}

// ConfidentialStorageMetadata is the validated, non-secret metadata needed to
// open a Codewire persistent volume inside a confidential guest.
type ConfidentialStorageMetadata struct {
	KeyID  string
	KeyURI string
}

// DriverOptions returns the fixed allowlist sent to the Kata Agent. Keep the
// order stable because the Agent policy compares driver options as an array.
func (m *ConfidentialStorageMetadata) DriverOptions() []string {
	return []string{
		ConfidentialStorageEncryptionMetadataKey + "=" + ConfidentialStorageEncryptionValue,
		ConfidentialStorageSourceMetadataKey + "=" + ConfidentialStorageSourceValue,
		ConfidentialStorageKeyURIMetadataKey + "=" + m.KeyURI,
		ConfidentialStorageFilesystemMetadataKey + "=" + ConfidentialStorageFilesystemValue,
		ConfidentialStorageGrowMetadataKey + "=" + ConfidentialStorageGrowValue,
	}
}

// ConfidentialStorage validates Codewire metadata when any Codewire key is
// present. Existing direct-volume metadata remains unaffected and is never
// copied into the confidential-storage driver-option allowlist.
func (m *MountInfo) ConfidentialStorage() (*ConfidentialStorageMetadata, error) {
	detected := false
	allowed := map[string]string{
		ConfidentialStorageEncryptionMetadataKey: ConfidentialStorageEncryptionValue,
		ConfidentialStorageSourceMetadataKey:     ConfidentialStorageSourceValue,
		ConfidentialStorageKeyURIMetadataKey:     "",
		ConfidentialStorageFilesystemMetadataKey: ConfidentialStorageFilesystemValue,
		ConfidentialStorageGrowMetadataKey:       ConfidentialStorageGrowValue,
	}

	for key := range m.Metadata {
		if !strings.HasPrefix(key, ConfidentialStorageMetadataPrefix) {
			continue
		}
		detected = true
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("%w: unsupported key %q", ErrInvalidConfidentialStorageMetadata, key)
		}
	}

	if !detected {
		return nil, nil
	}
	if m.VolumeType != "block" {
		return nil, fmt.Errorf("%w: volume type must be block", ErrInvalidConfidentialStorageMetadata)
	}
	if m.FsType != ConfidentialStorageFilesystemValue {
		return nil, fmt.Errorf("%w: filesystem must be ext4", ErrInvalidConfidentialStorageMetadata)
	}

	for key, expected := range allowed {
		value, ok := m.Metadata[key]
		if !ok {
			return nil, fmt.Errorf("%w: missing key %q", ErrInvalidConfidentialStorageMetadata, key)
		}
		if expected != "" && value != expected {
			return nil, fmt.Errorf("%w: invalid value for key %q", ErrInvalidConfidentialStorageMetadata, key)
		}
	}

	keyURI := m.Metadata[ConfidentialStorageKeyURIMetadataKey]
	keyID := strings.TrimPrefix(keyURI, ConfidentialStorageKeyURIPrefix)
	if keyID == keyURI || keyID == "" {
		return nil, fmt.Errorf("%w: invalid key URI", ErrInvalidConfidentialStorageMetadata)
	}
	parsed, err := uuid.Parse(keyID)
	if err != nil || parsed.String() != keyID {
		return nil, fmt.Errorf("%w: key URI must end in a canonical UUID", ErrInvalidConfidentialStorageMetadata)
	}

	return &ConfidentialStorageMetadata{KeyID: keyID, KeyURI: keyURI}, nil
}

// Add writes the mount info of a direct volume into a filesystem path known to Kata Container.
func Add(volumePath string, mountInfo string) error {
	var deserialized MountInfo
	if err := json.Unmarshal([]byte(mountInfo), &deserialized); err != nil {
		return err
	}
	if _, err := deserialized.ConfidentialStorage(); err != nil {
		return err
	}

	volumeDir := filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath)))
	stat, err := os.Stat(volumeDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(volumeDir, 0700); err != nil {
			return err
		}
	}
	if stat != nil && !stat.IsDir() {
		return fmt.Errorf("%s should be a directory", volumeDir)
	}

	return os.WriteFile(filepath.Join(volumeDir, mountInfoFileName), []byte(mountInfo), 0600)
}

func AddMountInfo(volumePath string, mountInfo MountInfo) error {
	s, err := json.Marshal(&mountInfo)
	if err != nil {
		return err
	}
	return Add(volumePath, string(s))
}

// Remove deletes the direct volume path including all the files inside it.
func Remove(volumePath string) error {
	return os.RemoveAll(filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath))))
}

// VolumeMountInfo retrieves the mount info of a direct volume.
func VolumeMountInfo(volumePath string) (*MountInfo, error) {
	mountInfoFilePath := filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath)), mountInfoFileName)
	if _, err := os.Stat(mountInfoFilePath); err != nil {
		return nil, err
	}
	buf, err := os.ReadFile(mountInfoFilePath)
	if err != nil {
		return nil, err
	}
	var mountInfo MountInfo
	if err := json.Unmarshal(buf, &mountInfo); err != nil {
		return nil, err
	}
	if _, err := mountInfo.ConfidentialStorage(); err != nil {
		return nil, err
	}
	return &mountInfo, nil
}

// IsVolumeMounted returns whether the direct volume mount is present.
func IsVolumeMounted(volumePath string) (bool, error) {
	if _, err := VolumeMountInfo(volumePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RecordSandboxId associates a sandbox id with a direct volume.
func RecordSandboxID(sandboxID string, volumePath string) error {
	encodedPath := b64.URLEncoding.EncodeToString([]byte(volumePath))
	mountInfoFilePath := filepath.Join(kataDirectVolumeRootPath, encodedPath, mountInfoFileName)
	if _, err := os.Stat(mountInfoFilePath); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(kataDirectVolumeRootPath, encodedPath, sandboxID), []byte(""), 0600)
}

func GetSandboxIDForVolume(volumePath string) (string, error) {
	files, err := os.ReadDir(filepath.Join(kataDirectVolumeRootPath, b64.URLEncoding.EncodeToString([]byte(volumePath))))
	if err != nil {
		return "", err
	}
	// Find the id of the first sandbox.
	// We expect a direct-assigned volume is associated with only a sandbox at a time.
	for _, file := range files {
		if file.Name() != mountInfoFileName {
			return file.Name(), nil
		}
	}
	return "", fmt.Errorf("no sandbox found for %s", volumePath)
}
