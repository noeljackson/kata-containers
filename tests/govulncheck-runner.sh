#!/bin/bash
#
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: Apache-2.0

# Run govulncheck security scanning on given binary
set -euo pipefail

declare -A false_positives

# These records were generated from v2-only containerd advisories, but the Go
# vulnerability database also marks the v1 module as affected at module scope
# with no vulnerable symbols or fixed version. Kata's binaries use selected v1
# client and shim packages, not either CRI checkpoint-restore server package.
# verify_containerd_checkpoint_restore_isolation() enforces that boundary before
# these exact records can be filtered.
readonly containerd_checkpoint_restore_false_positives="GO-2026-5622 \
  GO-2026-5338 \
  GO-2026-5064"

# Known false positives
# GO-2025-3595: golang.org/x/net/html - verified not compiled into binary
# GO-2025-3488: golang.org/x/oauth2/jws - verified not compiled into binary
# GO-2024-3169: github.com/containers/podman vulnerability not in annotations.go (only constants used)
# GO-2024-3042: github.com/containers/podman CVE-2024-3056 not in annotations.go (only constants used)
# GO-2023-1962: github.com/containers/podman CVE-2018-10856 not in annotations.go (only constants used)
# GO-2023-1942: github.com/containers/podman CVE-2019-18466 not in annotations.go (only constants used)
# GO-2022-1159: github.com/containers/podman CVE-2022-4123 not in annotations.go (only constants used)
false_positives["containerd-shim-kata-v2"]="GO-2025-3595 \
  GO-2025-3488 \
  GO-2024-3169 \
  GO-2024-3042 \
  GO-2023-1962 \
  GO-2023-1942 \
  GO-2022-1159 \
  ${containerd_checkpoint_restore_false_positives}"

# GO-2025-3595: golang.org/x/net/html - verified not compiled into binary
# GO-2025-3488: golang.org/x/oauth2/jws - verified not compiled into binary
# GO-2024-3169: github.com/containers/podman vulnerability not in annotations.go (only constants used)
# GO-2024-3042: github.com/containers/podman CVE-2024-3056 not in annotations.go (only constants used)
# GO-2023-1962: github.com/containers/podman CVE-2018-10856 not in annotations.go (only constants used)
# GO-2023-1942: github.com/containers/podman CVE-2019-18466 not in annotations.go (only constants used)
# GO-2022-1159: github.com/containers/podman CVE-2022-4123 not in annotations.go (only constants used)
false_positives["kata-runtime"]="GO-2025-3595 \
  GO-2025-3488 \
  GO-2024-3169 \
  GO-2024-3042 \
  GO-2023-1962 \
  GO-2023-1942 \
  GO-2022-1159 \
  ${containerd_checkpoint_restore_false_positives}"

# GO-2025-3595: golang.org/x/net/html - verified not compiled into binary
# GO-2025-3488: golang.org/x/oauth2/jws - verified not compiled into binary
# GO-2024-3169: github.com/containers/podman vulnerability not in annotations.go (only constants used)
# GO-2024-3042: github.com/containers/podman CVE-2024-3056 not in annotations.go (only constants used)
# GO-2023-1962: github.com/containers/podman CVE-2018-10856 not in annotations.go (only constants used)
# GO-2023-1942: github.com/containers/podman CVE-2019-18466 not in annotations.go (only constants used)
# GO-2022-1159: github.com/containers/podman CVE-2022-4123 not in annotations.go (only constants used)
false_positives["kata-monitor"]="GO-2025-3595 \
  GO-2025-3488 \
  GO-2024-3169 \
  GO-2024-3042 \
  GO-2023-1962 \
  GO-2023-1942 \
  GO-2022-1159 \
  ${containerd_checkpoint_restore_false_positives}"

verify_containerd_checkpoint_restore_isolation() {
  local binary_name="$1"
  local package

  case "${binary_name}" in
    containerd-shim-kata-v2)
      package="./cmd/containerd-shim-kata-v2"
      ;;
    kata-monitor)
      package="./cmd/kata-monitor"
      ;;
    kata-runtime)
      package="./cmd/kata-runtime"
      ;;
    *)
      return
      ;;
  esac

	local dependencies
	dependencies=$(go list -deps "${package}")
	verify_containerd_checkpoint_restore_dependencies "${binary_name}" "${dependencies}"
}

verify_containerd_checkpoint_restore_dependencies() {
	local binary_name="$1"
	local dependencies="$2"

	if grep -Eq '^github\.com/containerd/containerd(/v2)?/(internal/cri|pkg/cri/(server|sbserver)|plugins/cri)(/|$)' <<< "${dependencies}"; then
		echo "Refusing to filter containerd checkpoint-restore advisories: ${binary_name} links a CRI server package" >&2
		return 1
  fi
}

# Function to filter false positives and return both result and filtered output
# This is required as at the moment there is no native support for silencing vulnerability findings.
# See https://go.dev/issue/61211 for updates.
filter_and_check() {
  local binary_name="$1"
  local output="$2"

  local fp_list="${false_positives[${binary_name}]:-}"
  if [[ -z "${fp_list}" ]]; then
    if grep -q "GO-\|vulnerability" <<< "${output}"; then
      echo "${output}"
      false
    else
      true
    fi
    return
  fi

  # Filter out false positives and summary lines
  local filtered_output="${output}"
  for fp_id in ${fp_list}; do
    filtered_output=$(echo "${filtered_output}" | sed "/^Vulnerability #[0-9]*: ${fp_id}/,/^$/d")
  done
  filtered_output=$(echo "${filtered_output}" | grep -v "Your code is affected by.*vulnerabilities" || true)

  # Check if any real vulnerabilities remain
  if grep -q "GO-" <<< "${filtered_output}"; then
    echo "${filtered_output}"
    false
  else
    true
  fi
}

main() {
  if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <binary_path>"
    echo "Example: $0 ./kata-runtime"
    exit 1
  fi

  local binary_path="$1"
  local binary_name
  binary_name=$(basename "${binary_path}")

  if [[ ! -f "${binary_path}" ]]; then
    echo "Error: Binary ${binary_path} not found"
    exit 1
  fi

  verify_containerd_checkpoint_restore_isolation "${binary_name}"

  echo "=== Running govulncheck on ${binary_name} ==="

  local govulncheck_output
  govulncheck_output=$(govulncheck -mode=binary "${binary_path}" 2>&1 || true)

  local filtered_output
  if filtered_output=$(filter_and_check "${binary_name}" "${govulncheck_output}"); then
    echo " No vulnerabilities found in ${binary_name}"
  else
    echo " Vulnerabilities found in ${binary_name}:"
    echo "${filtered_output}"
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
