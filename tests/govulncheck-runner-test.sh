#!/bin/bash
#
# Copyright (c) 2026 Codewire, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# shellcheck source=/dev/null
source "${script_dir}/govulncheck-runner.sh"

containerd_checkpoint_findings='Vulnerability #1: GO-2026-5622
    containerd checkpoint restore finding

Vulnerability #2: GO-2026-5338
    containerd checkpoint restore finding

Vulnerability #3: GO-2026-5064
    containerd checkpoint restore finding
'

if ! filter_and_check "kata-runtime" "${containerd_checkpoint_findings}" >/dev/null; then
  echo "Expected guarded containerd checkpoint findings to be filtered" >&2
  exit 1
fi

mixed_findings="${containerd_checkpoint_findings}
Vulnerability #4: GO-2026-6238
    reachable cilium/ebpf finding
"

if filtered=$(filter_and_check "kata-runtime" "${mixed_findings}"); then
  echo "Expected an unrelated reachable finding to remain fatal" >&2
  exit 1
fi

grep -q '^Vulnerability #4: GO-2026-6238$' <<< "${filtered}"
if grep -q 'GO-2026-5622\|GO-2026-5338\|GO-2026-5064' <<< "${filtered}"; then
  echo "Expected only the guarded containerd findings to be removed" >&2
  exit 1
fi

if filter_and_check "unknown-binary" "${containerd_checkpoint_findings}" >/dev/null; then
  echo "Expected containerd findings to remain fatal for an unclassified binary" >&2
  exit 1
fi

for binary_name in containerd-shim-kata-v2 kata-monitor kata-runtime; do
  verify_containerd_checkpoint_restore_isolation "${binary_name}"
done

if verify_containerd_checkpoint_restore_dependencies \
  "kata-runtime" \
  "github.com/containerd/containerd/pkg/cri/server" >/dev/null 2>&1; then
  echo "Expected a linked CRI restore server package to prevent filtering" >&2
  exit 1
fi
