#!/bin/bash
#
# Copyright (c) 2026 Codewire, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

actual="$(
  jq -c --argjson policy_shas '["ordinary", "revert", "merge"]' \
    -f "${script_dir}/compact-pr-commits.jq" <<'JSON'
[[
  {
    "sha": "ordinary",
    "node_id": "discard-me",
    "author": {
      "login": "contributor",
      "type": "User",
      "avatar_url": "discard-me"
    },
    "parents": [{"sha": "parent", "url": "discard-me"}],
    "commit": {
      "author": {"name": "Contributor", "email": "c@example.com", "date": "discard-me"},
      "committer": {"name": "Contributor", "email": "c@example.com", "date": "discard-me"},
      "message": "runtime: keep the policy\n\nSigned-off-by: Contributor <c@example.com>",
      "tree": {"sha": "discard-me"},
      "verification": {"verified": true, "signature": "discard-me"}
    }
  },
  {
    "sha": "revert",
    "author": null,
    "parents": [{"sha": "parent"}],
    "commit": {
      "author": {"name": "Contributor", "email": "c@example.com"},
      "committer": {"name": "Contributor", "email": "c@example.com"},
      "message": "Revert \"runtime: keep the policy\"",
      "verification": {"verified": true}
    }
  },
  {
    "sha": "merge",
    "author": null,
    "parents": [{"sha": "first"}, {"sha": "second"}],
    "commit": {
      "author": {"name": "Integrator", "email": "i@example.com"},
      "committer": {"name": "Integrator", "email": "i@example.com"},
      "message": "Merge source into deployment\n\nSigned-off-by: Integrator <i@example.com>",
      "verification": {"verified": true}
    }
  },
  {
    "sha": "upstream",
    "author": {"login": "upstream", "type": "User"},
    "parents": [{"sha": "upstream-parent"}],
    "commit": {
      "author": {"name": "Upstream", "email": "u@example.com"},
      "committer": {"name": "Upstream", "email": "u@example.com"},
      "message": "Merge pull request with an upstream-only message",
      "verification": {"verified": true}
    }
  }
]]
JSON
)"

jq -e '
  length == 2 and
  .[0] == {
    "sha": "ordinary",
    "author": {"login": "contributor", "type": "User"},
    "parents": [{"sha": "parent"}],
    "commit": {
      "author": {"name": "Contributor", "email": "c@example.com"},
      "committer": {"name": "Contributor", "email": "c@example.com"},
      "message": "runtime: keep the policy\n\nSigned-off-by: Contributor <c@example.com>",
      "verification": {"verified": true}
    }
  } and
  .[1].sha == "merge" and
  .[1].author == null and
  .[1].parents == [{"sha": "first"}, {"sha": "second"}] and
  all(.[]; .sha != "upstream") and
  ([paths | map(tostring) | join(".")] | all(. != "node_id" and . != "author.avatar_url" and . != "commit.tree"))
' <<< "${actual}" >/dev/null

if jq -e -c --argjson policy_shas '["ordinary", "missing"]' \
  -f "${script_dir}/compact-pr-commits.jq" >/dev/null 2>&1 <<'JSON'
[[
  {
    "sha": "ordinary",
    "author": {"login": "contributor", "type": "User"},
    "parents": [{"sha": "parent"}],
    "commit": {
      "author": {"name": "Contributor", "email": "c@example.com"},
      "committer": {"name": "Contributor", "email": "c@example.com"},
      "message": "runtime: keep the policy\n\nExplain the change.\n\nSigned-off-by: Contributor <c@example.com>",
      "verification": {"verified": true}
    }
  }
]]
JSON
then
  echo "projection accepted a policy commit absent from the pull request" >&2
  exit 1
fi

if jq -e -c --argjson policy_shas '["ordinary", "ordinary"]' \
  -f "${script_dir}/compact-pr-commits.jq" >/dev/null 2>&1 <<'JSON'
[[
  {
    "sha": "ordinary",
    "author": {"login": "contributor", "type": "User"},
    "parents": [{"sha": "parent"}],
    "commit": {
      "author": {"name": "Contributor", "email": "c@example.com"},
      "committer": {"name": "Contributor", "email": "c@example.com"},
      "message": "runtime: keep the policy\n\nExplain the change.\n\nSigned-off-by: Contributor <c@example.com>",
      "verification": {"verified": true}
    }
  }
]]
JSON
then
  echo "projection accepted duplicate policy commits" >&2
  exit 1
fi
