# Copyright (c) 2026 Codewire, Inc.
#
# SPDX-License-Identifier: Apache-2.0

def compact_commit:
  {
    sha,
    author: (
      if .author == null then
        null
      else
        {
          login: .author.login,
          type: .author.type
        }
      end
    ),
    parents: [
      .parents[] |
      {sha}
    ],
    commit: {
      author: {
        name: .commit.author.name,
        email: .commit.author.email
      },
      committer: {
        name: .commit.committer.name,
        email: .commit.committer.email
      },
      message: .commit.message,
      verification: {
        verified: .commit.verification.verified
      }
    }
  };

if (type != "array") or any(.[]; type != "array") then
  error("expected paginated pull-request commit arrays")
else
  add as $commits
  | if ($commits | type) != "array" then
      error("pull-request commit list is empty")
    elif ($policy_shas | type) != "array" or ($policy_shas | length) == 0 then
      error("policy commit list is empty or invalid")
    elif ($policy_shas | unique | length) != ($policy_shas | length) then
      error("policy commit list contains duplicates")
    elif (
      [$policy_shas[] as $wanted | $commits[] | select(.sha == $wanted)]
      | length
    ) != ($policy_shas | length) then
      error("a selected policy commit is absent or duplicated in the pull request")
    else
      $commits
      | map(.sha as $sha | select(($policy_shas | index($sha)) != null))
      | map(select((.commit.message | test("^Revert \"|^Reapply \"")) | not))
      | map(compact_commit)
    end
end
