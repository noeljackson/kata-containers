#!/usr/bin/env python3
#
# Copyright (c) 2026 Noel Jackson
#
# SPDX-License-Identifier: Apache-2.0

"""Verify that the fork gate is runnable and fails closed on source changes."""

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tools/testing/gatekeeper/required-tests.yaml"
WORKFLOW = ROOT / ".github/workflows/static-checks-self-hosted.yaml"


def require(condition: bool, message: object) -> None:
    if not condition:
        raise RuntimeError(message)


def validate(config: dict[str, Any], workflow: dict[str, Any]) -> None:
    paths = config["paths"]
    final_pattern, final_features = next(iter(paths[-1].items()))
    require(final_pattern == ".*", final_pattern)
    require(final_features == ["static", "fork-test"], final_features)

    for item in paths[:-1]:
        _, features = next(iter(item.items()))
        require("test" not in features, item)

    mapping = config["mapping"]
    fork_tests = mapping["fork-test"]["names"]
    require(
        fork_tests == ["Static checks / build-checks-depending-on-kvm (runtime-rs)"],
        fork_tests,
    )
    require(
        mapping["fork-test"]["required-labels"] == ["ok-to-test"],
        mapping["fork-test"]["required-labels"],
    )

    static_names = mapping["static"]["names"]
    required_static_fragments = (
        "ubuntu-22.04",
        "ubuntu-24.04-arm",
        "make test, runtime-rs",
        "make test, runtime,",
        "build-checks-depending-on-kvm (runtime-rs)",
    )
    for fragment in required_static_fragments:
        require(any(fragment in name for name in static_names), fragment)
    require(not any("s390x" in name for name in static_names), "s390x gate")

    instances = workflow["jobs"]["build-checks"]["strategy"]["matrix"]["instance"]
    require(instances == ["ubuntu-24.04-arm"], instances)

    always_required = config["required_tests"]
    for name in (
        "Commit Message Check / Commit Message Check",
        "Darwin tests / test",
        "GHA security analysis / zizmor",
        "Lint GHA workflows / run-actionlint",
    ):
        require(name in always_required, name)


def require_rejected(
    config: dict[str, Any],
    workflow: dict[str, Any],
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    candidate_config = deepcopy(config)
    candidate_workflow = deepcopy(workflow)
    mutate(candidate_config, candidate_workflow)
    try:
        validate(candidate_config, candidate_workflow)
    except RuntimeError:
        return
    raise RuntimeError("invalid downstream gate fixture was accepted")


def main() -> None:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    validate(config, workflow)

    require_rejected(config, workflow, lambda candidate, _: candidate["paths"].pop())
    require_rejected(
        config,
        workflow,
        lambda candidate, _: candidate["mapping"]["fork-test"].update(names=[]),
    )
    require_rejected(
        config,
        workflow,
        lambda candidate, _: candidate["mapping"]["static"]["names"].append(
            "Static checks self-hosted / ubuntu-24.04-s390x"
        ),
    )
    require_rejected(
        config,
        workflow,
        lambda _, candidate: candidate["jobs"]["build-checks"]["strategy"][
            "matrix"
        ].update(instance=["ubuntu-24.04-arm", "ubuntu-24.04-s390x"]),
    )

    print("downstream gate policy: PASS")


if __name__ == "__main__":
    main()
