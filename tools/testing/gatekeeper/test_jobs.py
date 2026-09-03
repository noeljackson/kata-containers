#!/usr/bin/env python3
#
# Copyright (c) 2026 Noel Jackson
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for Gatekeeper workflow-run reconciliation."""

import os
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("GITHUB_REPOSITORY", "example/kata-containers")

from jobs import FAIL, PASS, RUNNING, Checker, latest_workflow_runs


class LatestWorkflowRunsTests(unittest.TestCase):
    def test_keeps_newest_run_for_each_workflow(self):
        runs = [
            {"id": 30, "name": "Static checks"},
            {"id": 10, "name": "Static checks"},
            {"id": 20, "name": "Darwin tests"},
        ]

        self.assertEqual(
            latest_workflow_runs(runs),
            [
                {"id": 20, "name": "Darwin tests"},
                {"id": 30, "name": "Static checks"},
            ],
        )


class WorkflowReconciliationTests(unittest.TestCase):
    def checker(self):
        environ = {
            "COMMIT_HASH": "a" * 40,
            "GH_PR_NUMBER": "10",
            "REQUIRED_JOBS": "Static checks / required-job",
            "REQUIRED_REGEXPS": "",
            "REQUIRED_LABELS": "",
        }
        with patch.dict(os.environ, environ, clear=False):
            return Checker()

    def test_superseded_cancelled_run_cannot_fail_newer_success(self):
        checker = self.checker()
        checker.paginated_fetch = Mock(
            return_value=[
                {"id": 10, "name": "Static checks"},
                {"id": 20, "name": "Static checks"},
            ]
        )
        checker.get_jobs_for_workflow_run = Mock(
            return_value=[
                {
                    "id": 200,
                    "run_id": 20,
                    "name": "required-job",
                    "status": "completed",
                    "conclusion": "success",
                }
            ]
        )

        self.assertEqual(checker.check_workflow_runs_status(1), PASS)
        checker.get_jobs_for_workflow_run.assert_called_once_with(20)

    def test_newer_run_without_jobs_stays_pending(self):
        checker = self.checker()
        checker.paginated_fetch = Mock(
            return_value=[
                {"id": 10, "name": "Static checks"},
                {"id": 20, "name": "Static checks"},
            ]
        )
        checker.get_jobs_for_workflow_run = Mock(return_value=[])

        self.assertEqual(checker.check_workflow_runs_status(1), RUNNING)
        checker.get_jobs_for_workflow_run.assert_called_once_with(20)

    def test_newest_cancelled_run_still_fails(self):
        checker = self.checker()
        checker.paginated_fetch = Mock(
            return_value=[
                {
                    "id": 20,
                    "name": "Static checks",
                }
            ]
        )
        checker.get_jobs_for_workflow_run = Mock(
            return_value=[
                {
                    "id": 200,
                    "run_id": 20,
                    "name": "required-job",
                    "status": "completed",
                    "conclusion": "cancelled",
                }
            ]
        )

        self.assertEqual(checker.check_workflow_runs_status(1), FAIL)


if __name__ == "__main__":
    unittest.main()
