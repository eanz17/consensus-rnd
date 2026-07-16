from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from codex_refactor_loop.issue_2737_recovery import (  # noqa: E402
    ORDER,
    Issue2737Effect,
    Issue2737RecoveryBlocked,
    LiteralIssue2737Port,
    Issue2737Binding,
    Issue2737Recovery,
    binding_from_observation,
    acquire_live_observation,
    literal_effect_target,
    next_effect,
    parse_occurrence_record,
    read_target_projection,
    validate_singleton_pr_b_changes,
    validate_live_occurrence,
)
from codex_refactor_loop.controller_actions import ControllerActions  # noqa: E402
from codex_refactor_loop.context import LoopContext  # noqa: E402
from codex_refactor_loop.github_actor import GitHubAuthenticatedActor  # noqa: E402
from codex_refactor_loop.issue_decomposition import (  # noqa: E402
    IssueDecompositionApplyProjection,
    IssueDecompositionError,
    IssueDecompositionTrackingChild,
    IssueDecompositionTrackingComment,
    IssueDecompositionTrackingProjection,
    build_issue_decomposition_apply_projection,
    build_issue_decomposition_tracking_block,
    issue_decomposition_child_fingerprint,
    issue_decomposition_plan_digest,
)


def record_bytes() -> bytes:
    empty_reactions = []
    def comment(number: int) -> dict[str, object]:
        return {"author": "eanz17", "body_sha256": hashlib.sha256(f"comment-{number}".encode()).hexdigest(), "created_at": "2026-07-01T00:00:00Z", "id": number, "minimized": False, "reactions": empty_reactions, "updated_at": "2026-07-01T00:00:00Z", "url": f"https://github.com/aevatarAI/aevatar/issues/2737#issuecomment-{number}"}
    def issue(number: int) -> dict[str, object]:
        comments = [comment(number * 10)]
        if number == 2737:
            comments.extend((comment(4983244800), comment(4983315457)))
        return {"assignees": [], "author": "eanz17", "body_sha256": hashlib.sha256(f"body-{number}".encode()).hexdigest(), "comment_high_water": max(row["id"] for row in comments), "comments": comments, "issue": number, "labels": ["crnd:lifecycle:managed"], "milestone": "", "reactions": [], "state": "open", "state_reason": "", "title_sha256": hashlib.sha256(f"title-{number}".encode()).hexdigest(), "url": f"https://github.com/aevatarAI/aevatar/issues/{number}"}
    topology = [
        {"issue": 2775, "slug": "materialize", "url": "https://github.com/aevatarAI/aevatar/issues/2775"},
        {"issue": 2776, "slug": "derive", "url": "https://github.com/aevatarAI/aevatar/issues/2776"},
        {"issue": 2777, "slug": "integrate", "url": "https://github.com/aevatarAI/aevatar/issues/2777"},
    ]
    retired = [
        {"issue": 2772, "slug": "legacy-materialize", "url": "https://github.com/aevatarAI/aevatar/issues/2772"},
        {"issue": 2773, "slug": "legacy-derive", "url": "https://github.com/aevatarAI/aevatar/issues/2773"},
        {"issue": 2774, "slug": "legacy-integrate", "url": "https://github.com/aevatarAI/aevatar/issues/2774"},
    ]
    raw = {
        "authorization_pr": {"base_ref": "main", "expected_base_sha": "2" * 40, "head_ref": "authorize", "number": 2},
        "contract": "issue-2737-reselection-occurrence",
        "implementation": {"bound_files": [{"blob_oid": "b" * 40, "path": "skills/consensus-loop/scripts/codex_refactor_loop/issue_2737_recovery.py", "sha256": "c" * 64}], "fork_repository": "eanz17/consensus-rnd", "merge_sha": "2" * 40, "merge_tree_oid": "4" * 40, "pr_number": 1, "reviewed_head_sha": "1" * 40, "reviewed_tree_oid": "5" * 40},
        "incident": {"decision_artifact_sha256": "6" * 64, "invariant_pr_number": 2752, "parent_issue": 2737, "plan_comment_id": 4983244800, "plan_digest": "7" * 64, "plan_path": ".refactor-loop/runs/issue-2737-decomposition/plan.json", "target_repository": "aevatarAI/aevatar", "tracking_comment_id": 4983315457},
        "occurrence": {"cleanup_required": True, "expected_initial_prefix": 0, "expires_at": "2099-01-01T00:00:00Z"},
        "prefix_zero_baseline": {"children": [issue(n) for n in (2772, 2773, 2774, 2775, 2776, 2777)], "invariant_pr": {"base_ref": "main", "base_repository": "aevatarAI/aevatar", "base_sha": "d" * 40, "body_sha256": hashlib.sha256(b"pr-body").hexdigest(), "draft": False, "head_ref": "work", "head_repository": "aevatarAI/aevatar", "head_sha": "f" * 40, "number": 2752, "state": "open", "title_sha256": hashlib.sha256(b"pr-title").hexdigest(), "url": "https://github.com/aevatarAI/aevatar/pull/2752"}, "parent": issue(2737), "parent_comments": [comment(4983244800), comment(4983315457)]},
        "settled_topology": {"fingerprints": [{"fingerprint": ch * 64, "modern_issue": row["issue"], "slug": row["slug"]} for ch, row in zip("123", topology)], "retained": topology, "retired": retired},
    }
    return json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class RecordAndPathTests(unittest.TestCase):
    def test_canonical_record_and_closed_top_level(self):
        value = parse_occurrence_record(record_bytes(), now=datetime(2026, 7, 16, tzinfo=timezone.utc))
        self.assertEqual("eanz17/consensus-rnd", value.raw["implementation"]["fork_repository"])
        raw = json.loads(record_bytes())
        for key, value in (("effect", "M2775"), ("unexpected", {}), ("authorized", True)):
            changed = dict(raw)
            changed[key] = value
            data = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            with self.subTest(key=key), self.assertRaises(Issue2737RecoveryBlocked):
                parse_occurrence_record(data)

    def test_duplicate_noncanonical_expired_and_wrong_target_fail(self):
        canonical = record_bytes()
        cases = [canonical.replace(b'"contract":', b'"contract":"x","contract":', 1), canonical.replace(b',', b', ', 1), canonical.replace(b"2099-01-01", b"2020-01-01"), canonical.replace(b"aevatarAI/aevatar", b"ChronoAIProject/consensus-rnd")]
        for data in cases:
            with self.subTest(data=data[:40]), self.assertRaises(Issue2737RecoveryBlocked):
                parse_occurrence_record(data, now=datetime(2026, 7, 16, tzinfo=timezone.utc))

    def test_nested_baseline_and_topology_are_closed_and_relational(self):
        raw = json.loads(record_bytes())
        cases = []
        changed = json.loads(record_bytes()); changed["prefix_zero_baseline"]["parent"]["extra"] = True; cases.append(changed)
        changed = json.loads(record_bytes()); changed["prefix_zero_baseline"]["children"].pop(); cases.append(changed)
        changed = json.loads(record_bytes()); changed["settled_topology"]["retained"][0]["issue"] = 9999; cases.append(changed)
        changed = json.loads(record_bytes()); changed["settled_topology"]["retained"][0], changed["settled_topology"]["retained"][1] = changed["settled_topology"]["retained"][1], changed["settled_topology"]["retained"][0]; cases.append(changed)
        changed = json.loads(record_bytes()); changed["settled_topology"]["fingerprints"][0]["slug"] = "derive"; cases.append(changed)
        changed = json.loads(record_bytes()); changed["prefix_zero_baseline"]["parent"]["issue"] = 9999; cases.append(changed)
        changed = json.loads(record_bytes()); changed["prefix_zero_baseline"]["invariant_pr"]["number"] = 9999; cases.append(changed)
        changed = json.loads(record_bytes()); changed["authorization_pr"]["expected_base_sha"] = "3" * 40; cases.append(changed)
        changed = json.loads(record_bytes()); changed["implementation"]["bound_files"] = []; cases.append(changed)
        for row in cases:
            with self.subTest(row=row), self.assertRaises(Issue2737RecoveryBlocked):
                parse_occurrence_record(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def test_live_binding_requires_all_owner_projections_and_noop_403(self):
        occurrence = parse_occurrence_record(record_bytes(), now=datetime(2026, 7, 16, tzinfo=timezone.utc))
        observation = {"record_blob_oid": "b" * 40, "prefix": 0, "pr_a": {"admitted": True}, "pr_b": {"admitted": True, "record_blob_oid": "b" * 40}, "review": {"admitted": True}, "checks": {"admitted": True}, "checkout": {"admitted": True}, "target": {"admitted": True}, "decomposition": {"is_noop": True, "conflicts": []}}
        self.assertEqual(0, binding_from_observation(occurrence, observation).prefix)
        for key in ("review", "checks", "target"):
            broken = json.loads(json.dumps(observation)); broken[key]["admitted"] = False
            with self.subTest(key=key), self.assertRaises(Issue2737RecoveryBlocked):
                binding_from_observation(occurrence, broken)
        broken = json.loads(json.dumps(observation)); broken["decomposition"]["is_noop"] = False
        with self.assertRaises(Issue2737RecoveryBlocked): binding_from_observation(occurrence, broken)

    def test_production_binder_consumes_owner_local_projections(self):
        occurrence = parse_occurrence_record(record_bytes(), now=datetime(2026, 7, 16, tzinfo=timezone.utc))
        readiness = SimpleNamespace(ok=True, head_sha="1" * 40, required_failed=(), required_pending=(), missing_required=())
        authorization_readiness = SimpleNamespace(ok=True, head_sha="3" * 40, required_failed=(), required_pending=(), missing_required=())
        decomposition = SimpleNamespace(is_noop=True, conflicts=())
        actions = SimpleNamespace(
            _issue_2737_pr_binding_projection=mock.Mock(side_effect=({"admitted": True}, {"admitted": True, "base_sha": "2" * 40, "head_sha": "3" * 40, "api_files": ({"filename": "skills/consensus-loop/authorizations/issue-2737-reselection.json", "status": "added", "previous_filename": None},), "git_files": (("skills/consensus-loop/authorizations/issue-2737-reselection.json", "A", "100644"),), "record_blob_oid": "b" * 40, "checkout_admitted": True})),
            _issue_2737_pr_readiness=mock.Mock(side_effect=(readiness, authorization_readiness)),
            _issue_2737_review_projection=mock.Mock(return_value={"admitted": True}),
            _issue_2737_target_projection=mock.Mock(return_value={"admitted": True, "prefix": 4}),
            _issue_2737_decomposition_projection=mock.Mock(return_value=decomposition),
        )
        observation = acquire_live_observation(actions, occurrence)
        self.assertEqual(4, observation["prefix"])
        self.assertTrue(observation["checks"]["admitted"])

    def test_singleton_changed_path_requires_two_exact_complete_observations(self):
        path = "skills/consensus-loop/authorizations/issue-2737-reselection.json"
        validate_singleton_pr_b_changes(({"filename": path, "status": "added", "previous_filename": None},), ((path, "A", "100644"),))
        bad = (
            (({"filename": path, "status": "modified", "previous_filename": None},), ((path, "A", "100644"),)),
            (({"filename": path, "status": "added", "previous_filename": None}, {"filename": "extra", "status": "added"}), ((path, "A", "100644"), ("extra", "A", "100644"))),
            (({"filename": path, "status": "added", "previous_filename": None},), ((path, "A", "120000"),)),
        )
        for api, git in bad:
            with self.subTest(api=api), self.assertRaises(Issue2737RecoveryBlocked):
                validate_singleton_pr_b_changes(api, git)

    def test_real_authorization_pr_binder_golden_transcript_and_checkout_failures(self):
        raw = json.loads(record_bytes())
        authorization = raw["authorization_pr"]
        path = "skills/consensus-loop/authorizations/issue-2737-reselection.json"
        head = "3" * 40
        merge = "4" * 40
        tree = "5" * 40
        blob = "b" * 40
        implementation_path = raw["implementation"]["bound_files"][0]["path"]

        def run(*, origin="https://github.com/eanz17/consensus-rnd.git", object_format="sha1", operation=False,
                fetch_rc=0, binding_authorization=True, parents_override=None, tree_override=None,
                diff_override=None, api_override=None, mode="100644", record_override=None):
            git_calls = []
            gh_calls = []

            def completed(argv, stdout="", returncode=0):
                return subprocess.CompletedProcess(argv, returncode, stdout, "")

            def git(argv, check=False):
                git_calls.append((list(argv), check))
                key = tuple(argv)
                if key == ("remote", "get-url", "origin"): return completed(argv, origin + "\n")
                if key == ("rev-parse", "--show-object-format"): return completed(argv, object_format + "\n")
                if key[:2] == ("rev-parse", "--git-path"):
                    marker = key[-1]
                    return completed(argv, str(SCRIPT_DIR if operation and marker == "MERGE_HEAD" else SCRIPT_DIR / f"absent-{marker}"))
                if key[:3] == ("fetch", "--no-tags", "origin"): return completed(argv, returncode=fetch_rc)
                if key[:3] == ("show", "-s", "--format=%P"): return completed(argv, (parents_override or f"{'2' * 40} {head}") + "\n")
                if key[:3] == ("show", "-s", "--format=%T"): return completed(argv, (tree_override or tree) + "\n")
                if key[:2] == ("diff", "--name-status"):
                    return completed(argv, diff_override if diff_override is not None else f"A\0{path}\0")
                if key[0] == "ls-tree":
                    selected_path = path if binding_authorization else implementation_path
                    return completed(argv, f"{mode} blob {blob}\t{selected_path}\n")
                if key[0] == "hash-object": return completed(argv, blob + "\n")
                if key[0] == "rev-parse" and ":" in key[-1]: return completed(argv, blob + "\n")
                if key[:2] == ("status", "--porcelain=v1"): return completed(argv)
                if key[:3] == ("symbolic-ref", "-q", "HEAD"): return completed(argv, returncode=1)
                raise AssertionError(f"unexpected git call: {argv}")

            def gh(argv, check=False):
                gh_calls.append((list(argv), check))
                if argv[1].endswith("/pulls/2"):
                    return completed(argv, json.dumps({
                        "state": "closed", "merged": True, "merge_commit_sha": merge,
                        "head": {"sha": head, "ref": "authorize", "repo": {"full_name": "eanz17/consensus-rnd"}},
                        "base": {"sha": "2" * 40, "ref": "main", "repo": {"full_name": "eanz17/consensus-rnd"}},
                    }))
                if argv[1].endswith("/pulls/2/files"):
                    rows = api_override if api_override is not None else [{"filename": path, "status": "added", "previous_filename": None}]
                    return completed(argv, json.dumps([rows]))
                if argv[1].endswith("/pulls/1"):
                    return completed(argv, json.dumps({
                        "state": "closed", "merged": True, "merge_commit_sha": merge,
                        "head": {"sha": head, "ref": "implementation", "repo": {"full_name": "eanz17/consensus-rnd"}},
                        "base": {"sha": "2" * 40, "ref": "main", "repo": {"full_name": "eanz17/consensus-rnd"}},
                    }))
                if argv[1].endswith("/pulls/1/files"):
                    rows = api_override if api_override is not None else [{"filename": implementation_path, "status": "modified", "previous_filename": None}]
                    return completed(argv, json.dumps([rows]))
                raise AssertionError(f"unexpected gh call: {argv}")

            actions = SimpleNamespace(git=git, gh=gh, repo_root=SCRIPT_DIR.parent.parent.parent)
            selected = record_override or authorization
            return actions, git_calls, gh_calls, selected, binding_authorization

        actions, git_calls, gh_calls, selected, binding_authorization = run()
        projection = ControllerActions._issue_2737_pr_binding_projection(actions, selected, authorization=binding_authorization)
        self.assertTrue(projection["admitted"])
        self.assertTrue(projection["checkout_admitted"])
        self.assertIn((["fetch", "--no-tags", "origin", "pull/2/head", "pull/2/merge"], False), git_calls)
        self.assertEqual((["api", "repos/eanz17/consensus-rnd/pulls/2/files", "--paginate", "--slurp"], False), gh_calls[-1])

        for kwargs in (
            {"origin": "https://github.com/other/repo.git"},
            {"object_format": "unknown"},
            {"operation": True},
            {"fetch_rc": 1},
        ):
            actions, _, _, selected, binding_authorization = run(**kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                ControllerActions._issue_2737_pr_binding_projection(actions, selected, authorization=binding_authorization)

        implementation = dict(raw["implementation"])
        implementation.update(merge_sha=merge, reviewed_head_sha=head, merge_tree_oid=tree, reviewed_tree_oid=tree)
        bound = dict(implementation["bound_files"][0])
        local = SCRIPT_DIR.parent.parent.parent / bound["path"]
        bound.update(blob_oid=blob, sha256=hashlib.sha256(local.read_bytes()).hexdigest())
        implementation["bound_files"] = [bound]
        valid = dict(binding_authorization=False, record_override=implementation,
                     diff_override=f"M\0{implementation_path}\0")
        actions, _, _, selected, flag = run(**valid)
        self.assertTrue(ControllerActions._issue_2737_pr_binding_projection(actions, selected, authorization=flag)["admitted"])
        bad_cases = (
            {"parents_override": f"{head} {'2' * 40}"},
            {"parents_override": f"{'2' * 40} {head} {'9' * 40}"},
            {"parents_override": head},
            {"tree_override": "9" * 40},
            {"diff_override": f"M\0{implementation_path}"},
            {"diff_override": f"M\0{implementation_path}\0A\0extra\0"},
            {"api_override": []},
            {"api_override": [{"filename": "extra", "status": "modified", "previous_filename": None}]},
            {"api_override": [{"filename": implementation_path, "status": "renamed", "previous_filename": "old"}]},
            {"mode": "120000"},
            {"record_override": {**implementation, "reviewed_head_sha": "8" * 40}},
            {"record_override": {**implementation, "merge_sha": "8" * 40}},
            {"record_override": {**implementation, "bound_files": [{**bound, "blob_oid": "8" * 40}]}},
            {"record_override": {**implementation, "bound_files": [{**bound, "sha256": "8" * 64}]}},
        )
        for mutation in bad_cases:
            kwargs = {**valid, **mutation}
            actions, _, _, selected, flag = run(**kwargs)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                ControllerActions._issue_2737_pr_binding_projection(actions, selected, authorization=flag)


class CapabilityTests(unittest.TestCase):
    def test_total_order_has_only_nine_closed_variants(self):
        self.assertEqual(tuple(Issue2737Effect), ORDER)
        self.assertEqual(tuple(ORDER) + (None,), tuple(next_effect(prefix) for prefix in range(10)))
        for value in (-1, 10, True, "0"):
            with self.subTest(value=value), self.assertRaises(Issue2737RecoveryBlocked):
                next_effect(value)  # type: ignore[arg-type]

    def test_independent_literal_transport_transcript(self):
        actions = SimpleNamespace(gh=mock.Mock(return_value=subprocess.CompletedProcess([], 0, "{}", "")))
        port = LiteralIssue2737Port(actions)
        for effect in ORDER:
            port.invoke(effect)
        calls = actions.gh.call_args_list
        self.assertEqual(9, len(calls))
        expected_targets = (2775, 2772, 2772, 2776, 2773, 2773, 2777, 2774, 2774)
        expected_body_hashes = (
            "80202680a3e1f3692d14886ffee7834c4e784da4b022adbfbda5d7f9a65154d1",
            "635645dca2d17a7ce33fe673ec9fb57221cd88c50bf47fb43b8d7fec32ff8340", None,
            "25914ff1cf48aaa66302d1bae2457e44ff2e520132e851cef2e13604f2c28ca1",
            "fcd8bbd0c422e9ca90b5fada6c5cc18a2bd9df4d8c11565866619d06bbd883af", None,
            "983fbdb39c0fcde4f44adb86c3ac22cd8f8984d09cc7c59a727dbeadd506393d",
            "8fc7bc659911be6908f096546b9cf2eb723e7c3f59d0694c31c5c7eee9726646", None,
        )
        for index, (call, target) in enumerate(zip(calls, expected_targets)):
            argv = call.args[0]
            self.assertEqual("api", argv[0])
            self.assertEqual(f"repos/aevatarAI/aevatar/issues/{target}" + ("/comments" if index % 3 != 2 else ""), argv[1])
            self.assertEqual("POST" if index % 3 != 2 else "PATCH", argv[3])
            if index % 3 == 2:
                self.assertEqual(["-f", "state=closed", "-f", "state_reason=not_planned"], argv[4:])
            else:
                body = argv[-1][5:]
                self.assertEqual(expected_body_hashes[index], hashlib.sha256(body.encode()).hexdigest())
                self.assertTrue(body.endswith("\u27e6AI:AUTO-LOOP\u27e7\n"))

    def test_non_enum_effect_is_unrepresentable_without_transport(self):
        actions = SimpleNamespace(gh=mock.Mock())
        with self.assertRaises(Issue2737RecoveryBlocked):
            LiteralIssue2737Port(actions).invoke("M2775")  # type: ignore[arg-type]
        actions.gh.assert_not_called()


class ProductionTargetProjectionTests(unittest.TestCase):
    @staticmethod
    def _result(payload, returncode=0):
        return subprocess.CompletedProcess([], returncode, json.dumps(payload), "")

    def _actions(self, prefix: int, mutate=None):
        raw = json.loads(record_bytes())
        calls = []
        recorder = SimpleNamespace(gh=mock.Mock(side_effect=lambda argv, check=False: (calls.append(argv), self._result({}))[1]))
        for effect in ORDER:
            LiteralIssue2737Port(recorder).invoke(effect)
        effects = []
        for argv in calls:
            number = int(argv[1].split("/issues/")[1].split("/")[0])
            effects.append((number, argv[-1][5:] if argv[3] == "POST" else None, argv[3] == "PATCH"))
        issues = {row["issue"]: row for row in [raw["prefix_zero_baseline"]["parent"], *raw["prefix_zero_baseline"]["children"]]}
        comments = {number: [{"id": row["id"], "html_url": row["url"], "user": {"login": row["author"]}, "body": f"comment-{row['id']}", "created_at": row["created_at"], "updated_at": row["updated_at"], "minimized": row["minimized"]} for row in baseline["comments"]] for number, baseline in issues.items()}
        timelines = {number: [] for number in issues}
        for index, (number, body, closed) in enumerate(effects[:prefix], 1):
            if body is not None:
                comments[number].append({"id": 6000000000 + index, "html_url": f"https://github.com/aevatarAI/aevatar/issues/{number}#issuecomment-{6000000000 + index}", "user": {"login": "eanz17"}, "body": body, "created_at": f"2026-07-02T00:00:{index:02d}Z", "updated_at": f"2026-07-02T00:00:{index:02d}Z", "minimized": False})
            if closed:
                timelines[number].append({"event": "closed", "created_at": f"2026-07-02T00:00:{index:02d}Z", "actor": {"login": "eanz17"}})
        if mutate:
            mutate(raw, comments, timelines)

        def gh(argv, check=False):
            endpoint = argv[1]
            if endpoint.endswith("/pulls/2752"):
                baseline = raw["prefix_zero_baseline"]["invariant_pr"]
                return self._result({"number": 2752, "html_url": baseline["url"], "state": "open", "draft": False, "title": "pr-title", "body": "pr-body", "base": {"repo": {"full_name": "aevatarAI/aevatar"}, "ref": "main", "sha": "d" * 40}, "head": {"repo": {"full_name": "aevatarAI/aevatar"}, "ref": "work", "sha": "f" * 40}})
            if "/issues/comments/" in endpoint and endpoint.endswith("/reactions"):
                comment_id = endpoint.split("/issues/comments/")[1].split("/")[0]
                return self._result([[*raw.get("_test_comment_reactions", {}).get(comment_id, [])]])
            number = int(endpoint.split("/issues/")[1].split("/")[0])
            if endpoint.endswith("/comments"):
                return self._result([comments[number]])
            if endpoint.endswith("/reactions"):
                return self._result([[]])
            if endpoint.endswith("/timeline"):
                return self._result([timelines[number]])
            baseline = issues[number]
            closed = bool(timelines[number])
            return self._result({"number": number, "html_url": baseline["url"], "title": f"title-{number}", "body": f"body-{number}", "user": {"login": "eanz17"}, "labels": [{"name": "crnd:lifecycle:managed"}], "assignees": [], "milestone": None, "state": "closed" if closed else "open", "state_reason": "not_planned" if closed else None})
        return SimpleNamespace(gh=mock.Mock(side_effect=gh)), raw

    def test_real_target_reader_recognizes_every_exact_prefix(self):
        for prefix in range(10):
            actions, raw = self._actions(prefix)
            with self.subTest(prefix=prefix):
                self.assertEqual(prefix, read_target_projection(actions, raw)["prefix"])

    def test_real_target_reader_rejects_baseline_and_close_chronology_drift(self):
        mutations = (
            lambda raw, comments, timelines: comments[2775][0].update(updated_at="2026-07-03T00:00:00Z"),
            lambda raw, comments, timelines: comments[2775][0].update(minimized=True),
            lambda raw, comments, timelines: timelines[2772][0].update(actor={"login": "other"}),
            lambda raw, comments, timelines: timelines[2772][0].update(created_at="2026-07-01T00:00:00Z"),
            lambda raw, comments, timelines: timelines[2772].append({"event": "reopened", "created_at": "2026-07-03T00:00:00Z", "actor": {"login": "eanz17"}}),
            lambda raw, comments, timelines: comments[2775][-1].update(id=1),
            lambda raw, comments, timelines: comments[2775][-1].update(html_url="https://github.com/aevatarAI/aevatar/issues/2775#issuecomment-1"),
            lambda raw, comments, timelines: comments[2775][-1].update(created_at="2026-06-01T00:00:00Z", updated_at="2026-06-01T00:00:00Z"),
            lambda raw, comments, timelines: timelines[2772].append({"event": "labeled", "created_at": "2026-07-02T00:00:03.5Z", "actor": {"login": "eanz17"}}),
        )
        for mutate in mutations:
            actions, raw = self._actions(3, mutate)
            with self.subTest(mutate=mutate), self.assertRaises(Issue2737RecoveryBlocked):
                read_target_projection(actions, raw)

    def test_real_target_reader_rejects_global_close_comment_inversion(self):
        def invert(_raw, comments, timelines):
            timelines[2772][0]["created_at"] = "2026-07-02T00:00:04Z"
            comments[2776][-1]["created_at"] = "2026-07-02T00:00:03Z"
            comments[2776][-1]["updated_at"] = "2026-07-02T00:00:03Z"

        actions, raw = self._actions(4, invert)
        with self.assertRaises(Issue2737RecoveryBlocked):
            read_target_projection(actions, raw)

    def test_real_target_reader_rejects_every_forbidden_incident_history_shape(self):
        def wrong_target(_raw, comments, _timelines):
            comments[2776].append(comments[2775].pop())

        def duplicate(_raw, comments, _timelines):
            comments[2775].append(dict(comments[2775][-1], id=7000000001,
                                       html_url="https://github.com/aevatarAI/aevatar/issues/2775#issuecomment-7000000001"))

        mutations = (
            lambda _raw, comments, _timelines: comments[2775][-1].update(user={"login": "other"}),
            lambda _raw, comments, _timelines: comments[2775][-1].update(body="wrong body"),
            lambda raw, _comments, _timelines: raw.setdefault("_test_comment_reactions", {}).update(
                {"6000000001": [{"content": "+1", "user": {"login": "eanz17"}}]}
            ),
            wrong_target,
            duplicate,
            lambda _raw, comments, _timelines: comments[2777].append(dict(comments[2775][-1], id=7000000002,
                html_url="https://github.com/aevatarAI/aevatar/issues/2777#issuecomment-7000000002")),
            lambda _raw, _comments, timelines: timelines[2775].append(
                {"event": "closed", "created_at": "2026-07-02T00:00:04Z", "actor": {"login": "eanz17"}}
            ),
            lambda raw, _comments, _timelines: raw["prefix_zero_baseline"]["invariant_pr"].update(head_sha="0" * 40),
        )
        for mutate in mutations:
            actions, raw = self._actions(3, mutate)
            with self.subTest(mutate=mutate), self.assertRaises(Issue2737RecoveryBlocked):
                read_target_projection(actions, raw)

    def test_real_target_reader_uses_exact_paginated_read_transcript(self):
        actions, raw = self._actions(0)
        read_target_projection(actions, raw)
        expected = []
        for number in (2737, 2772, 2773, 2774, 2775, 2776, 2777):
            expected.extend((
                ["api", f"repos/aevatarAI/aevatar/issues/{number}"],
                ["api", f"repos/aevatarAI/aevatar/issues/{number}/comments", "--paginate", "--slurp"],
                ["api", f"repos/aevatarAI/aevatar/issues/{number}/reactions", "--paginate", "--slurp"],
                ["api", f"repos/aevatarAI/aevatar/issues/{number}/timeline", "--paginate", "--slurp"],
                ["api", f"repos/aevatarAI/aevatar/issues/comments/{number * 10}/reactions", "--paginate", "--slurp"],
            ))
            if number == 2737:
                expected.extend((
                    ["api", "repos/aevatarAI/aevatar/issues/comments/4983244800/reactions", "--paginate", "--slurp"],
                    ["api", "repos/aevatarAI/aevatar/issues/comments/4983315457/reactions", "--paginate", "--slurp"],
                ))
        expected.insert(7, ["api", "repos/aevatarAI/aevatar/pulls/2752"])
        self.assertEqual(expected, [call.args[0] for call in actions.gh.call_args_list])
        self.assertTrue(all(call.kwargs == {"check": False} for call in actions.gh.call_args_list))


class CoordinatorTests(unittest.TestCase):
    def binding(self, prefix: int, observation: str = "same") -> Issue2737Binding:
        return Issue2737Binding("a" * 64, "b" * 40, datetime(2099, 1, 1, tzinfo=timezone.utc), prefix, observation)

    def test_immediate_admission_and_binding_revalidation_precede_one_effect(self):
        events = []
        bindings = iter((self.binding(0), self.binding(0), self.binding(0), self.binding(1, "after")))
        class Actions:
            def _validate_issue_2737_occurrence(inner): events.append("bind"); return next(bindings)
            def _revalidate_issue_2737_effect_admission(inner, effect): events.append(("admit", effect))
            def gh(inner, argv, check=False): events.append("transport"); return subprocess.CompletedProcess(argv, 0, "{}", "")
        self.assertEqual(1, Issue2737Recovery(Actions()).run())
        self.assertEqual(["bind", "bind", "bind", ("admit", Issue2737Effect.M2775), "transport", "bind"], events)

    def test_drift_or_response_loss_stops_without_later_effect_or_compensation(self):
        for bindings in (
            (self.binding(0), self.binding(0), self.binding(0, "drift")),
            (self.binding(0), self.binding(0), self.binding(0), self.binding(0)),
        ):
            actions = SimpleNamespace(
                _validate_issue_2737_occurrence=mock.Mock(side_effect=bindings),
                _revalidate_issue_2737_effect_admission=mock.Mock(),
                gh=mock.Mock(return_value=subprocess.CompletedProcess([], 0, "{}", "")),
            )
            with self.subTest(count=len(bindings)), self.assertRaises(Issue2737RecoveryBlocked):
                Issue2737Recovery(actions).run()
            self.assertLessEqual(actions.gh.call_count, 1)

    def test_every_effect_has_one_write_success_and_failure_transition(self):
        for prefix, effect in enumerate(ORDER):
            before = self.binding(prefix)
            after = self.binding(prefix + 1, f"after-{prefix}")
            actions = SimpleNamespace(
                _validate_issue_2737_occurrence=mock.Mock(side_effect=(before, before, before, after)),
                _revalidate_issue_2737_effect_admission=mock.Mock(),
                gh=mock.Mock(return_value=subprocess.CompletedProcess([], 0, "{}", "")),
            )
            with self.subTest(prefix=prefix, result="success"):
                self.assertEqual(prefix + 1, Issue2737Recovery(actions).run())
                actions._revalidate_issue_2737_effect_admission.assert_called_once_with(effect)
                self.assertEqual(1, actions.gh.call_count)
            failed = SimpleNamespace(
                _validate_issue_2737_occurrence=mock.Mock(side_effect=(before, before, before, before)),
                _revalidate_issue_2737_effect_admission=mock.Mock(),
                gh=mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "failed")),
            )
            with self.subTest(prefix=prefix, result="failure"), self.assertRaises(Issue2737RecoveryBlocked):
                Issue2737Recovery(failed).run()
            self.assertEqual(1, failed.gh.call_count)

    def test_every_ambiguous_effect_adopts_only_exact_fresh_next_prefix(self):
        for prefix, effect in enumerate(ORDER):
            before = self.binding(prefix)
            after = self.binding(prefix + 1, f"committed-{prefix}")
            for outcome in (
                subprocess.CompletedProcess([], 1, "", "timeout"),
                TimeoutError("response lost"),
            ):
                transport = mock.Mock(side_effect=outcome if isinstance(outcome, BaseException) else None,
                                      return_value=None if isinstance(outcome, BaseException) else outcome)
                actions = SimpleNamespace(
                    _validate_issue_2737_occurrence=mock.Mock(side_effect=(before, before, before, after)),
                    _revalidate_issue_2737_effect_admission=mock.Mock(), gh=transport,
                )
                with self.subTest(prefix=prefix, outcome=type(outcome).__name__):
                    self.assertEqual(prefix + 1, Issue2737Recovery(actions).run())
                    actions._revalidate_issue_2737_effect_admission.assert_called_once_with(effect)
                    self.assertEqual(1, transport.call_count)

    def _run_recorded_production_acquisition(self, failure=None):
        """One recorded harness composes the production owners through ambiguous adoption."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bound_path = root / "skills/consensus-loop/scripts/codex_refactor_loop/issue_2737_recovery.py"
            bound_path.parent.mkdir(parents=True)
            bound_path.write_bytes(b"recorded reviewed PR-A capability\n")
            raw_record = json.loads(record_bytes())
            runs = root / ".refactor-loop/runs"
            runs.mkdir(parents=True)
            consensus_path = ".refactor-loop/runs/consensus.md"
            parent_comment_path = ".refactor-loop/runs/parent.md"
            (root / consensus_path).write_text("consensus\n", encoding="utf-8")
            (root / parent_comment_path).write_text("Parent issue: #2737\n\n\u27e6AI:AUTO-LOOP\u27e7\n", encoding="utf-8")
            children = []
            for slug in ("materialize", "derive", "integrate"):
                body_path = f".refactor-loop/runs/{slug}.md"
                scope = f"{slug} scope"
                non_goals = "No lifecycle expansion"
                (root / body_path).write_text(
                    f"Parent issue: #2737\nSource consensus artifact: consensus.md\nScope: {scope}\n"
                    f"Non-goals: {non_goals}\n\n<details>\n<summary>\u5185\u8054 artifact 1: decision.md</summary>\n\n"
                    "```markdown\nevidence\n```\n\n</details>\n\n\u27e6AI:AUTO-LOOP\u27e7\n",
                    encoding="utf-8",
                )
                children.append({"slug": slug, "title": slug.title(), "scope": scope,
                                 "non_goals": non_goals, "body_artifact_path": body_path})
            plan_raw = {"schema": "IssueDecompositionPlan", "parent_issue": 2737,
                        "source_consensus_artifact": consensus_path, "children": children,
                        "parent_update": {"comment_artifact_path": parent_comment_path}}
            plan_path = root / ".refactor-loop/runs/issue-2737-decomposition/plan.json"
            plan_path.parent.mkdir(parents=True)
            plan_path.write_text(json.dumps(plan_raw), encoding="utf-8")
            plan_digest = issue_decomposition_plan_digest(plan_raw)
            raw_record["incident"]["plan_digest"] = plan_digest
            raw_record["implementation"]["merge_tree_oid"] = "5" * 40
            raw_record["implementation"]["bound_files"][0].update(
                blob_oid="d" * 40, sha256=hashlib.sha256(bound_path.read_bytes()).hexdigest()
            )
            exact_record = json.dumps(raw_record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            record_path = root / "skills/consensus-loop/authorizations/issue-2737-reselection.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_bytes(exact_record)
            occurrence = parse_occurrence_record(exact_record)
            host_env = root / ".config/consensus-rnd/host.env"
            host_env.parent.mkdir(parents=True)
            host_env.write_text(
                f'export REPO_ROOT="{root}"\nexport GH_REPO_SLUG="aevatarAI/aevatar"\n', encoding="utf-8"
            )
            ctx = LoopContext.load(repo_root=root, env={"CONSENSUS_RND_HOST_ENV": ".config/consensus-rnd/host.env"})

            def actor_runner(command, _cwd):
                payload = {"login": "eanz17"} if list(command) == ["gh", "api", "user"] else {"permission": "write"}
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            target_harness = ProductionTargetProjectionTests()
            target_reads = iter(target_harness._actions(prefix)[0] for prefix in (0, 0, 0, 1))

            tracked_children = tuple(
                IssueDecompositionTrackingChild(
                    slug, number, f"https://github.com/aevatarAI/aevatar/issues/{number}",
                    issue_decomposition_child_fingerprint(2737, plan_digest, slug),
                )
                for slug, number in zip(("materialize", "derive", "integrate"), (2775, 2776, 2777))
            )
            tracking_body = build_issue_decomposition_tracking_block(2737, plan_digest, tracked_children)

            class RecordedActions:
                repo_root = root
                def __init__(self):
                    self.ctx = ctx
                    self.github_actor = GitHubAuthenticatedActor(ctx, runner=actor_runner)
                    self.transports = 0
                    self.events = []
                    self.owner_calls = {}
                    self.active_owner = None
                def owner_call(self, name, callback):
                    self.owner_calls[name] = self.owner_calls.get(name, 0) + 1
                    self.active_owner = name if failure == (name, self.owner_calls[name]) else None
                    try:
                        return callback()
                    finally:
                        self.active_owner = None
                def _validate_issue_2737_occurrence(self):
                    return validate_live_occurrence(self)
                def _issue_2737_live_observation(self, parsed):
                    self.assert_same_record(parsed)
                    return acquire_live_observation(self, parsed)
                @staticmethod
                def assert_same_record(parsed):
                    if parsed.exact_bytes != occurrence.exact_bytes:
                        raise AssertionError("record drift")
                def _issue_2737_pr_binding_projection(self, record, *, authorization):
                    owner = "pr-b" if authorization else "pr-a"
                    self.events.append(owner)
                    return self.owner_call(owner, lambda: ControllerActions._issue_2737_pr_binding_projection(
                        self, record, authorization=authorization
                    ))
                def _issue_2737_pr_readiness(self, repo, number):
                    self.events.append(f"checks:{number}")
                    owner = "checks-b" if number == 2 else "checks-a"
                    return self.owner_call(owner, lambda: ControllerActions._issue_2737_pr_readiness(self, repo, number))
                def _issue_2737_review_projection(self, implementation):
                    self.events.append("review")
                    owner = "review-b" if implementation["pr_number"] == 2 else "review-a"
                    return self.owner_call(owner, lambda: ControllerActions._issue_2737_review_projection(self, implementation))
                def _issue_2737_target_projection(self, raw):
                    self.events.append("target")
                    self._target_actions = next(target_reads)
                    return self.owner_call("target", lambda: ControllerActions._issue_2737_target_projection(
                        self, raw
                    ))
                def _issue_2737_decomposition_projection(self, raw):
                    self.events.append("decomposition")
                    def project():
                        if self.active_owner != "decomposition":
                            return ControllerActions._issue_2737_decomposition_projection(self, raw)
                        original = plan_path.read_bytes()
                        plan_path.write_bytes(original.replace(b'"parent_issue": 2737', b'"parent_issue": 9999'))
                        try:
                            return ControllerActions._issue_2737_decomposition_projection(self, raw)
                        finally:
                            plan_path.write_bytes(original)
                    return self.owner_call("decomposition", project)
                def _issue_decomposition_parent_comments(self, parent):
                    self.events.append("tracking-comments")
                    return ControllerActions._issue_decomposition_parent_comments(self, parent)
                def _issue_decomposition_existing_children_by_fingerprint(self, plan, digest):
                    self.events.append("existing-children")
                    return ControllerActions._issue_decomposition_existing_children_by_fingerprint(self, plan, digest)
                def _issue_decomposition_live_child_by_fingerprint(self, slug, fingerprint):
                    self.events.append("live-duplicate")
                    return ControllerActions._issue_decomposition_live_child_by_fingerprint(self, slug, fingerprint)
                def _revalidate_issue_2737_effect_admission(self, effect):
                    self.events.extend(("lease", "actor", f"item:{literal_effect_target(effect)}"))
                    for owner in ("lease", "actor", "item"):
                        self.owner_calls[owner] = self.owner_calls.get(owner, 0) + 1
                    self.active_owner = next(
                        (owner for owner in ("lease", "actor", "item") if failure == (owner, self.owner_calls[owner])), None
                    )
                    try:
                        return ControllerActions._revalidate_issue_2737_effect_admission(self, effect)
                    finally:
                        self.active_owner = None
                def _require_owner_or_raise(self, action): return ControllerActions._require_owner_or_raise(self, action)
                def _require_github_actor_or_raise(self, action): return ControllerActions._require_github_actor_or_raise(self, action)
                def _normalize_lifecycle_target_or_raise(self, value, **kwargs):
                    return ControllerActions._normalize_lifecycle_target_or_raise(self, value, **kwargs)
                def _normalize_lifecycle_target_or_block(self, value, **kwargs):
                    return ControllerActions._normalize_lifecycle_target_or_block(self, value, **kwargs)
                def _require_item_write_admission_or_return(self, *args, **kwargs):
                    return ControllerActions._require_item_write_admission_or_return(self, *args, **kwargs)
                def cross_instance_admission(self, *args, **kwargs):
                    return ControllerActions.cross_instance_admission(self, *args, **kwargs)
                def _record_cross_instance_stand_down(self, *args, **kwargs):
                    return ControllerActions._record_cross_instance_stand_down(self, *args, **kwargs)
                def _append_pending_event(self, line):
                    return ControllerActions._append_pending_event(self, line)
                def gh(self, argv, check=False):
                    if argv[:3] == ["issue", "view", "2737"]:
                        if self.active_owner == "decomposition":
                            return subprocess.CompletedProcess(argv, 0, json.dumps({"comments": []}), "")
                        return subprocess.CompletedProcess(argv, 0, json.dumps({"comments": [{"body": tracking_body}]}), "")
                    if argv[0] == "api" and argv[1].startswith("repos/aevatarAI/aevatar/") and ("/issues/" in argv[1] or "/pulls/2752" in argv[1]) and "-X" not in argv:
                        if self.active_owner == "target":
                            return subprocess.CompletedProcess(argv, 0, "{malformed", "")
                        return self._target_actions.gh(argv, check=check)
                    endpoint = argv[1] if len(argv) > 1 else ""
                    if endpoint.endswith("/pulls/1"):
                        payload = {"state": "closed", "merged": True, "merge_commit_sha": "2" * 40,
                                   "head": {"sha": "1" * 40, "ref": "implementation", "repo": {"full_name": "eanz17/consensus-rnd"}},
                                   "base": {"sha": "0" * 40, "ref": "main", "repo": {"full_name": "eanz17/consensus-rnd"}}}
                        if self.active_owner == "pr-a": payload["merged"] = False
                        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
                    if endpoint.endswith("/pulls/2"):
                        payload = {"state": "closed", "merged": True, "merge_commit_sha": "4" * 40,
                                   "head": {"sha": "3" * 40, "ref": "authorize", "repo": {"full_name": "eanz17/consensus-rnd"}},
                                   "base": {"sha": "2" * 40, "ref": "main", "repo": {"full_name": "eanz17/consensus-rnd"}}}
                        if self.active_owner == "pr-b": payload["merged"] = False
                        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
                    if endpoint.endswith("/pulls/1/files"):
                        row = {"filename": raw_record["implementation"]["bound_files"][0]["path"], "status": "modified", "previous_filename": None}
                        return subprocess.CompletedProcess(argv, 0, json.dumps([[row]]), "")
                    if endpoint.endswith("/pulls/2/files"):
                        row = {"filename": "skills/consensus-loop/authorizations/issue-2737-reselection.json", "status": "added", "previous_filename": None}
                        return subprocess.CompletedProcess(argv, 0, json.dumps([[row]]), "")
                    if endpoint.endswith("/issues/1/comments") or endpoint.endswith("/issues/2/comments"):
                        number = int(endpoint.split("/issues/")[1].split("/")[0])
                        head = "1" * 40 if number == 1 else "3" * 40
                        verdict = "reject" if self.active_owner in ("review-a", "review-b") else "approve"
                        rows = [{"id": index + number * 10, "created_at": f"2026-07-16T00:00:0{index}Z",
                                 "body": f"---\nhead_sha: {head}\nverdict: {verdict}\n---\nREVIEW_DONE:{number}:{role}:{verdict}\n\n\u27e6AI:AUTO-LOOP\u27e7\n"}
                                for index, role in enumerate(("architect", "tests", "quality"), 1)]
                        return subprocess.CompletedProcess(argv, 0, json.dumps([rows]), "")
                    self.events.append(("transport", tuple(argv)))
                    self.transports += 1
                    return subprocess.CompletedProcess([], 1, "", "ambiguous")
                def git(self, argv, check=False):
                    key = tuple(argv)
                    path = raw_record["implementation"]["bound_files"][0]["path"]
                    occurrence_path = "skills/consensus-loop/authorizations/issue-2737-reselection.json"
                    if key == ("remote", "get-url", "origin"): out, rc = "https://github.com/eanz17/consensus-rnd.git\n", 0
                    elif key == ("rev-parse", "--show-object-format"): out, rc = "sha1\n", 0
                    elif key[:2] == ("rev-parse", "--git-path"): out, rc = str(root / "absent" / key[-1]), 0
                    elif key[:3] == ("fetch", "--no-tags", "origin"): out, rc = "", 0
                    elif key[:3] == ("show", "-s", "--format=%P"):
                        out, rc = (("0" * 40 + " " + "1" * 40) if key[-1] == "2" * 40 else ("2" * 40 + " " + "3" * 40)) + "\n", 0
                    elif key[:3] == ("show", "-s", "--format=%T"):
                        out, rc = ("5" * 40 if key[-1] in ("1" * 40, "2" * 40) else "6" * 40) + "\n", 0
                    elif key[:2] == ("diff", "--name-status"):
                        selected = occurrence_path if key[-1] == "3" * 40 else path
                        status = "A" if selected == occurrence_path else "M"
                        out, rc = f"{status}\0{selected}\0", 0
                    elif key[0] == "ls-tree":
                        selected = occurrence_path if key[-1] == occurrence_path else path
                        blob = "b" * 40 if selected == occurrence_path else "d" * 40
                        out, rc = f"100644 blob {blob}\t{selected}\n", 0
                    elif key[0] == "hash-object" or (key[0] == "rev-parse" and ":" in key[-1]): out, rc = "b" * 40 + "\n", 0
                    elif key[:2] == ("status", "--porcelain=v1"): out, rc = "", 0
                    elif key[:3] == ("symbolic-ref", "-q", "HEAD"): out, rc = "", 1
                    else: raise AssertionError(f"unexpected recorded git call: {argv}")
                    return subprocess.CompletedProcess(argv, rc, out, "")
                def _cross_instance_runner(self, command, _cwd):
                    command = list(command)
                    if command[:3] == ["gh", "pr", "view"]:
                        number = int(command[3]); head = "1" * 40 if number == 1 else "3" * 40
                        payload = {"baseRefName": "main", "headRefOid": head, "mergeStateStatus": "CLEAN"}
                    elif "/protection/required_status_checks" in command[2]: payload = {"contexts": ["required"]}
                    elif "/check-runs" in command[2]:
                        payload = [[{"name": "required", "status": "in_progress", "conclusion": None}]] if self.active_owner in ("checks-a", "checks-b") else [[{"name": "required", "status": "completed", "conclusion": "success"}]]
                    elif command[:2] == ["gh", "api"] and ("/comments?" in command[2] or "/timeline?" in command[2]):
                        if self.active_owner == "item":
                            return subprocess.CompletedProcess(command, 0, "{malformed", "")
                        payload = [[]]
                    else: raise AssertionError(f"unexpected owner/readiness command: {command}")
                    return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

            actions = RecordedActions()
            snapshot = SimpleNamespace(loaded_ok=True, items=())
            allowed_lease = SimpleNamespace(allowed=True, owner_device="local-single-device")
            denied_lease = SimpleNamespace(allowed=False, owner_device="other-device")
            real_actor_runner = actions.github_actor.runner
            def refusal_actor_runner(command, cwd):
                if actions.active_owner == "actor" and list(command) == ["gh", "api", "user"]:
                    return subprocess.CompletedProcess(command, 0, json.dumps({"login": "other-user"}), "")
                return real_actor_runner(command, cwd)
            actions.github_actor = GitHubAuthenticatedActor(ctx, runner=refusal_actor_runner)
            def lease_decision(_ctx, _action):
                return denied_lease if actions.active_owner == "lease" else allowed_lease
            with mock.patch("codex_refactor_loop.controller_actions.load_open_managed_work_snapshot", return_value=snapshot), mock.patch(
                "codex_refactor_loop.controller_actions.require_active_controller", side_effect=lease_decision
            ), mock.patch("codex_refactor_loop.controller_actions.write_active_controller_status"):
                if failure is None:
                    self.assertEqual(1, Issue2737Recovery(actions).run())
                else:
                    with self.assertRaises((Issue2737RecoveryBlocked, IssueDecompositionError, RuntimeError)):
                        Issue2737Recovery(actions).run()
                    expected_transports = 1 if failure[1] == 4 else 0
                    self.assertEqual(expected_transports, actions.transports)
                    return actions.events
            self.assertEqual(1, actions.transports)
            self.assertEqual(4, actions.events.count("pr-a"))
            self.assertEqual(4, actions.events.count("pr-b"))
            self.assertEqual(8, len([event for event in actions.events if str(event).startswith("checks:")]))
            self.assertEqual(8, actions.events.count("review"))
            self.assertEqual(4, actions.events.count("target"))
            self.assertEqual(4, actions.events.count("decomposition"))
            self.assertEqual(4, actions.events.count("tracking-comments"))
            self.assertEqual(4, actions.events.count("existing-children"))
            self.assertNotIn("live-duplicate", actions.events)
            transport_index = next(index for index, event in enumerate(actions.events) if isinstance(event, tuple))
            self.assertEqual(["lease", "actor", "item:2775"], actions.events[transport_index - 3:transport_index])
            transport = actions.events[transport_index][1]
            self.assertEqual(("api", "repos/aevatarAI/aevatar/issues/2775/comments", "-X", "POST"), transport[:4])
            self.assertEqual(1, len([event for event in actions.events if isinstance(event, tuple)]))
            acquisition = [
                "pr-a", "pr-b", "checks:1", "review", "checks:2", "review", "target",
                "decomposition", "tracking-comments", "existing-children",
            ]
            self.assertEqual(
                acquisition * 3 + ["lease", "actor", "item:2775", actions.events[transport_index]] + acquisition,
                actions.events,
            )

    def test_recorded_production_acquisition_adopts_ambiguous_next_prefix(self):
        self._run_recorded_production_acquisition()

    def test_recorded_production_acquisition_refuses_each_real_owner_boundary(self):
        pre_transport = (
            "pr-a", "pr-b", "checks-a", "review-a", "checks-b", "review-b",
            "target", "decomposition", "lease", "actor", "item",
        )
        for owner in pre_transport:
            with self.subTest(owner=owner):
                events = self._run_recorded_production_acquisition((owner, 1))
                self.assertFalse(any(isinstance(event, tuple) for event in events))

        for owner in ("pr-a", "pr-b", "checks-a", "review-a", "checks-b", "review-b", "target", "decomposition"):
            with self.subTest(owner=owner, phase="post-transport"):
                events = self._run_recorded_production_acquisition((owner, 4))
                transports = [event for event in events if isinstance(event, tuple)]
                self.assertEqual(1, len(transports))

    def test_ambiguous_effect_blocks_unchanged_skipped_and_repeated_ambiguity(self):
        before = self.binding(0)
        for observed in (before, self.binding(2, "skipped")):
            actions = SimpleNamespace(
                _validate_issue_2737_occurrence=mock.Mock(side_effect=(before, before, before, observed)),
                _revalidate_issue_2737_effect_admission=mock.Mock(),
                gh=mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "timeout")),
            )
            with self.subTest(prefix=observed.prefix), self.assertRaises(Issue2737RecoveryBlocked):
                Issue2737Recovery(actions).run()
            self.assertEqual(1, actions.gh.call_count)
        unavailable = SimpleNamespace(
            _validate_issue_2737_occurrence=mock.Mock(side_effect=(before, before, before, TimeoutError("refetch"))),
            _revalidate_issue_2737_effect_admission=mock.Mock(),
            gh=mock.Mock(side_effect=TimeoutError("transport")),
        )
        with self.assertRaises(Issue2737RecoveryBlocked):
            Issue2737Recovery(unavailable).run()
        self.assertEqual(1, unavailable.gh.call_count)

    def test_verify_only_and_terminal_are_zero_transport(self):
        for prefix, verify in ((0, True), (9, False)):
            binding = self.binding(prefix)
            actions = SimpleNamespace(_validate_issue_2737_occurrence=mock.Mock(side_effect=(binding, binding)), gh=mock.Mock())
            self.assertEqual(prefix, Issue2737Recovery(actions).run(verify_only=verify))
            actions.gh.assert_not_called()

    def test_real_owner_local_admission_path_rechecks_every_literal_target(self):
        for effect, target in zip(ORDER, (2775, 2772, 2772, 2776, 2773, 2773, 2777, 2774, 2774)):
            actions = SimpleNamespace(
                _require_owner_or_raise=mock.Mock(),
                _require_github_actor_or_raise=mock.Mock(return_value=SimpleNamespace(login="eanz17", repo_slug="aevatarAI/aevatar")),
                _normalize_lifecycle_target_or_raise=mock.Mock(return_value=str(target)),
                _require_item_write_admission_or_return=mock.Mock(return_value=None),
            )
            with self.subTest(effect=effect):
                ControllerActions._revalidate_issue_2737_effect_admission(actions, effect)
                actions._require_owner_or_raise.assert_called_once_with("recover-issue-2737-partial-decomposition")
                actions._normalize_lifecycle_target_or_raise.assert_called_once_with(target, kind="issue", action="recover-issue-2737-partial-decomposition", source="literal-capability")
                actions._require_item_write_admission_or_return.assert_called_once_with("recover-issue-2737-partial-decomposition", "issue", str(target), current_login="eanz17")

    def test_real_owner_local_admission_path_blocks_actor_and_item_drift(self):
        cases = (
            SimpleNamespace(login="other", repo_slug="aevatarAI/aevatar"),
            SimpleNamespace(login="eanz17", repo_slug="other/repo"),
        )
        for admission in cases:
            actions = SimpleNamespace(_require_owner_or_raise=mock.Mock(), _require_github_actor_or_raise=mock.Mock(return_value=admission))
            with self.subTest(admission=admission), self.assertRaises(RuntimeError):
                ControllerActions._revalidate_issue_2737_effect_admission(actions, ORDER[0])
        actions = SimpleNamespace(
            _require_owner_or_raise=mock.Mock(),
            _require_github_actor_or_raise=mock.Mock(return_value=SimpleNamespace(login="eanz17", repo_slug="aevatarAI/aevatar")),
            _normalize_lifecycle_target_or_raise=mock.Mock(return_value="2775"),
            _require_item_write_admission_or_return=mock.Mock(return_value={"denied": True}),
        )
        with self.assertRaises(RuntimeError):
            ControllerActions._revalidate_issue_2737_effect_admission(actions, ORDER[0])


class SourceBoundaryTests(unittest.TestCase):
    def test_no_occurrence_record_route_receipt_or_parallel_architecture(self):
        root = SCRIPT_DIR.parent
        self.assertFalse((root / "authorizations" / "issue-2737-reselection.json").exists())
        self.assertFalse((SCRIPT_DIR / "codex_refactor_loop" / "issue_2737_evidence.py").exists())
        self.assertFalse((SCRIPT_DIR / "codex_refactor_loop" / "issue_decomposition_recovery.py").exists())
        source = (SCRIPT_DIR / "codex_refactor_loop" / "issue_2737_recovery.py").read_text(encoding="utf-8")
        for forbidden in ("receipt", "ledger", "argparse", "wakeup_plan", "wakeup_runner", "ChronoAIProject/consensus-rnd"):
            self.assertNotIn(forbidden, source.lower() if forbidden.islower() else source)

    def test_repository_wide_incident_residue_has_only_disposable_owners_and_no_route(self):
        skill_root = SCRIPT_DIR.parent
        cleanup_guard = SCRIPT_DIR / "test_issue_2737_cleanup_contract.py"
        cleanup_manifest = SCRIPT_DIR / "fixtures/issue_2737_pr_a_cleanup_contract.json"
        self.assertTrue(cleanup_guard.is_file())
        self.assertTrue(cleanup_manifest.is_file())
        allowed = {
            "SKILL.md",
            "authorizations/runtime-exceptions.md",
            "scripts/codex_refactor_loop/controller_actions.py",
            "scripts/codex_refactor_loop/issue_2737_recovery.py",
            "scripts/test_issue_2737_recovery.py",
            "scripts/test_issue_2737_cleanup_contract.py",
            "scripts/fixtures/issue_2737_pr_a_cleanup_contract.json",
            "scripts/test_skill_reference_anchors.py",
        }
        needles = (
            "issue_2737_recovery", "Issue2737", "issue-2737-reselection",
            "recover_issue_2737", "issue-2737-partial-decomposition-recovery",
        )
        residue = set()
        for path in skill_root.rglob("*"):
            if not path.is_file() or path.suffix not in (".py", ".md", ".json"):
                continue
            text = path.read_text(encoding="utf-8")
            if any(needle in text for needle in needles):
                residue.add(path.relative_to(skill_root).as_posix())
        self.assertEqual(allowed, residue)
        for route_owner in (
            "scripts/codex_refactor_loop/cli.py",
            "scripts/codex_refactor_loop/wakeup_plan.py",
            "scripts/codex_refactor_loop/wakeup_runner.py",
            "scripts/codex_refactor_loop/runtime_copy.py",
        ):
            text = (skill_root / route_owner).read_text(encoding="utf-8")
            self.assertFalse(any(needle in text for needle in needles), route_owner)
        controller = (skill_root / "scripts/codex_refactor_loop/controller_actions.py").read_text(encoding="utf-8")
        self.assertEqual(1, controller.count("def recover_issue_2737_partial_decomposition"))


if __name__ == "__main__":
    unittest.main()
