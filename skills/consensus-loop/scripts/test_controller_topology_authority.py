#!/usr/bin/env python3
"""Behavior and source-boundary tests for ControllerTopologyAuthority."""
from __future__ import annotations

import tempfile
import unittest
import json
from dataclasses import replace
from datetime import date
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from codex_refactor_loop.controller_topology_authority import (
    ControllerTopologyAuthority, ControllerTopologyError, ControllerTopologyIdentity,
    CreateCompliantWorktreeRequest, PRState, PublicationSnapshot, PublishExactHeadRequest,
    ReceiptState, RetirementSnapshot, RetireSupersededPRRequest, ReviewGateProjection,
    SUPERSESSION_SENTINEL, TopologyPhase, WorktreeState,
    TopologyProvenance, controller_topology_branch_is_durable, read_controller_topology_identity,
    parse_legacy_implementation_head_evidence,
)

BASE = "b" * 40
F = "f" * 40
TREE = "a" * 40
DIFF = "d" * 64


class FakePort:
    def __init__(self, root: Path) -> None:
        self.repo_root = root
        self._topology_repository = "owner/repo"
        self.records = {}
        self.calls = []
        self.deny_at: int | None = None
        self.deny_boundary: str | None = None
        self.denial_reason = "not-owner"
        self.fresh_count = 0
        self.cas_race = False
        self.branch = "refactor/2026-07-15_controller-topology"
        self.worktree = WorktreeState(BASE, None, None, False, None, None, False, False, ())
        self.receipt = ReceiptState("receipt-1", "VERIFIED", 2737, "dev", self.branch, F, None)
        self.prs = ()
        self.old_state = "OPEN"
        self.sentinels = ()
        self.review = ReviewGateProjection("MERGE_WITH_COMMENTS", 11, F, "review-digest")
        self.fail_close = False
        self.fail_effect = ""
        self.publication_override = None
        self.retirement_override = None

    def _topology_require_fresh_owner(self, action):
        self.fresh_count += 1
        self.calls.append("fresh:" + action)
        if self.deny_at == self.fresh_count or (self.deny_boundary and self.deny_boundary in action):
            raise RuntimeError(f"active-controller lease denied: {self.denial_reason}")

    def _topology_read_provenance(self, key):
        self.calls.append("read-record")
        return self.records.get(key)

    def _topology_cas_provenance(self, key, generation, digest, value):
        self.calls.append("CAS:" + value.phase.value)
        current = self.records.get(key)
        if self.cas_race:
            self.cas_race = False
            raise RuntimeError("CAS conflict")
        expected = None if generation is None else (generation, digest)
        actual = None if current is None else (current.generation, current.digest)
        if expected != actual:
            raise RuntimeError("CAS conflict")
        self.records[key] = value

    def _topology_read_worktree(self, branch, path, base_ref, remote):
        self.calls.append("read-worktree")
        return self.worktree

    def _topology_create_worktree(self, branch, path, base_sha):
        self.calls.append("EFFECT:create")
        # Models the actual single worktree add -b effect.
        self.worktree = WorktreeState(BASE, BASE, None, True, branch, BASE, True, False, ())

    def _topology_attach_worktree(self, branch, path):
        self.calls.append("EFFECT:attach")
        self.worktree = replace(self.worktree, worktree_registered=True, worktree_branch=branch,
                                worktree_head_sha=BASE, worktree_clean=True)

    def _topology_read_publication(self, request, path):
        self.calls.append("read-publication")
        legacy = PRState(9, "OPEN", True, "dev", "refactor/iter2737-issue-2737", F, TREE,
                         "", "", DIFF, (2737,))
        snapshot = PublicationSnapshot(self.worktree, True, TREE, DIFF, self.worktree.local_ref_sha,
                                       self.worktree.remote_ref_sha, self.prs, legacy, "OPEN", self.receipt)
        return self.publication_override(snapshot) if self.publication_override else snapshot

    def _topology_create_local_ref(self, branch, sha):
        self.calls.append("EFFECT:local")
        if self.fail_effect == "local": raise RuntimeError("local effect failed")
        self.worktree = replace(self.worktree, local_ref_sha=sha, worktree_head_sha=sha)

    def _topology_push_exact_ref(self, remote, branch, sha):
        self.calls.append("EFFECT:push")
        if self.fail_effect == "push": raise RuntimeError("push effect failed")
        if remote != "origin": raise AssertionError("configured remote changed")
        self.worktree = replace(self.worktree, remote_ref_sha=sha)

    def _topology_create_or_update_pr(self, request, existing):
        self.calls.append("EFFECT:pr")
        if self.fail_effect == "pr": raise RuntimeError("PR effect failed")
        self.prs = (PRState(11, "OPEN", True, "dev", request.identity.branch, F, TREE,
                           request.title_digest, request.body_digest, DIFF, (2737,)),)
        return 11

    def _topology_finalize_receipt(self, receipt_id, pr_number):
        self.calls.append("EFFECT:receipt")
        if self.fail_effect == "receipt": raise RuntimeError("receipt effect failed")
        self.receipt = replace(self.receipt, status="PUBLISHED", pr_number=pr_number)

    def _topology_read_retirement(self, request, digest):
        self.calls.append("read-retirement")
        old = PRState(10, self.old_state, True, "dev", "legacy", F, TREE, "", "", "same", (2737,))
        new = replace(old, number=11, state="OPEN", head_branch=self.branch)
        snapshot = RetirementSnapshot(old, new, "OPEN", self.review, self.sentinels)
        return self.retirement_override(snapshot) if self.retirement_override else snapshot

    def _topology_post_supersession(self, request, sentinel_digest):
        self.calls.append("EFFECT:comment")
        if self.fail_effect == "comment": raise RuntimeError("comment effect failed")
        self.sentinels = ("https://github.com/owner/repo/pull/10#issuecomment-1",)
        return self.sentinels[0]

    def _topology_close_old_pr(self, old):
        self.calls.append("EFFECT:close")
        if self.fail_close:
            raise RuntimeError("close failed")
        self.old_state = "CLOSED"


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.port = FakePort(Path(self.temp.name))
        self.owner = ControllerTopologyAuthority(self.port)
        self.identity = ControllerTopologyIdentity(2737, "controller-topology", "refactor", date(2026, 7, 15))
        self.create = CreateCompliantWorktreeRequest(self.identity, "origin/dev", BASE)
        self.publish = PublishExactHeadRequest(self.identity, F, "origin", "dev", 9, "receipt-1", "title", "body")
        self.body = Path(self.temp.name) / "supersession.md"
        self.body.write_text(f"{SUPERSESSION_SENTINEL}\nReplacement: #11\n", encoding="utf-8")
        self.retire = RetireSupersededPRRequest(10, 11, 2737, F, "dev", self.port.review, self.body)

    def tearDown(self):
        self.temp.cleanup()

    def _created(self):
        result = self.owner.create_compliant_worktree(self.create)
        self.port.worktree = replace(self.port.worktree, local_ref_sha=F, worktree_head_sha=F)
        return result

    def _assert_denial_matrix(self, invoke, boundary, prior_phase, forbidden_effects):
        for reason in ("not-owner", "expired", "owner-change", "invalid-evidence",
                       "ambiguous-evidence", "remote-read-failure", "lease-cas-conflict"):
            with self.subTest(boundary=boundary, reason=reason):
                self.port.calls.clear()
                self.port.deny_boundary = boundary
                self.port.denial_reason = reason
                with self.assertRaisesRegex(RuntimeError, reason):
                    invoke()
                record = next(record for record in self.port.records.values() if record.phase is prior_phase)
                self.assertEqual(prior_phase, record.phase)
                denied = next(i for i, call in enumerate(self.port.calls)
                              if call.startswith("fresh:") and boundary in call)
                self.assertFalse(any(call.startswith("CAS:") or call in forbidden_effects
                                     for call in self.port.calls[denied + 1:]))
        self.port.deny_boundary = None

    def test_complete_create_uses_locked_phases_and_one_create_effect(self):
        result = self.owner.create_compliant_worktree(self.create)
        self.assertEqual(TopologyPhase.WORKTREE_CREATED, result.phase)
        self.assertEqual(1, self.port.calls.count("EFFECT:create"))
        self.assertNotIn("EFFECT:attach", self.port.calls)
        record = self.port.records[f"publication:{self.identity.branch}"]
        self.assertEqual(2, record.generation)
        self.assertEqual(record, record.exact())

    def test_branch_only_partial_state_is_exactly_adopted_without_recreate(self):
        self.port.deny_at = 2
        with self.assertRaises(RuntimeError):
            self.owner.create_compliant_worktree(self.create)
        self.port.deny_at = None
        self.port.worktree = replace(self.port.worktree, local_ref_sha=BASE)
        result = self.owner.create_compliant_worktree(self.create)
        self.assertEqual(TopologyPhase.WORKTREE_CREATED, result.phase)
        self.assertEqual(1, self.port.calls.count("EFFECT:attach"))
        self.assertNotIn("EFFECT:create", self.port.calls)

    def test_create_collisions_are_zero_effect(self):
        variants = [replace(self.port.worktree, local_ref_sha="e" * 40),
                    replace(self.port.worktree, remote_ref_sha=BASE),
                    replace(self.port.worktree, foreign_attachment=True),
                    replace(self.port.worktree, open_pr_numbers=(7,))]
        for state in variants:
            with self.subTest(state=state):
                port = FakePort(Path(self.temp.name)); port.worktree = state
                with self.assertRaises(ControllerTopologyError):
                    ControllerTopologyAuthority(port).create_compliant_worktree(self.create)
                self.assertFalse(any(c.startswith("EFFECT:") for c in port.calls))

    def test_fresh_denial_before_prepare_or_effect_is_zero_effect(self):
        for boundary in (1, 2):
            with self.subTest(boundary=boundary):
                port = FakePort(Path(self.temp.name)); port.deny_at = boundary
                with self.assertRaises(RuntimeError):
                    ControllerTopologyAuthority(port).create_compliant_worktree(self.create)
                effects = [c for c in port.calls if c.startswith("EFFECT:")]
                self.assertEqual([] if boundary == 1 else [], effects)

    def test_loss_after_create_effect_blocks_phase_cas_then_exact_retry_adopts(self):
        self.port.deny_at = 3
        with self.assertRaises(RuntimeError):
            self.owner.create_compliant_worktree(self.create)
        self.assertEqual(TopologyPhase.CREATE_PREPARED, next(iter(self.port.records.values())).phase)
        self.port.deny_at = None
        result = self.owner.create_compliant_worktree(self.create)
        self.assertEqual(TopologyPhase.WORKTREE_CREATED, result.phase)
        self.assertEqual(1, self.port.calls.count("EFFECT:create"))

    def test_create_revalidates_remote_and_open_pr_collisions_at_every_boundary(self):
        collision_rows = (
            ("remote", {"remote_ref_sha": BASE}),
            ("open-pr", {"open_pr_numbers": (77,)}),
        )
        for label, fields in collision_rows:
            with self.subTest(boundary="after-prepare", collision=label):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                port.deny_at = 2
                with self.assertRaises(RuntimeError): owner.create_compliant_worktree(self.create)
                port.deny_at = None
                port.worktree = replace(port.worktree, **fields)
                before = len(port.calls)
                with self.assertRaises(ControllerTopologyError): owner.create_compliant_worktree(self.create)
                self.assertEqual(TopologyPhase.CREATE_PREPARED, next(iter(port.records.values())).phase)
                self.assertFalse(any(call.startswith("EFFECT:") or call.startswith("CAS:") for call in port.calls[before:]))
                port.worktree = replace(port.worktree, remote_ref_sha=None, open_pr_numbers=())
                self.assertEqual(TopologyPhase.WORKTREE_CREATED, owner.create_compliant_worktree(self.create).phase)

            with self.subTest(boundary="after-effect", collision=label):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                original = port._topology_create_worktree
                def create_then_collide(branch, path, sha, original=original, fields=fields):
                    original(branch, path, sha)
                    port.worktree = replace(port.worktree, **fields)
                port._topology_create_worktree = create_then_collide
                with self.assertRaises(ControllerTopologyError): owner.create_compliant_worktree(self.create)
                self.assertEqual(TopologyPhase.CREATE_PREPARED, next(iter(port.records.values())).phase)
                self.assertNotIn("CAS:WORKTREE_CREATED", port.calls)
                port.worktree = replace(port.worktree, remote_ref_sha=None, open_pr_numbers=())
                self.assertEqual(TopologyPhase.WORKTREE_CREATED, owner.create_compliant_worktree(self.create).phase)
                self.assertEqual(1, port.calls.count("EFFECT:create"))

            with self.subTest(boundary="terminal", collision=label):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, **fields)
                before = len(port.calls)
                with self.assertRaises(ControllerTopologyError): owner.create_compliant_worktree(self.create)
                self.assertFalse(any(call.startswith("EFFECT:") or call.startswith("CAS:") for call in port.calls[before:]))
                port.worktree = replace(port.worktree, remote_ref_sha=None, open_pr_numbers=())
                self.assertEqual(TopologyPhase.WORKTREE_CREATED, owner.create_compliant_worktree(self.create).phase)

    def test_publication_membership_rejects_external_symlink_and_non_regular_entries(self):
        root = Path(self.temp.name)
        branch = self.identity.branch
        worktree = root / ".worktrees" / branch.replace("/", "__")
        record = TopologyProvenance(
            f"publication:{branch}", TopologyPhase.WORKTREE_CREATED, 2, "", 2737,
            "controller-topology", "refactor", "2026-07-15", branch, str(worktree),
            "origin/dev", BASE,
        ).exact()
        state = root / ".refactor-loop" / "state" / "controller-topology"
        state.mkdir(parents=True)
        name = f"publication__{branch.replace('/', '__')}.json"
        outside = root / "outside.json"
        outside.write_text(json.dumps({**record.payload(), "digest": record.digest}), encoding="utf-8")
        (state / name).symlink_to(outside)
        for reader in (lambda: read_controller_topology_identity(root, 2737),
                       lambda: controller_topology_branch_is_durable(root, branch)):
            with self.assertRaisesRegex(ControllerTopologyError, "regular file"):
                reader()
        (state / name).unlink()
        (state / name).mkdir()
        with self.assertRaisesRegex(ControllerTopologyError, "regular file"):
            controller_topology_branch_is_durable(root, branch)

    def test_publish_runs_exact_locked_sequence_and_receipt_precedes_return(self):
        self._created()
        result = self.owner.publish_exact_head(self.publish)
        self.assertEqual(TopologyPhase.PUBLICATION_RECEIPT_FINALIZED, result.phase)
        phases = [c for c in self.port.calls if c.startswith("CAS:")]
        self.assertEqual(["CAS:CREATE_PREPARED", "CAS:WORKTREE_CREATED", "CAS:PUBLISH_PREPARED",
                          "CAS:LOCAL_REF_READY", "CAS:REMOTE_REF_PUBLISHED", "CAS:PR_FINALIZED",
                          "CAS:PUBLICATION_RECEIPT_FINALIZED"], phases)
        self.assertLess(self.port.calls.index("EFFECT:receipt"),
                        self.port.calls.index("CAS:PUBLICATION_RECEIPT_FINALIZED"))

    def test_publish_exact_noop_adoption_still_requires_fresh_before_cas(self):
        self._created()
        self.port.prs = (PRState(11, "OPEN", True, "dev", self.identity.branch, F, TREE,
                                "title", "body", DIFF, (2737,)),)
        self.port.worktree = replace(self.port.worktree, remote_ref_sha=F)
        result = self.owner.publish_exact_head(self.publish)
        self.assertEqual(TopologyPhase.PUBLICATION_RECEIPT_FINALIZED, result.phase)
        self.assertNotIn("EFFECT:local", self.port.calls)
        self.assertNotIn("EFFECT:push", self.port.calls)
        self.assertNotIn("EFFECT:pr", self.port.calls)
        self.assertGreaterEqual(sum(c.startswith("fresh:") for c in self.port.calls), 7)

    def test_every_effect_and_cas_has_immediately_preceding_fresh_gate(self):
        self._created()
        self.owner.publish_exact_head(self.publish)
        self.owner.retire_superseded_pr(self.retire)
        for index, call in enumerate(self.port.calls):
            if call.startswith("EFFECT:") or call.startswith("CAS:"):
                with self.subTest(call=call, index=index):
                    self.assertGreater(index, 0)
                    self.assertTrue(self.port.calls[index - 1].startswith("fresh:"), self.port.calls[max(0, index - 3):index + 1])
            if call.startswith("CAS:") and call not in {"CAS:CREATE_PREPARED", "CAS:RETIREMENT_PREPARED"}:
                self.assertEqual("read-record", self.port.calls[index - 2])

    def test_all_six_exact_adoptions_fail_closed_for_full_lease_denial_matrix(self):
        self.port.deny_boundary = "created phase CAS"
        with self.assertRaises(RuntimeError):
            self.owner.create_compliant_worktree(self.create)
        self.port.deny_boundary = None
        self._assert_denial_matrix(
            lambda: self.owner.create_compliant_worktree(self.create), "created phase CAS",
            TopologyPhase.CREATE_PREPARED, {"EFFECT:create", "EFFECT:attach"},
        )
        self.owner.create_compliant_worktree(self.create)
        self.port.worktree = replace(self.port.worktree, local_ref_sha=F, worktree_head_sha=F)

        publication_cases = (
            ("local ref phase CAS", TopologyPhase.PUBLISH_PREPARED,
             {"EFFECT:push", "EFFECT:pr", "EFFECT:receipt"}),
            ("remote ref phase CAS", TopologyPhase.LOCAL_REF_READY,
             {"EFFECT:pr", "EFFECT:receipt"}),
            ("replacement PR phase CAS", TopologyPhase.REMOTE_REF_PUBLISHED,
             {"EFFECT:receipt"}),
        )
        for boundary, phase, later_effects in publication_cases:
            self.port.deny_boundary = boundary
            with self.assertRaises(RuntimeError):
                self.owner.publish_exact_head(self.publish)
            self.port.deny_boundary = None
            self._assert_denial_matrix(lambda: self.owner.publish_exact_head(self.publish), boundary, phase, later_effects)

        self.port.deny_boundary = "supersession phase CAS"
        with self.assertRaises(RuntimeError):
            self.owner.retire_superseded_pr(self.retire)
        self.port.deny_boundary = None
        self._assert_denial_matrix(
            lambda: self.owner.retire_superseded_pr(self.retire), "supersession phase CAS",
            TopologyPhase.RETIREMENT_PREPARED, {"EFFECT:close"},
        )
        self.port.deny_boundary = "old close terminal CAS"
        with self.assertRaises(RuntimeError):
            self.owner.retire_superseded_pr(self.retire)
        self.port.deny_boundary = None
        self._assert_denial_matrix(
            lambda: self.owner.retire_superseded_pr(self.retire), "old close terminal CAS",
            TopologyPhase.SUPERSESSION_POSTED, set(),
        )

    def test_local_and_remote_collisions_fail_closed(self):
        for field in ("local_ref_sha", "remote_ref_sha"):
            with self.subTest(field=field):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=F, worktree_head_sha=F,
                                        **({field: "e" * 40} if field != "local_ref_sha" else {}))
                if field == "local_ref_sha":
                    port.worktree = replace(port.worktree, local_ref_sha="e" * 40, worktree_head_sha=F)
                with self.assertRaises(ControllerTopologyError): owner.publish_exact_head(self.publish)

    def test_publication_wrong_fact_matrix_is_zero_effect(self):
        def mutations(snapshot):
            bad_pr = PRState(11, "OPEN", True, "dev", self.identity.branch, F, TREE,
                             "title", "body", DIFF, (2737,))
            return {
                "missing-commit": replace(snapshot, commit_exists=False),
                "missing-tree": replace(snapshot, final_tree_sha=""),
                "dirty-worktree": replace(snapshot, worktree=replace(snapshot.worktree, worktree_clean=False)),
                "wrong-head": replace(snapshot, worktree=replace(snapshot.worktree, worktree_head_sha="e" * 40)),
                "legacy-number": replace(snapshot, legacy_pr=replace(snapshot.legacy_pr, number=8)),
                "legacy-head": replace(snapshot, legacy_pr=replace(snapshot.legacy_pr, head_sha="e" * 40)),
                "legacy-base": replace(snapshot, legacy_pr=replace(snapshot.legacy_pr, base_branch="main")),
                "closed-issue": replace(snapshot, linked_issue_state="CLOSED"),
                "duplicate-pr": replace(snapshot, canonical_prs=(bad_pr, bad_pr)),
                "pr-head": replace(snapshot, canonical_prs=(replace(bad_pr, head_sha="e" * 40),)),
                "pr-tree": replace(snapshot, canonical_prs=(replace(bad_pr, head_tree_sha="e" * 40),)),
                "pr-base": replace(snapshot, canonical_prs=(replace(bad_pr, base_branch="main"),)),
                "pr-issue": replace(snapshot, canonical_prs=(replace(bad_pr, closing_issue_numbers=(1,)),)),
            }
        for label, mutate in mutations(self.port._topology_read_publication(self.publish, Path("."))).items():
            with self.subTest(row=label):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=F, worktree_head_sha=F)
                port.worktree = replace(port.worktree, remote_ref_sha=F)
                if label in {"dirty-worktree", "wrong-head"}:
                    port.publication_override = lambda snapshot, bad=mutate: replace(
                        bad, local_ref_sha=snapshot.local_ref_sha, remote_ref_sha=snapshot.remote_ref_sha,
                        receipt=snapshot.receipt)
                else:
                    port.publication_override = lambda snapshot, bad=mutate: replace(
                        bad, worktree=snapshot.worktree, local_ref_sha=snapshot.local_ref_sha,
                        remote_ref_sha=snapshot.remote_ref_sha, receipt=snapshot.receipt)
                before = len(port.calls)
                with self.assertRaises(ControllerTopologyError): owner.publish_exact_head(self.publish)
                self.assertFalse(any(call.startswith("EFFECT:") for call in port.calls[before:]))

    def test_effect_failure_and_loss_after_effect_matrix_replays_idempotently(self):
        boundaries = (
            ("local", "local ref phase CAS", TopologyPhase.PUBLISH_PREPARED, "EFFECT:local"),
            ("push", "remote ref phase CAS", TopologyPhase.LOCAL_REF_READY, "EFFECT:push"),
            ("pr", "replacement PR phase CAS", TopologyPhase.REMOTE_REF_PUBLISHED, "EFFECT:pr"),
            ("receipt", "publication terminal CAS", TopologyPhase.PR_FINALIZED, "EFFECT:receipt"),
        )
        for effect, cas, phase, call in boundaries:
            with self.subTest(effect=effect, failure="effect"):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=None, worktree_head_sha=F)
                port.fail_effect = effect
                with self.assertRaises(RuntimeError): owner.publish_exact_head(self.publish)
                self.assertEqual(phase, port.records[f"publication:{self.identity.branch}"].phase)
            with self.subTest(effect=effect, failure="owner-after-effect"):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=None, worktree_head_sha=F)
                port.deny_boundary = cas
                with self.assertRaises(RuntimeError): owner.publish_exact_head(self.publish)
                self.assertEqual(phase, port.records[f"publication:{self.identity.branch}"].phase)
                port.deny_boundary = None
                owner.publish_exact_head(self.publish)
                self.assertEqual(1, port.calls.count(call))

    def test_receipt_identity_and_terminal_cas_races_block_review_boundary(self):
        receipt_rows = {
            "id": replace(self.port.receipt, receipt_id="other"),
            "status": replace(self.port.receipt, status="PUBLISHED"),
            "issue": replace(self.port.receipt, issue_number=1),
            "base": replace(self.port.receipt, base_branch="main"),
            "head": replace(self.port.receipt, head_branch="other"),
            "sha": replace(self.port.receipt, final_sha="e" * 40),
            "premature-pr": replace(self.port.receipt, pr_number=11),
        }
        for label, receipt in receipt_rows.items():
            with self.subTest(row=label):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=F, worktree_head_sha=F)
                port.receipt = receipt
                with self.assertRaises(ControllerTopologyError): owner.publish_exact_head(self.publish)
                self.assertNotIn("EFFECT:receipt", port.calls)

    def test_phase_cas_race_suppresses_every_later_effect(self):
        cases = (
            ("create", TopologyPhase.CREATE_PREPARED, {"EFFECT:create", "EFFECT:attach"}),
            ("publish", TopologyPhase.PUBLISH_PREPARED, {"EFFECT:push", "EFFECT:pr", "EFFECT:receipt"}),
            ("retire", TopologyPhase.RETIREMENT_PREPARED, {"EFFECT:close"}),
        )
        for transaction, prior, forbidden in cases:
            with self.subTest(transaction=transaction):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                if transaction == "create":
                    port.deny_boundary = "created phase CAS"
                    with self.assertRaises(RuntimeError): owner.create_compliant_worktree(self.create)
                    port.deny_boundary = None; port.cas_race = True
                    invoke = lambda: owner.create_compliant_worktree(self.create)
                elif transaction == "publish":
                    owner.create_compliant_worktree(self.create)
                    port.worktree = replace(port.worktree, local_ref_sha=F, worktree_head_sha=F)
                    port.deny_boundary = "local ref phase CAS"
                    with self.assertRaises(RuntimeError): owner.publish_exact_head(self.publish)
                    port.deny_boundary = None; port.cas_race = True
                    invoke = lambda: owner.publish_exact_head(self.publish)
                else:
                    port.deny_boundary = "supersession phase CAS"
                    request = replace(self.retire, review=port.review)
                    with self.assertRaises(RuntimeError): owner.retire_superseded_pr(request)
                    port.deny_boundary = None; port.cas_race = True
                    invoke = lambda: owner.retire_superseded_pr(request)
                before = len(port.calls)
                with self.assertRaisesRegex(RuntimeError, "CAS conflict"): invoke()
                self.assertEqual(prior, next(r.phase for r in port.records.values() if r.phase is prior))
                self.assertFalse(forbidden.intersection(port.calls[before:]))

    def test_remote_postproof_and_receipt_postproof_failures_stop_at_durable_phase(self):
        for effect, phase in (("push", TopologyPhase.LOCAL_REF_READY),
                              ("receipt", TopologyPhase.PR_FINALIZED)):
            with self.subTest(effect=effect):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                owner.create_compliant_worktree(self.create)
                port.worktree = replace(port.worktree, local_ref_sha=F, worktree_head_sha=F)
                if effect == "push":
                    original = port._topology_push_exact_ref
                    port._topology_push_exact_ref = lambda remote, branch, sha: port.calls.append("EFFECT:push")
                else:
                    original = port._topology_finalize_receipt
                    port._topology_finalize_receipt = lambda receipt, pr: port.calls.append("EFFECT:receipt")
                with self.assertRaises(ControllerTopologyError): owner.publish_exact_head(self.publish)
                self.assertEqual(phase, port.records[f"publication:{self.identity.branch}"].phase)

    def test_loss_after_retirement_effect_replays_without_duplicate_effect(self):
        for boundary, effect, prior in (("supersession phase CAS", "EFFECT:comment", TopologyPhase.RETIREMENT_PREPARED),
                                        ("old close terminal CAS", "EFFECT:close", TopologyPhase.SUPERSESSION_POSTED)):
            with self.subTest(boundary=boundary):
                port = FakePort(Path(self.temp.name)); owner = ControllerTopologyAuthority(port)
                request = replace(self.retire, review=port.review)
                port.deny_boundary = boundary
                with self.assertRaises(RuntimeError): owner.retire_superseded_pr(request)
                self.assertEqual(prior, next(r.phase for r in port.records.values() if r.phase is prior))
                port.deny_boundary = None
                self.assertEqual(TopologyPhase.OLD_PR_CLOSED, owner.retire_superseded_pr(request).phase)
                self.assertEqual(1, port.calls.count(effect))

    def test_retirement_wrong_fact_and_reentry_matrix_is_zero_effect(self):
        rows = {
            "old-number": lambda s: replace(s, old=replace(s.old, number=9)),
            "replacement-number": lambda s: replace(s, replacement=replace(s.replacement, number=12)),
            "replacement-closed": lambda s: replace(s, replacement=replace(s.replacement, state="CLOSED")),
            "issue-closed": lambda s: replace(s, linked_issue_state="CLOSED"),
            "base": lambda s: replace(s, replacement=replace(s.replacement, base_branch="main")),
            "closing": lambda s: replace(s, old=replace(s.old, closing_issue_numbers=(1,))),
            "head": lambda s: replace(s, replacement=replace(s.replacement, head_sha="e" * 40)),
            "tree": lambda s: replace(s, replacement=replace(s.replacement, head_tree_sha="e" * 40)),
            "diff": lambda s: replace(s, replacement=replace(s.replacement, diff_digest="other")),
            "review": lambda s: replace(s, review=replace(s.review, decision="WAIT")),
            "duplicate-sentinel": lambda s: replace(s, sentinel_urls=("one", "two")),
        }
        for label, mutate in rows.items():
            with self.subTest(row=label):
                port = FakePort(Path(self.temp.name)); port.retirement_override = mutate
                with self.assertRaises(ControllerTopologyError):
                    ControllerTopologyAuthority(port).retire_superseded_pr(
                        replace(self.retire, review=port.review))
                self.assertFalse(any(call.startswith("EFFECT:") for call in port.calls))

    def test_retirement_comment_failure_boundary_and_terminal_reentry(self):
        result = self.owner.retire_superseded_pr(self.retire)
        self.assertEqual(TopologyPhase.OLD_PR_CLOSED, result.phase)
        self.assertEqual(["EFFECT:comment", "EFFECT:close"], [c for c in self.port.calls if c.startswith("EFFECT:")])
        self.port.calls.clear()
        result = self.owner.retire_superseded_pr(self.retire)
        self.assertEqual(TopologyPhase.OLD_PR_CLOSED, result.phase)
        self.assertFalse(any(c.startswith("EFFECT:") for c in self.port.calls))
        self.port.sentinels = ()
        with self.assertRaisesRegex(ControllerTopologyError, "uniquely rediscoverable"):
            self.owner.retire_superseded_pr(self.retire)

    def test_retirement_rejects_empty_or_invalid_live_and_stored_sentinel_urls(self):
        invalid_urls = (
            "", "https://example.invalid/comment/1", "https://github.com/owner/repo/pull/10",
            "https://github.com/foreign/repository/pull/10#issuecomment-1",
            "https://github.com/owner/repo/pull/99#issuecomment-1",
            "https://github.com/owner/repo/issues/10#issuecomment-1",
        )
        for value in invalid_urls:
            with self.subTest(value=value):
                port = FakePort(Path(self.temp.name))
                port.sentinels = (value,)
                with self.assertRaisesRegex(ControllerTopologyError, "URL is missing or invalid"):
                    ControllerTopologyAuthority(port).retire_superseded_pr(replace(self.retire, review=port.review))
                self.assertNotIn("EFFECT:close", port.calls)

        self.owner.retire_superseded_pr(self.retire)
        record = next(iter(self.port.records.values()))
        for value in invalid_urls:
            with self.subTest(stored=value):
                invalid = replace(record, sentinel_url=value, digest="").exact()
                self.port.records[invalid.key] = invalid
                self.port.calls.clear()
                with self.assertRaisesRegex(ControllerTopologyError, "URL is missing or invalid"):
                    self.owner.retire_superseded_pr(self.retire)
                self.assertFalse(any(call.startswith("EFFECT:") for call in self.port.calls))

    def test_retirement_rejects_foreign_live_sentinel_at_every_transaction_phase(self):
        invalid_urls = (
            "https://github.com/foreign/repository/pull/10#issuecomment-1",
            "https://github.com/owner/repo/pull/99#issuecomment-1",
            "https://github.com/owner/repo/issues/10#issuecomment-1",
        )
        for stage in ("adoption", "close", "close-failure-retry", "terminal-reentry"):
            for value in invalid_urls:
                with self.subTest(stage=stage, value=value):
                    port = FakePort(Path(self.temp.name))
                    owner = ControllerTopologyAuthority(port)
                    request = replace(self.retire, review=port.review)
                    if stage == "adoption":
                        port.deny_boundary = "supersession phase CAS"
                    elif stage == "close":
                        port.deny_boundary = "old PR close effect"
                    elif stage == "close-failure-retry":
                        port.fail_close = True
                    try:
                        owner.retire_superseded_pr(request)
                    except RuntimeError as error:
                        expected = {
                            "adoption": "active-controller lease denied: not-owner",
                            "close": "active-controller lease denied: not-owner",
                            "close-failure-retry": "close failed",
                        }.get(stage)
                        if str(error) != expected:
                            raise
                    port.deny_boundary = None
                    port.fail_close = False
                    port.sentinels = (value,)
                    port.calls.clear()
                    with self.assertRaisesRegex(ControllerTopologyError, "URL is missing or invalid"):
                        owner.retire_superseded_pr(request)
                    self.assertFalse(any(call.startswith("EFFECT:") for call in port.calls))

    def test_canonical_sentinel_adopts_and_retries_without_duplicate_post(self):
        canonical = "https://github.com/owner/repo/pull/10#issuecomment-7"
        for stage in ("adoption", "close", "close-failure-retry", "terminal-reentry"):
            with self.subTest(stage=stage):
                port = FakePort(Path(self.temp.name))
                owner = ControllerTopologyAuthority(port)
                request = replace(self.retire, review=port.review)
                if stage == "adoption":
                    port.sentinels = (canonical,)
                elif stage == "close":
                    port.deny_boundary = "old PR close effect"
                elif stage == "close-failure-retry":
                    port.fail_close = True
                try:
                    owner.retire_superseded_pr(request)
                except RuntimeError as error:
                    expected = {
                        "close": "active-controller lease denied: not-owner",
                        "close-failure-retry": "close failed",
                    }.get(stage)
                    if str(error) != expected:
                        raise
                port.deny_boundary = None
                port.fail_close = False
                port.calls.clear()
                result = owner.retire_superseded_pr(request)
                self.assertEqual(TopologyPhase.OLD_PR_CLOSED, result.phase)
                self.assertNotIn("EFFECT:comment", port.calls)

    def test_zero_sentinel_after_claimed_post_cannot_advance_or_close(self):
        original = self.port._topology_post_supersession
        self.port._topology_post_supersession = lambda request, digest: self.port.calls.append("EFFECT:comment")
        with self.assertRaisesRegex(ControllerTopologyError, "postproof failed"):
            self.owner.retire_superseded_pr(self.retire)
        self.assertEqual(TopologyPhase.RETIREMENT_PREPARED, next(iter(self.port.records.values())).phase)
        self.assertNotIn("EFFECT:close", self.port.calls)
        self.port._topology_post_supersession = original

    def test_publication_terminal_reentry_reproves_live_diff_without_effect_or_cas(self):
        self._created()
        self.owner.publish_exact_head(self.publish)
        self.port.calls.clear()
        self.port.publication_override = lambda snapshot: replace(snapshot, final_diff_digest="e" * 64)
        with self.assertRaises(ControllerTopologyError):
            self.owner.publish_exact_head(self.publish)
        self.assertFalse(any(call.startswith("EFFECT:") or call.startswith("CAS:") for call in self.port.calls))

    def test_sentinel_success_close_failure_retries_only_close(self):
        self.port.fail_close = True
        with self.assertRaises(RuntimeError): self.owner.retire_superseded_pr(self.retire)
        self.assertEqual(TopologyPhase.SUPERSESSION_POSTED, next(iter(self.port.records.values())).phase)
        self.port.fail_close = False; self.port.calls.clear()
        result = self.owner.retire_superseded_pr(self.retire)
        self.assertEqual(TopologyPhase.OLD_PR_CLOSED, result.phase)
        self.assertNotIn("EFFECT:comment", self.port.calls)
        self.assertIn("EFFECT:close", self.port.calls)

    def test_replacement_merged_and_non_merge_review_are_zero_effect(self):
        bad = replace(self.port.review, decision="MERGE")
        self.port.review = bad
        request = replace(self.retire, review=replace(bad, decision="WAIT"))
        with self.assertRaises(ControllerTopologyError): self.owner.retire_superseded_pr(request)
        self.assertFalse(any(c.startswith("EFFECT:") for c in self.port.calls))

    def test_sole_legacy_parser_is_read_only(self):
        parsed = parse_legacy_implementation_head_evidence("refactor/iter2737-issue-2737")
        self.assertEqual(2737, parsed.issue_number)
        self.assertIsNone(parse_legacy_implementation_head_evidence(self.identity.branch))

    def test_source_boundary_has_no_git_legacy_writers_or_public_partial_port(self):
        production = HERE / "codex_refactor_loop"
        git_source = (production / "git.py").read_text(encoding="utf-8")
        self.assertNotIn("def safe_worktree", git_source)
        self.assertNotIn("def fresh_safe_worktree", git_source)
        authority = (production / "controller_topology_authority.py").read_text(encoding="utf-8")
        self.assertNotIn("class ControllerTopologyEffects", authority)
        actions = (production / "controller_actions.py").read_text(encoding="utf-8")
        self.assertNotRegex(actions, r"\n    def topology_")
        runner = (production / "wakeup_runner.py").read_text(encoding="utf-8")
        lifecycle = (production / "implement_lifecycle.py").read_text(encoding="utf-8")
        plan = (production / "wakeup_plan.py").read_text(encoding="utf-8")
        combined = "\n".join((authority, actions, runner, lifecycle, plan))
        for forbidden in (
            "def _write_branch_provenance",
            "def _backfill_legacy_branch_provenance",
            "def _validate_publish_implementation_identity",
            "def _managed_pr_head_ref",
            "MANAGED_PR_HEAD_RE",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertEqual(1, combined.count("def parse_legacy_implementation_head_evidence"))
        self.assertIn(".create_compliant_worktree(", actions)
        self.assertIn(".publish_exact_head(", actions)
        self.assertIn(".retire_superseded_pr(", actions)
        self.assertLess(actions.index("publish_exact_head("), actions.index("return self.dispatch_reviewers"))
        self.assertLess(runner.index("_retire_superseded_pr("), runner.index("merge_rc = self.actions.merge_pr"))


if __name__ == "__main__":
    unittest.main()
