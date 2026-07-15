"""Owner-private, crash-safe controller topology transactions.

The module deliberately exposes complete transactions only.  ``_TopologyPort``
is a structural private port implemented by ``ControllerActions``; callers
cannot compose its individual git, GitHub, receipt, or provenance effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol

BranchType = Literal["feat", "fix", "refactor", "docs", "test", "chore"]
ReviewDecision = Literal["MERGE", "MERGE_WITH_COMMENTS"]
_PURPOSE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_LEGACY_HEAD_RE = re.compile(r"^refactor/iter([1-9][0-9]*)-([A-Za-z0-9._-]+)$")
SUPERSESSION_SENTINEL = "<!-- crnd:controller-topology-supersession -->"
_SUPERSESSION_KIND = "controller-topology-supersession"
_SUPERSESSION_MARKER_RE = re.compile(
    r"<!-- crnd:controller-topology-supersession sentinel_digest=([0-9a-f]{64}) -->"
)


class ControllerTopologyError(RuntimeError):
    """The complete transaction could not prove its next exact transition."""


class TopologyPhase(str, Enum):
    CREATE_PREPARED = "CREATE_PREPARED"
    WORKTREE_CREATED = "WORKTREE_CREATED"
    PUBLISH_PREPARED = "PUBLISH_PREPARED"
    LOCAL_REF_READY = "LOCAL_REF_READY"
    REMOTE_REF_PUBLISHED = "REMOTE_REF_PUBLISHED"
    PR_FINALIZED = "PR_FINALIZED"
    PUBLICATION_RECEIPT_FINALIZED = "PUBLICATION_RECEIPT_FINALIZED"
    RETIREMENT_PREPARED = "RETIREMENT_PREPARED"
    SUPERSESSION_POSTED = "SUPERSESSION_POSTED"
    OLD_PR_CLOSED = "OLD_PR_CLOSED"


@dataclass(frozen=True)
class ControllerTopologyIdentity:
    issue_number: int
    purpose: str
    branch_type: BranchType
    date: date

    @property
    def branch(self) -> str:
        return f"{self.branch_type}/{self.date.isoformat()}_{self.purpose}"

    @property
    def worktree_name(self) -> str:
        return self.branch.replace("/", "__")


@dataclass(frozen=True)
class LegacyImplementationHeadEvidence:
    issue_number: int
    cluster: str
    head_ref: str


def parse_legacy_implementation_head_evidence(value: str) -> LegacyImplementationHeadEvidence | None:
    """Parse already-open legacy PR evidence; this function has no write port."""
    match = _LEGACY_HEAD_RE.fullmatch(value)
    if match is None:
        return None
    return LegacyImplementationHeadEvidence(int(match.group(1)), match.group(2), value)


@dataclass(frozen=True)
class CreateCompliantWorktreeRequest:
    identity: ControllerTopologyIdentity
    base_ref: str
    base_sha: str


@dataclass(frozen=True)
class PublishExactHeadRequest:
    identity: ControllerTopologyIdentity
    final_sha: str
    configured_remote: str
    base_branch: str
    legacy_pr_number: int
    receipt_id: str
    title_digest: str
    body_digest: str


@dataclass(frozen=True)
class ReviewGateProjection:
    decision: ReviewDecision
    replacement_pr_number: int
    live_head_sha: str
    evidence_digest: str


@dataclass(frozen=True)
class RetireSupersededPRRequest:
    old_pr_number: int
    replacement_pr_number: int
    linked_issue_number: int
    final_sha: str
    base_branch: str
    review: ReviewGateProjection
    supersession_body_file: Path


@dataclass(frozen=True)
class CreateCompliantWorktreeResult:
    branch: str
    worktree: Path
    base_sha: str
    phase: TopologyPhase


@dataclass(frozen=True)
class PublishExactHeadResult:
    branch: str
    final_sha: str
    pr_number: int
    phase: TopologyPhase


@dataclass(frozen=True)
class RetireSupersededPRResult:
    old_pr_number: int
    replacement_pr_number: int
    phase: TopologyPhase
    supersession_comment_url: str


@dataclass(frozen=True)
class WorktreeState:
    base_ref_sha: str
    local_ref_sha: str | None
    remote_ref_sha: str | None
    worktree_registered: bool
    worktree_branch: str | None
    worktree_head_sha: str | None
    worktree_clean: bool
    foreign_attachment: bool
    open_pr_numbers: tuple[int, ...]


@dataclass(frozen=True)
class PRState:
    number: int
    state: str
    managed: bool
    base_branch: str
    head_branch: str
    head_sha: str
    head_tree_sha: str
    title_digest: str
    body_digest: str
    diff_digest: str
    closing_issue_numbers: tuple[int, ...]


@dataclass(frozen=True)
class ReceiptState:
    receipt_id: str
    status: str
    issue_number: int
    base_branch: str
    head_branch: str
    final_sha: str
    pr_number: int | None


@dataclass(frozen=True)
class PublicationSnapshot:
    worktree: WorktreeState
    commit_exists: bool
    final_tree_sha: str
    final_diff_digest: str
    local_ref_sha: str | None
    remote_ref_sha: str | None
    canonical_prs: tuple[PRState, ...]
    legacy_pr: PRState
    linked_issue_state: str
    receipt: ReceiptState


@dataclass(frozen=True)
class RetirementSnapshot:
    old: PRState
    replacement: PRState
    linked_issue_state: str
    review: ReviewGateProjection
    sentinel_urls: tuple[str, ...]


@dataclass(frozen=True)
class TopologyProvenance:
    key: str
    phase: TopologyPhase
    generation: int
    digest: str
    issue_number: int
    purpose: str
    branch_type: str
    branch_date: str
    branch: str
    worktree: str
    base_ref: str
    base_sha: str
    configured_remote: str = ""
    base_branch: str = ""
    final_sha: str = ""
    final_tree_sha: str = ""
    final_diff_digest: str = ""
    receipt_id: str = ""
    legacy_pr_number: int = 0
    legacy_head: str = ""
    pr_number: int = 0
    title_digest: str = ""
    body_digest: str = ""
    old_pr_number: int = 0
    replacement_pr_number: int = 0
    review_evidence_digest: str = ""
    equivalence_digest: str = ""
    sentinel_digest: str = ""
    sentinel_url: str = ""

    def payload(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        value["phase"] = self.phase.value
        return value

    def exact(self) -> "TopologyProvenance":
        encoded = json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode()
        return replace(self, digest=hashlib.sha256(encoded).hexdigest())


_DURABLE_PUBLICATION_PHASES = {
    TopologyPhase.WORKTREE_CREATED,
    TopologyPhase.PUBLISH_PREPARED,
    TopologyPhase.LOCAL_REF_READY,
    TopologyPhase.REMOTE_REF_PUBLISHED,
    TopologyPhase.PR_FINALIZED,
    TopologyPhase.PUBLICATION_RECEIPT_FINALIZED,
}


def _iter_exact_publications(repo_root: Path):
    state_dir = repo_root / ".refactor-loop" / "state" / "controller-topology"
    if not state_dir.is_dir():
        return
    worktrees = (repo_root / ".worktrees").resolve()
    for path in state_dir.glob("publication__*.json"):
        if not path.is_file():
            raise ControllerTopologyError("publication provenance is not a regular file")
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
            row["phase"] = TopologyPhase(str(row["phase"]))
            record = TopologyProvenance(**row)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ControllerTopologyError(f"invalid publication provenance: {path}") from exc
        expected_name = re.sub(r"[^A-Za-z0-9._-]", "__", f"publication:{record.branch}") + ".json"
        worktree = Path(record.worktree)
        if (record != record.exact() or record.key != f"publication:{record.branch}"
                or path.name != expected_name or record.phase not in _DURABLE_PUBLICATION_PHASES
                or not worktree.is_absolute() or worktree.name != record.branch.replace("/", "__")):
            raise ControllerTopologyError("publication provenance membership mismatch")
        try:
            resolved = worktree.resolve().relative_to(worktrees)
        except ValueError as exc:
            raise ControllerTopologyError("publication worktree escapes canonical root") from exc
        if len(resolved.parts) != 1:
            raise ControllerTopologyError("publication worktree is not canonical")
        yield record, worktree.resolve()


def read_controller_topology_identity(repo_root: Path, issue_number: int) -> tuple[str, Path] | None:
    """Read exactly one durable publication identity for an issue."""
    matches = {(record.branch, worktree) for record, worktree in _iter_exact_publications(repo_root)
               if record.issue_number == issue_number}
    if len(matches) > 1:
        raise ControllerTopologyError("duplicate controller topology identity")
    return matches.pop() if matches else None


def controller_topology_branch_is_durable(repo_root: Path, branch: str) -> bool:
    return any(record.branch == branch for record, _ in _iter_exact_publications(repo_root))


class _TopologyPort(Protocol):
    repo_root: Path

    def _topology_require_fresh_owner(self, action: str) -> None: ...
    def _topology_read_provenance(self, key: str) -> TopologyProvenance | None: ...
    def _topology_cas_provenance(
        self, key: str, expected_generation: int | None, expected_digest: str | None, value: TopologyProvenance
    ) -> None: ...
    def _topology_read_worktree(self, branch: str, worktree: Path, base_ref: str, remote: str) -> WorktreeState: ...
    def _topology_create_worktree(self, branch: str, worktree: Path, base_sha: str) -> None: ...
    def _topology_attach_worktree(self, branch: str, worktree: Path) -> None: ...
    def _topology_read_publication(self, request: PublishExactHeadRequest, worktree: Path) -> PublicationSnapshot: ...
    def _topology_create_local_ref(self, branch: str, final_sha: str) -> None: ...
    def _topology_push_exact_ref(self, remote: str, branch: str, final_sha: str) -> None: ...
    def _topology_create_or_update_pr(self, request: PublishExactHeadRequest, existing: PRState | None) -> int: ...
    def _topology_finalize_receipt(self, receipt_id: str, pr_number: int) -> None: ...
    def _topology_read_retirement(self, request: RetireSupersededPRRequest, sentinel_digest: str) -> RetirementSnapshot: ...
    def _topology_post_supersession(self, request: RetireSupersededPRRequest, sentinel_digest: str) -> str: ...
    def _topology_close_old_pr(self, old_pr_number: int) -> None: ...


class ControllerTopologyAuthority:
    """The only policy owner for three complete topology transactions."""

    def __init__(self, port: _TopologyPort) -> None:
        self._port = port

    def create_compliant_worktree(self, request: CreateCompliantWorktreeRequest) -> CreateCompliantWorktreeResult:
        identity = _validated_identity(request.identity)
        _sha(request.base_sha, "base_sha")
        _token(request.base_ref, "base_ref")
        branch = identity.branch
        worktree = self._port.repo_root / ".worktrees" / identity.worktree_name
        key = f"publication:{branch}"
        record = self._port._topology_read_provenance(key)
        live = self._port._topology_read_worktree(branch, worktree, request.base_ref, "origin")
        if record is None:
            if live.base_ref_sha != request.base_sha or _has_create_collision(live):
                raise ControllerTopologyError("create preproof collision or stale base")
            prepared = TopologyProvenance(
                key, TopologyPhase.CREATE_PREPARED, 1, "", identity.issue_number, identity.purpose,
                identity.branch_type, identity.date.isoformat(), branch, str(worktree), request.base_ref,
                request.base_sha,
            ).exact()
            self._fresh("create prepare CAS")
            self._port._topology_cas_provenance(key, None, None, prepared)
            record = self._reread_exact(prepared)
        self._require_create_identity(record, request, worktree)
        if record.phase is TopologyPhase.WORKTREE_CREATED:
            self._require_complete_worktree(live, branch, request.base_sha)
            return CreateCompliantWorktreeResult(branch, worktree, request.base_sha, record.phase)
        if record.phase is not TopologyPhase.CREATE_PREPARED:
            raise ControllerTopologyError("create cannot resume from publication phase")

        live = self._port._topology_read_worktree(branch, worktree, request.base_ref, "origin")
        complete = _is_complete_worktree(live, branch, request.base_sha)
        branch_only = _is_branch_only(live, request.base_sha)
        if not complete:
            self._fresh("create worktree effect")
            if _is_wholly_absent(live):
                self._port._topology_create_worktree(branch, worktree, request.base_sha)
            elif branch_only:
                self._port._topology_attach_worktree(branch, worktree)
            else:
                raise ControllerTopologyError("create partial state is not exactly adoptable")
            live = self._port._topology_read_worktree(branch, worktree, request.base_ref, "origin")
        self._require_complete_worktree(live, branch, request.base_sha)
        advanced = self._advance(record, TopologyPhase.WORKTREE_CREATED)
        self._cas(record, advanced, "created phase CAS")
        return CreateCompliantWorktreeResult(branch, worktree, request.base_sha, advanced.phase)

    def publish_exact_head(self, request: PublishExactHeadRequest) -> PublishExactHeadResult:
        identity = _validated_identity(request.identity)
        _sha(request.final_sha, "final_sha")
        for value, name in ((request.configured_remote, "configured_remote"), (request.base_branch, "base_branch"),
                            (request.receipt_id, "receipt_id"), (request.title_digest, "title_digest"),
                            (request.body_digest, "body_digest")):
            _token(value, name)
        key = f"publication:{identity.branch}"
        record = self._required_record(key)
        worktree = Path(record.worktree)
        if record.phase is TopologyPhase.PUBLICATION_RECEIPT_FINALIZED:
            self._require_publication_identity(record, request)
            snapshot = self._continuing_publication(record, request, worktree)
            exact = self._exact_canonical_prs(snapshot, request)
            if len(exact) != 1 or exact[0].number != record.pr_number:
                raise ControllerTopologyError("terminal publication PR proof changed")
            self._validate_exact(snapshot.local_ref_sha, request.final_sha, "local ref")
            self._validate_exact(snapshot.remote_ref_sha, request.final_sha, "remote ref")
            self._validate_receipt(snapshot.receipt, request, record.pr_number, "PUBLISHED")
            return PublishExactHeadResult(identity.branch, request.final_sha, record.pr_number, record.phase)
        if record.phase is TopologyPhase.WORKTREE_CREATED:
            snapshot = self._port._topology_read_publication(request, worktree)
            self._validate_publish_snapshot(snapshot, record, request)
            self._validate_receipt(snapshot.receipt, request, None, "VERIFIED")
            legacy = parse_legacy_implementation_head_evidence(snapshot.legacy_pr.head_branch)
            if legacy is None or legacy.issue_number != identity.issue_number:
                raise ControllerTopologyError("legacy evidence is not eligible")
            prepared = replace(
                record, phase=TopologyPhase.PUBLISH_PREPARED, generation=record.generation + 1, digest="",
                configured_remote=request.configured_remote, base_branch=request.base_branch,
                final_sha=request.final_sha, final_tree_sha=snapshot.final_tree_sha,
                final_diff_digest=snapshot.final_diff_digest,
                receipt_id=request.receipt_id, legacy_pr_number=request.legacy_pr_number,
                legacy_head=snapshot.legacy_pr.head_branch, title_digest=request.title_digest,
                body_digest=request.body_digest,
            ).exact()
            self._cas(record, prepared, "publish prepare CAS")
            record = prepared
        self._require_publication_identity(record, request)

        if record.phase is TopologyPhase.PUBLISH_PREPARED:
            snapshot = self._continuing_publication(record, request, worktree)
            self._validate_ref(snapshot.local_ref_sha, request.final_sha, "local")
            self._validate_ref(snapshot.remote_ref_sha, request.final_sha, "remote")
            if snapshot.local_ref_sha is None:
                self._fresh("local ref effect")
                self._port._topology_create_local_ref(identity.branch, request.final_sha)
                snapshot = self._continuing_publication(record, request, worktree)
            self._validate_exact(snapshot.local_ref_sha, request.final_sha, "local ref")
            record = self._adopt_phase(record, TopologyPhase.LOCAL_REF_READY, "local ref phase CAS")

        if record.phase is TopologyPhase.LOCAL_REF_READY:
            snapshot = self._continuing_publication(record, request, worktree)
            self._validate_exact(snapshot.local_ref_sha, request.final_sha, "local ref")
            self._validate_ref(snapshot.remote_ref_sha, request.final_sha, "remote")
            if snapshot.remote_ref_sha is None:
                self._fresh("remote ref effect")
                self._port._topology_push_exact_ref(request.configured_remote, identity.branch, request.final_sha)
                snapshot = self._continuing_publication(record, request, worktree)
            self._validate_exact(snapshot.remote_ref_sha, request.final_sha, "remote ref")
            record = self._adopt_phase(record, TopologyPhase.REMOTE_REF_PUBLISHED, "remote ref phase CAS")

        if record.phase is TopologyPhase.REMOTE_REF_PUBLISHED:
            snapshot = self._continuing_publication(record, request, worktree)
            exact = self._exact_canonical_prs(snapshot, request)
            if len(snapshot.canonical_prs) > 1 or len(exact) > 1:
                raise ControllerTopologyError("canonical PR set is ambiguous")
            existing = exact[0] if exact else None
            updateable = self._updateable_canonical_prs(snapshot, request)
            if existing is None and len(updateable) == 1:
                self._fresh("replacement PR effect")
                self._port._topology_create_or_update_pr(request, updateable[0])
                snapshot = self._continuing_publication(record, request, worktree)
                exact = self._exact_canonical_prs(snapshot, request)
                existing = exact[0] if len(exact) == 1 else None
            elif snapshot.canonical_prs and existing is None:
                raise ControllerTopologyError("canonical PR collision")
            if existing is None:
                self._fresh("replacement PR effect")
                self._port._topology_create_or_update_pr(request, None)
                snapshot = self._continuing_publication(record, request, worktree)
                exact = self._exact_canonical_prs(snapshot, request)
            if len(exact) != 1:
                raise ControllerTopologyError("replacement PR exact postproof failed")
            record = self._adopt_phase(replace(record, pr_number=exact[0].number).exact(), TopologyPhase.PR_FINALIZED,
                                       "replacement PR phase CAS", prior=record)

        if record.phase is TopologyPhase.PR_FINALIZED:
            snapshot = self._continuing_publication(record, request, worktree)
            exact = self._exact_canonical_prs(snapshot, request)
            if len(exact) != 1 or exact[0].number != record.pr_number:
                raise ControllerTopologyError("PR finalization proof changed")
            receipt = snapshot.receipt
            if receipt.status != "PUBLISHED":
                if receipt.status != "VERIFIED":
                    raise ControllerTopologyError("receipt is not VERIFIED")
                self._fresh("receipt finalization effect")
                self._port._topology_finalize_receipt(request.receipt_id, record.pr_number)
                snapshot = self._continuing_publication(record, request, worktree)
            self._validate_receipt(snapshot.receipt, request, record.pr_number, "PUBLISHED")
            record = self._adopt_phase(record, TopologyPhase.PUBLICATION_RECEIPT_FINALIZED,
                                       "publication terminal CAS")
        return PublishExactHeadResult(identity.branch, request.final_sha, record.pr_number, record.phase)

    def retire_superseded_pr(self, request: RetireSupersededPRRequest) -> RetireSupersededPRResult:
        self._validate_retirement_request(request)
        key = f"retirement:{request.old_pr_number}:{request.replacement_pr_number}"
        record = self._port._topology_read_provenance(key)
        if record is None:
            snapshot = self._port._topology_read_retirement(request, "")
            equivalence = self._validate_retirement_snapshot(snapshot, request, allow_closed=False)
            sentinel_digest = _sentinel_digest(request, equivalence)
            snapshot = self._port._topology_read_retirement(request, sentinel_digest)
            if self._validate_retirement_snapshot(snapshot, request, allow_closed=False) != equivalence:
                raise ControllerTopologyError("retirement evidence changed during preparation")
            prepared = TopologyProvenance(
                key, TopologyPhase.RETIREMENT_PREPARED, 1, "", request.linked_issue_number, "retirement",
                "refactor", "", snapshot.replacement.head_branch, "", "", "", base_branch=request.base_branch,
                final_sha=request.final_sha, old_pr_number=request.old_pr_number,
                replacement_pr_number=request.replacement_pr_number,
                review_evidence_digest=request.review.evidence_digest, equivalence_digest=equivalence,
                sentinel_digest=sentinel_digest,
            ).exact()
            self._fresh("retirement prepare CAS")
            self._port._topology_cas_provenance(key, None, None, prepared)
            record = self._reread_exact(prepared)
        self._require_retirement_identity(record, request)
        if record.phase is TopologyPhase.OLD_PR_CLOSED:
            snapshot = self._port._topology_read_retirement(request, record.sentinel_digest)
            self._validate_retirement_snapshot(snapshot, request, allow_closed=True, require_closed=True)
            self._require_stored_sentinel(snapshot, record)
            return RetireSupersededPRResult(request.old_pr_number, request.replacement_pr_number,
                                            record.phase, record.sentinel_url)
        if record.phase is TopologyPhase.RETIREMENT_PREPARED:
            snapshot = self._port._topology_read_retirement(request, record.sentinel_digest)
            equivalence = self._validate_retirement_snapshot(snapshot, request, allow_closed=False)
            if equivalence != record.equivalence_digest or record.sentinel_digest != _sentinel_digest(request, equivalence):
                raise ControllerTopologyError("retirement immutable evidence changed")
            if len(snapshot.sentinel_urls) > 1:
                raise ControllerTopologyError("duplicate supersession sentinel")
            sentinel = snapshot.sentinel_urls[0] if snapshot.sentinel_urls else ""
            if not sentinel:
                self._fresh("supersession comment effect")
                self._port._topology_post_supersession(request, record.sentinel_digest)
                snapshot = self._port._topology_read_retirement(request, record.sentinel_digest)
                if len(snapshot.sentinel_urls) != 1:
                    raise ControllerTopologyError("supersession sentinel postproof failed")
                sentinel = snapshot.sentinel_urls[0]
            proposed = replace(record, sentinel_url=sentinel).exact()
            record = self._adopt_phase(proposed, TopologyPhase.SUPERSESSION_POSTED,
                                       "supersession phase CAS", prior=record)
        if record.phase is TopologyPhase.SUPERSESSION_POSTED:
            snapshot = self._port._topology_read_retirement(request, record.sentinel_digest)
            self._validate_retirement_snapshot(snapshot, request, allow_closed=True)
            self._require_stored_sentinel(snapshot, record)
            if snapshot.old.state == "OPEN":
                self._fresh("old PR close effect")
                self._port._topology_close_old_pr(request.old_pr_number)
                snapshot = self._port._topology_read_retirement(request, record.sentinel_digest)
            self._validate_retirement_snapshot(snapshot, request, allow_closed=True, require_closed=True)
            self._require_stored_sentinel(snapshot, record)
            record = self._adopt_phase(record, TopologyPhase.OLD_PR_CLOSED, "old close terminal CAS")
        return RetireSupersededPRResult(request.old_pr_number, request.replacement_pr_number,
                                        record.phase, record.sentinel_url)

    def _fresh(self, boundary: str) -> None:
        self._port._topology_require_fresh_owner(f"controller topology: {boundary}")

    def _required_record(self, key: str) -> TopologyProvenance:
        record = self._port._topology_read_provenance(key)
        if record is None or record != record.exact():
            raise ControllerTopologyError("missing or invalid provenance")
        return record

    def _reread_exact(self, expected: TopologyProvenance) -> TopologyProvenance:
        actual = self._port._topology_read_provenance(expected.key)
        if actual != expected or actual != actual.exact():
            raise ControllerTopologyError("provenance CAS postproof failed")
        return actual

    def _cas(self, prior: TopologyProvenance, value: TopologyProvenance, boundary: str) -> None:
        current = self._port._topology_read_provenance(prior.key)
        if current != prior:
            raise ControllerTopologyError("provenance generation/digest changed")
        self._fresh(boundary)
        self._port._topology_cas_provenance(prior.key, prior.generation, prior.digest, value)
        self._reread_exact(value)

    def _advance(self, record: TopologyProvenance, phase: TopologyPhase) -> TopologyProvenance:
        return replace(record, phase=phase, generation=record.generation + 1, digest="").exact()

    def _adopt_phase(self, record: TopologyProvenance, phase: TopologyPhase, boundary: str,
                     prior: TopologyProvenance | None = None) -> TopologyProvenance:
        old = prior or record
        advanced = replace(record, phase=phase, generation=old.generation + 1, digest="").exact()
        self._cas(old, advanced, boundary)
        return advanced

    @staticmethod
    def _require_complete_worktree(live: WorktreeState, branch: str, sha: str) -> None:
        if not _is_complete_worktree(live, branch, sha):
            raise ControllerTopologyError("worktree exact postproof failed")

    @staticmethod
    def _require_create_identity(record: TopologyProvenance, request: CreateCompliantWorktreeRequest,
                                 worktree: Path) -> None:
        identity = request.identity
        expected = (identity.issue_number, identity.purpose, identity.branch_type, identity.date.isoformat(),
                    identity.branch, str(worktree), request.base_ref, request.base_sha)
        actual = (record.issue_number, record.purpose, record.branch_type, record.branch_date, record.branch,
                  record.worktree, record.base_ref, record.base_sha)
        if actual != expected or record != record.exact():
            raise ControllerTopologyError("create provenance identity mismatch")

    @staticmethod
    def _require_publication_identity(record: TopologyProvenance, request: PublishExactHeadRequest) -> None:
        expected = (request.identity.issue_number, request.identity.branch, request.configured_remote,
                    request.base_branch, request.final_sha, request.receipt_id, request.legacy_pr_number,
                    request.title_digest, request.body_digest)
        actual = (record.issue_number, record.branch, record.configured_remote, record.base_branch,
                  record.final_sha, record.receipt_id, record.legacy_pr_number, record.title_digest,
                  record.body_digest)
        if actual != expected or record != record.exact():
            raise ControllerTopologyError("publication provenance identity mismatch")

    def _validate_publish_snapshot(self, snapshot: PublicationSnapshot, record: TopologyProvenance,
                                   request: PublishExactHeadRequest) -> None:
        live = snapshot.worktree
        if not (live.worktree_registered and live.worktree_branch == record.branch
                and live.worktree_head_sha == request.final_sha and live.worktree_clean
                and not live.foreign_attachment):
            raise ControllerTopologyError("publication worktree proof failed")
        if (not snapshot.commit_exists or not _SHA_RE.fullmatch(snapshot.final_tree_sha)
                or not re.fullmatch(r"[0-9a-f]{64}", snapshot.final_diff_digest)):
            raise ControllerTopologyError("final SHA is not an independently available commit")
        legacy = snapshot.legacy_pr
        if legacy.number != request.legacy_pr_number or legacy.head_sha != request.final_sha:
            raise ControllerTopologyError("legacy evidence does not bind exact final SHA")
        if (legacy.state != "OPEN" or not legacy.managed or legacy.base_branch != request.base_branch
                or legacy.head_tree_sha != snapshot.final_tree_sha
                or legacy.diff_digest != snapshot.final_diff_digest
                or legacy.closing_issue_numbers != (request.identity.issue_number,)
                or snapshot.linked_issue_state != "OPEN"):
            raise ControllerTopologyError("legacy base or linked issue changed")
        if snapshot.receipt.status == "VERIFIED":
            self._validate_receipt(snapshot.receipt, request, None, "VERIFIED")
        elif snapshot.receipt.status == "PUBLISHED":
            if snapshot.receipt.pr_number is None:
                raise ControllerTopologyError("published receipt has no PR")
            self._validate_receipt(snapshot.receipt, request, snapshot.receipt.pr_number, "PUBLISHED")
        else:
            raise ControllerTopologyError("receipt is neither VERIFIED nor PUBLISHED")

    def _continuing_publication(self, record: TopologyProvenance, request: PublishExactHeadRequest,
                                worktree: Path) -> PublicationSnapshot:
        snapshot = self._port._topology_read_publication(request, worktree)
        self._validate_publish_snapshot(snapshot, record, request)
        if (snapshot.final_tree_sha != record.final_tree_sha
                or snapshot.final_diff_digest != record.final_diff_digest):
            raise ControllerTopologyError("publication final evidence changed")
        return snapshot

    @staticmethod
    def _validate_ref(actual: str | None, expected: str, label: str) -> None:
        if actual not in (None, expected):
            raise ControllerTopologyError(f"{label} ref collision")

    @staticmethod
    def _validate_exact(actual: str | None, expected: str, label: str) -> None:
        if actual != expected:
            raise ControllerTopologyError(f"{label} exact postproof failed")

    @staticmethod
    def _exact_canonical_prs(snapshot: PublicationSnapshot, request: PublishExactHeadRequest) -> list[PRState]:
        return [pr for pr in snapshot.canonical_prs if pr.state == "OPEN" and pr.managed
                and pr.base_branch == request.base_branch and pr.head_branch == request.identity.branch
                and pr.head_sha == request.final_sha and pr.head_tree_sha == snapshot.final_tree_sha
                and pr.diff_digest == snapshot.final_diff_digest
                and pr.title_digest == request.title_digest and pr.body_digest == request.body_digest
                and pr.closing_issue_numbers == (request.identity.issue_number,)]

    @staticmethod
    def _updateable_canonical_prs(snapshot: PublicationSnapshot, request: PublishExactHeadRequest) -> list[PRState]:
        return [
            pr
            for pr in snapshot.canonical_prs
            if pr.state == "OPEN"
            and pr.managed
            and pr.base_branch == request.base_branch
            and pr.head_branch == request.identity.branch
            and pr.head_sha == request.final_sha
            and pr.head_tree_sha == snapshot.final_tree_sha
            and pr.diff_digest == snapshot.final_diff_digest
            and pr.closing_issue_numbers == (request.identity.issue_number,)
        ]

    @staticmethod
    def _validate_receipt(receipt: ReceiptState, request: PublishExactHeadRequest,
                          pr_number: int | None, status: str) -> None:
        expected = (request.receipt_id, status, request.identity.issue_number, request.base_branch,
                    request.identity.branch, request.final_sha, pr_number)
        actual = (receipt.receipt_id, receipt.status, receipt.issue_number, receipt.base_branch,
                  receipt.head_branch, receipt.final_sha, receipt.pr_number)
        if actual != expected:
            raise ControllerTopologyError("publish-verification receipt identity mismatch")

    @staticmethod
    def _validate_retirement_request(request: RetireSupersededPRRequest) -> None:
        if min(request.old_pr_number, request.replacement_pr_number, request.linked_issue_number) <= 0:
            raise ControllerTopologyError("PR and issue numbers must be positive")
        if request.old_pr_number == request.replacement_pr_number:
            raise ControllerTopologyError("old and replacement PR must differ")
        _sha(request.final_sha, "final_sha")
        if request.review.decision not in ("MERGE", "MERGE_WITH_COMMENTS"):
            raise ControllerTopologyError("review gate is not merge-capable")
        if request.review.replacement_pr_number != request.replacement_pr_number or request.review.live_head_sha != request.final_sha:
            raise ControllerTopologyError("review projection is stale or foreign")
        body = request.supersession_body_file.read_text(encoding="utf-8")
        if body.count(SUPERSESSION_SENTINEL) != 1:
            raise ControllerTopologyError("supersession body must contain exactly one sentinel")

    @staticmethod
    def _require_stored_sentinel(snapshot: RetirementSnapshot, record: TopologyProvenance) -> None:
        if len(snapshot.sentinel_urls) != 1 or snapshot.sentinel_urls[0] != record.sentinel_url:
            raise ControllerTopologyError("stored supersession sentinel is not uniquely rediscoverable")

    @staticmethod
    def _validate_retirement_snapshot(snapshot: RetirementSnapshot, request: RetireSupersededPRRequest,
                                      allow_closed: bool, require_closed: bool = False) -> str:
        old, replacement = snapshot.old, snapshot.replacement
        if old.number != request.old_pr_number or replacement.number != request.replacement_pr_number:
            raise ControllerTopologyError("retirement PR identity changed")
        allowed_old = {"CLOSED"} if require_closed else ({"OPEN", "CLOSED"} if allow_closed else {"OPEN"})
        if old.state not in allowed_old or replacement.state != "OPEN" or snapshot.linked_issue_state != "OPEN":
            raise ControllerTopologyError("retirement live state changed")
        if not old.managed or not replacement.managed or old.base_branch != request.base_branch or replacement.base_branch != request.base_branch:
            raise ControllerTopologyError("retirement management/base proof changed")
        closing = (request.linked_issue_number,)
        if old.closing_issue_numbers != closing or replacement.closing_issue_numbers != closing:
            raise ControllerTopologyError("retirement issue equivalence changed")
        if old.head_sha != request.final_sha or replacement.head_sha != request.final_sha:
            raise ControllerTopologyError("retirement exact head changed")
        if old.head_tree_sha != replacement.head_tree_sha or old.diff_digest != replacement.diff_digest:
            raise ControllerTopologyError("retirement equivalence changed")
        if snapshot.review != request.review or snapshot.review.decision not in ("MERGE", "MERGE_WITH_COMMENTS"):
            raise ControllerTopologyError("canonical review truth input changed")
        if len(snapshot.sentinel_urls) > 1:
            raise ControllerTopologyError("sentinel is duplicate or foreign")
        return hashlib.sha256(f"{old.head_tree_sha}:{old.diff_digest}".encode()).hexdigest()

    @staticmethod
    def _require_retirement_identity(record: TopologyProvenance, request: RetireSupersededPRRequest) -> None:
        expected = (request.linked_issue_number, request.old_pr_number, request.replacement_pr_number,
                    request.final_sha, request.base_branch, request.review.evidence_digest)
        actual = (record.issue_number, record.old_pr_number, record.replacement_pr_number, record.final_sha,
                  record.base_branch, record.review_evidence_digest)
        if actual != expected or record != record.exact():
            raise ControllerTopologyError("retirement provenance identity mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", record.sentinel_digest):
            raise ControllerTopologyError("retirement sentinel digest is invalid")


def _validated_identity(identity: ControllerTopologyIdentity) -> ControllerTopologyIdentity:
    if identity.issue_number <= 0 or identity.branch_type not in {"feat", "fix", "refactor", "docs", "test", "chore"}:
        raise ControllerTopologyError("invalid topology identity")
    if not _PURPOSE_RE.fullmatch(identity.purpose):
        raise ControllerTopologyError("purpose must be lower-kebab-case")
    return identity


def _sha(value: str, name: str) -> None:
    if not _SHA_RE.fullmatch(value):
        raise ControllerTopologyError(f"{name} must be lowercase 40-hex")


def _token(value: str, name: str) -> None:
    if not value or value.startswith("-") or "\x00" in value or "\n" in value:
        raise ControllerTopologyError(f"invalid {name}")


def supersession_marker(sentinel_digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", sentinel_digest):
        raise ControllerTopologyError("sentinel_digest must be lowercase 64-hex")
    return f"<!-- crnd:controller-topology-supersession sentinel_digest={sentinel_digest} -->"


def _sentinel_digest(request: RetireSupersededPRRequest, equivalence_digest: str) -> str:
    payload = {
        "base_branch": request.base_branch,
        "equivalence_digest": equivalence_digest,
        "final_sha": request.final_sha,
        "key": f"retirement:{request.old_pr_number}:{request.replacement_pr_number}",
        "kind": _SUPERSESSION_KIND,
        "linked_issue_number": request.linked_issue_number,
        "old_pr_number": request.old_pr_number,
        "replacement_pr_number": request.replacement_pr_number,
        "review_evidence_digest": request.review.evidence_digest,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_wholly_absent(live: WorktreeState) -> bool:
    return live.local_ref_sha is None and not live.worktree_registered and not live.foreign_attachment


def _is_branch_only(live: WorktreeState, sha: str) -> bool:
    return live.local_ref_sha == sha and not live.worktree_registered and not live.foreign_attachment


def _is_complete_worktree(live: WorktreeState, branch: str, sha: str) -> bool:
    return (live.local_ref_sha == sha and live.worktree_registered and live.worktree_branch == branch
            and live.worktree_head_sha == sha and live.worktree_clean and not live.foreign_attachment)


def _has_create_collision(live: WorktreeState) -> bool:
    return bool(live.local_ref_sha or live.remote_ref_sha or live.worktree_registered
                or live.foreign_attachment or live.open_pr_numbers)
