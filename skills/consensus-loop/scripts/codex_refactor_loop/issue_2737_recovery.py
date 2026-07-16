"""Disposable, fork-private capability for the reviewed #2737 recovery."""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence


class Issue2737RecoveryBlocked(RuntimeError):
    pass


class Issue2737Effect(Enum):
    M2775 = "M2775"
    O2772 = "O2772"
    X2772 = "X2772"
    M2776 = "M2776"
    O2773 = "O2773"
    X2773 = "X2773"
    M2777 = "M2777"
    O2774 = "O2774"
    X2774 = "X2774"


ORDER = (
    Issue2737Effect.M2775, Issue2737Effect.O2772, Issue2737Effect.X2772,
    Issue2737Effect.M2776, Issue2737Effect.O2773, Issue2737Effect.X2773,
    Issue2737Effect.M2777, Issue2737Effect.O2774, Issue2737Effect.X2774,
)
_OCCURRENCE_PATH = "skills/consensus-loop/authorizations/issue-2737-reselection.json"
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOP_KEYS = frozenset({"contract", "incident", "implementation", "authorization_pr", "occurrence", "settled_topology", "prefix_zero_baseline"})
_FORBIDDEN_KEYS = frozenset({"effect", "effects", "order", "method", "endpoint", "payload", "transaction", "argv", "command", "env", "attestation", "authorized", "record_digest", "required_checks", "reviews"})
_BOUND_FILE_KEYS = frozenset({"path", "blob_oid", "sha256"})
_TOPOLOGY_IDENTITY_KEYS = frozenset({"slug", "issue", "url"})
_FINGERPRINT_KEYS = frozenset({"slug", "modern_issue", "fingerprint"})
_ISSUE_BASELINE_KEYS = frozenset({"issue", "url", "state", "state_reason", "title_sha256", "body_sha256", "labels", "author", "assignees", "milestone", "comments", "comment_high_water", "reactions"})
_COMMENT_BASELINE_KEYS = frozenset({"id", "url", "author", "body_sha256", "created_at", "updated_at", "minimized", "reactions"})
_REACTION_KEYS = frozenset({"content", "users"})
_PR_BASELINE_KEYS = frozenset({"number", "url", "state", "draft", "base_repository", "base_ref", "base_sha", "head_repository", "head_ref", "head_sha", "title_sha256", "body_sha256"})
_RETAINED_TOPOLOGY = (
    ("materialize", 2775), ("derive", 2776), ("integrate", 2777),
)
_RETIRED_TOPOLOGY = (
    ("legacy-materialize", 2772), ("legacy-derive", 2773), ("legacy-integrate", 2774),
)


@dataclass(frozen=True)
class Issue2737Occurrence:
    raw: Mapping[str, Any]
    exact_bytes: bytes
    expires_at: datetime


@dataclass(frozen=True)
class Issue2737Binding:
    record_digest: str
    record_blob_oid: str
    expires_at: datetime
    prefix: int
    observation_digest: str


def _blocked(reason: str) -> Issue2737RecoveryBlocked:
    return Issue2737RecoveryBlocked(f"issue-2737-recovery:{reason}")


def _exact_keys(value: Any, keys: set[str] | frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise _blocked(f"record-{where}-fields")
    return value


def _reject_forbidden(value: Any) -> None:
    if isinstance(value, dict):
        if _FORBIDDEN_KEYS.intersection(value):
            raise _blocked("record-forbidden-authority")
        for child in value.values():
            _reject_forbidden(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden(child)
    elif value is None or isinstance(value, float):
        raise _blocked("record-null-or-float")


def _positive_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _blocked(f"record-{where}")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise _blocked(f"record-{where}")
    return value


def _hex(value: Any, pattern: re.Pattern[str], where: str) -> str:
    text = _string(value, where)
    if pattern.fullmatch(text) is None:
        raise _blocked(f"record-{where}")
    return text


def _tuple(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise _blocked(f"record-{where}")
    return value


def _validate_reactions(value: Any, where: str) -> None:
    seen: set[str] = set()
    for index, raw in enumerate(_tuple(value, where)):
        row = _exact_keys(raw, _REACTION_KEYS, f"{where}-{index}")
        content = _string(row["content"], f"{where}-content")
        users = _tuple(row["users"], f"{where}-users")
        if content in seen or any(not isinstance(user, str) or not user for user in users) or users != sorted(set(users)):
            raise _blocked(f"record-{where}")
        seen.add(content)


def _validate_comment(value: Any, where: str) -> None:
    row = _exact_keys(value, _COMMENT_BASELINE_KEYS, where)
    _positive_int(row["id"], f"{where}-id")
    for key in ("url", "author", "created_at", "updated_at"):
        _string(row[key], f"{where}-{key}")
    _hex(row["body_sha256"], _HEX64, f"{where}-body-sha256")
    if row["minimized"] is not False:
        raise _blocked(f"record-{where}-minimized")
    _validate_reactions(row["reactions"], f"{where}-reactions")


def _validate_issue_baseline(value: Any, where: str) -> None:
    row = _exact_keys(value, _ISSUE_BASELINE_KEYS, where)
    _positive_int(row["issue"], f"{where}-issue")
    for key in ("url", "state", "title_sha256", "body_sha256", "author"):
        _string(row[key], f"{where}-{key}")
    _hex(row["title_sha256"], _HEX64, f"{where}-title-sha256")
    _hex(row["body_sha256"], _HEX64, f"{where}-body-sha256")
    if row["state_reason"] not in ("", "not_planned") or row["milestone"] != "":
        raise _blocked(f"record-{where}-mutable-shape")
    for key in ("labels", "assignees"):
        values = _tuple(row[key], f"{where}-{key}")
        if any(not isinstance(item, str) or not item for item in values) or values != sorted(set(values)):
            raise _blocked(f"record-{where}-{key}")
    comments = _tuple(row["comments"], f"{where}-comments")
    for index, comment in enumerate(comments):
        _validate_comment(comment, f"{where}-comment-{index}")
    ids = [comment["id"] for comment in comments]
    if ids != sorted(set(ids)) or row["comment_high_water"] != (max(ids) if ids else 0):
        raise _blocked(f"record-{where}-comment-order")
    _validate_reactions(row["reactions"], f"{where}-reactions")


def _validate_nested_record(top: Mapping[str, Any]) -> None:
    implementation = top["implementation"]
    files = _tuple(implementation["bound_files"], "bound-files")
    if not files:
        raise _blocked("record-bound-files")
    paths: list[str] = []
    for index, raw in enumerate(files):
        row = _exact_keys(raw, _BOUND_FILE_KEYS, f"bound-file-{index}")
        paths.append(_string(row["path"], "bound-file-path"))
        _string(row["blob_oid"], "bound-file-blob")
        _hex(row["sha256"], _HEX64, "bound-file-sha256")
    if paths != sorted(set(paths)) or any(path.startswith("/") or ".." in path.split("/") for path in paths):
        raise _blocked("record-bound-files")
    topology = _exact_keys(top["settled_topology"], {"retained", "retired", "fingerprints"}, "settled-topology")
    identities: dict[str, Mapping[str, Any]] = {}
    for group in ("retained", "retired"):
        rows = _tuple(topology[group], f"topology-{group}")
        if len(rows) != 3:
            raise _blocked(f"record-topology-{group}")
        for index, raw in enumerate(rows):
            row = _exact_keys(raw, _TOPOLOGY_IDENTITY_KEYS, f"topology-{group}-{index}")
            slug = _string(row["slug"], "topology-slug")
            _positive_int(row["issue"], "topology-issue")
            _string(row["url"], "topology-url")
            if slug in identities:
                raise _blocked("record-topology-duplicate")
            identities[slug] = row
    for group, expected in (("retained", _RETAINED_TOPOLOGY), ("retired", _RETIRED_TOPOLOGY)):
        actual = tuple((row["slug"], row["issue"]) for row in topology[group])
        if actual != expected or any(row["url"] != f"https://github.com/aevatarAI/aevatar/issues/{row['issue']}" for row in topology[group]):
            raise _blocked(f"record-topology-{group}-identity")
    fingerprints = _tuple(topology["fingerprints"], "topology-fingerprints")
    if len(fingerprints) != 3:
        raise _blocked("record-topology-fingerprints")
    retained = {row["issue"] for row in topology["retained"]}
    retained_by_slug = {row["slug"]: row["issue"] for row in topology["retained"]}
    seen_fp: set[str] = set()
    for index, raw in enumerate(fingerprints):
        row = _exact_keys(raw, _FINGERPRINT_KEYS, f"fingerprint-{index}")
        slug = _string(row["slug"], "fingerprint-slug")
        if slug in seen_fp or retained_by_slug.get(slug) != row["modern_issue"]:
            raise _blocked("record-topology-fingerprints")
        _hex(row["fingerprint"], _HEX64, "fingerprint")
        seen_fp.add(slug)
    baseline = _exact_keys(top["prefix_zero_baseline"], {"parent", "parent_comments", "children", "invariant_pr"}, "prefix-zero-baseline")
    _validate_issue_baseline(baseline["parent"], "baseline-parent")
    if baseline["parent"]["issue"] != 2737 or baseline["parent"]["url"] != "https://github.com/aevatarAI/aevatar/issues/2737":
        raise _blocked("record-baseline-parent-identity")
    parent_comments = _tuple(baseline["parent_comments"], "baseline-parent-comments")
    for index, comment in enumerate(parent_comments):
        _validate_comment(comment, f"baseline-parent-comment-{index}")
    parent_by_id = {row["id"]: row for row in baseline["parent"]["comments"]}
    if [row["id"] for row in parent_comments] != [4983244800, 4983315457] or any(parent_by_id.get(row["id"]) != row for row in parent_comments):
        raise _blocked("record-baseline-parent-comments")
    children = _tuple(baseline["children"], "baseline-children")
    if len(children) != 6:
        raise _blocked("record-baseline-children")
    for index, child in enumerate(children):
        _validate_issue_baseline(child, f"baseline-child-{index}")
    if {row["issue"] for row in children} != {row["issue"] for row in identities.values()}:
        raise _blocked("record-baseline-topology")
    if [row["issue"] for row in children] != [2772, 2773, 2774, 2775, 2776, 2777]:
        raise _blocked("record-baseline-child-order")
    if any(row["url"] != f"https://github.com/aevatarAI/aevatar/issues/{row['issue']}" for row in children):
        raise _blocked("record-baseline-child-identity")
    invariant = _exact_keys(baseline["invariant_pr"], _PR_BASELINE_KEYS, "baseline-invariant-pr")
    _positive_int(invariant["number"], "baseline-invariant-pr-number")
    for key in _PR_BASELINE_KEYS - {"number", "draft"}:
        _string(invariant[key], f"baseline-invariant-pr-{key}")
    if not isinstance(invariant["draft"], bool):
        raise _blocked("record-baseline-invariant-pr-draft")
    for key in ("base_sha", "head_sha"):
        _hex(invariant[key], _HEX40, f"baseline-invariant-pr-{key}")
    for key in ("title_sha256", "body_sha256"):
        _hex(invariant[key], _HEX64, f"baseline-invariant-pr-{key}")
    if invariant["number"] != 2752 or invariant["url"] != "https://github.com/aevatarAI/aevatar/pull/2752":
        raise _blocked("record-baseline-invariant-pr-identity")


def parse_occurrence_record(data: bytes, *, now: datetime | None = None) -> Issue2737Occurrence:
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise _blocked("record-encoding")
    try:
        text = data.decode("utf-8")
        raw = json.loads(text, object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _blocked("record-json") from exc
    top = _exact_keys(raw, _TOP_KEYS, "top")
    _reject_forbidden(top)
    canonical = json.dumps(top, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if canonical != data:
        raise _blocked("record-noncanonical")
    if top["contract"] != "issue-2737-reselection-occurrence":
        raise _blocked("record-contract")
    incident = _exact_keys(top["incident"], {"parent_issue", "target_repository", "decision_artifact_sha256", "plan_path", "plan_digest", "plan_comment_id", "tracking_comment_id", "invariant_pr_number"}, "incident")
    if (incident["parent_issue"], incident["target_repository"], incident["plan_comment_id"], incident["tracking_comment_id"], incident["invariant_pr_number"]) != (2737, "aevatarAI/aevatar", 4983244800, 4983315457, 2752):
        raise _blocked("record-incident")
    implementation = _exact_keys(top["implementation"], {"fork_repository", "pr_number", "reviewed_head_sha", "reviewed_tree_oid", "merge_sha", "merge_tree_oid", "bound_files"}, "implementation")
    if implementation["fork_repository"] != "eanz17/consensus-rnd":
        raise _blocked("record-fork")
    authorization = _exact_keys(top["authorization_pr"], {"number", "base_ref", "head_ref", "expected_base_sha"}, "authorization-pr")
    occurrence = _exact_keys(top["occurrence"], {"expected_initial_prefix", "expires_at", "cleanup_required"}, "occurrence")
    if occurrence["expected_initial_prefix"] != 0 or occurrence["cleanup_required"] is not True:
        raise _blocked("record-occurrence")
    for value in (incident["decision_artifact_sha256"], incident["plan_digest"]):
        if not isinstance(value, str) or not _HEX64.fullmatch(value): raise _blocked("record-sha256")
    for value in (implementation["reviewed_head_sha"], implementation["merge_sha"], authorization["expected_base_sha"]):
        if not isinstance(value, str) or not _HEX40.fullmatch(value): raise _blocked("record-sha")
    if authorization["expected_base_sha"] != implementation["merge_sha"]:
        raise _blocked("record-authorization-base")
    for value in (implementation["pr_number"], authorization["number"]):
        _positive_int(value, "pr-number")
    for value in (implementation["reviewed_tree_oid"], implementation["merge_tree_oid"]):
        _string(value, "tree-oid")
    for value in (authorization["base_ref"], authorization["head_ref"], incident["plan_path"]):
        _string(value, "record-reference")
    _validate_nested_record(top)
    try:
        expires = datetime.fromisoformat(str(occurrence["expires_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise _blocked("record-expiry") from exc
    current = now or datetime.now(timezone.utc)
    if expires.tzinfo is None or expires <= current:
        raise _blocked("record-expired")
    return Issue2737Occurrence(top, data, expires)


def _pairs_without_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def validate_singleton_pr_b_changes(api_files: Sequence[Mapping[str, Any]], git_files: Sequence[tuple[str, str, str]]) -> None:
    api = tuple((row.get("filename"), row.get("status"), row.get("previous_filename")) for row in api_files)
    git = tuple(git_files)
    if api != ((_OCCURRENCE_PATH, "added", None),) or git != ((_OCCURRENCE_PATH, "A", "100644"),):
        raise _blocked("authorization-pr-changed-paths")


def next_effect(prefix: int) -> Issue2737Effect | None:
    if isinstance(prefix, bool) or not isinstance(prefix, int) or not 0 <= prefix <= len(ORDER):
        raise _blocked("invalid-prefix")
    return None if prefix == len(ORDER) else ORDER[prefix]


def binding_from_observation(occurrence: Issue2737Occurrence, observation: Mapping[str, Any]) -> Issue2737Binding:
    required = {"record_blob_oid", "prefix", "pr_a", "pr_b", "review", "checks", "checkout", "target", "decomposition"}
    row = _exact_keys(observation, required, "live-observation")
    prefix = row["prefix"]
    next_effect(prefix)
    if row["record_blob_oid"] != row["pr_b"].get("record_blob_oid"):
        raise _blocked("record-blob-drift")
    if not all(bool(row[key].get("admitted")) for key in ("pr_a", "pr_b", "review", "checks", "checkout", "target")):
        raise _blocked("live-admission")
    decomposition = row["decomposition"]
    if not isinstance(decomposition, Mapping) or decomposition.get("is_noop") is not True or decomposition.get("conflicts") not in ([], ()):
        raise _blocked("ordinary-403-not-noop")
    normalized = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    record_digest = hashlib.sha256(b"issue2737-occurrence\0" + occurrence.exact_bytes).hexdigest()
    return Issue2737Binding(record_digest, str(row["record_blob_oid"]), occurrence.expires_at, prefix, hashlib.sha256(normalized).hexdigest())


def validate_live_occurrence(actions: Any) -> Issue2737Binding:
    path = actions.repo_root / _OCCURRENCE_PATH
    try:
        occurrence = parse_occurrence_record(path.read_bytes())
    except OSError as exc:
        raise _blocked("occurrence-record-unavailable") from exc
    observation = actions._issue_2737_live_observation(occurrence)
    return binding_from_observation(occurrence, observation)


def acquire_live_observation(actions: Any, occurrence: Issue2737Occurrence) -> Mapping[str, Any]:
    """Compose existing owner-local projections; this function owns no mutable fact."""
    raw = occurrence.raw
    implementation = raw["implementation"]
    authorization = raw["authorization_pr"]
    pr_a = actions._issue_2737_pr_binding_projection(implementation, authorization=False)
    pr_b = actions._issue_2737_pr_binding_projection(authorization, authorization=True)
    if pr_b.get("base_sha") != implementation["merge_sha"]:
        raise _blocked("authorization-pr-not-based-on-implementation")
    validate_singleton_pr_b_changes(pr_b["api_files"], pr_b["git_files"])
    readiness = actions._issue_2737_pr_readiness(str(implementation["fork_repository"]), int(implementation["pr_number"]))
    checks_admitted = bool(
        readiness.ok
        and readiness.head_sha == implementation["reviewed_head_sha"]
        and not readiness.required_failed
        and not readiness.required_pending
        and not readiness.missing_required
    )
    review = actions._issue_2737_review_projection(implementation)
    authorization_readiness = actions._issue_2737_pr_readiness("eanz17/consensus-rnd", int(authorization["number"]))
    authorization_review = actions._issue_2737_review_projection({"fork_repository": "eanz17/consensus-rnd", "pr_number": authorization["number"], "reviewed_head_sha": pr_b["head_sha"]})
    pr_b_admitted = bool(pr_b["admitted"] and authorization_readiness.ok and authorization_readiness.head_sha == pr_b["head_sha"] and not authorization_readiness.required_failed and not authorization_readiness.required_pending and not authorization_readiness.missing_required and authorization_review["admitted"])
    target = actions._issue_2737_target_projection(raw)
    decomposition = actions._issue_2737_decomposition_projection(raw)
    return {
        "record_blob_oid": pr_b["record_blob_oid"],
        "prefix": target["prefix"],
        "pr_a": {"admitted": bool(pr_a["admitted"])},
        "pr_b": {"admitted": pr_b_admitted, "record_blob_oid": pr_b["record_blob_oid"]},
        "review": {"admitted": bool(review["admitted"])},
        "checks": {"admitted": checks_admitted},
        "checkout": {"admitted": bool(pr_b["checkout_admitted"])},
        "target": {"admitted": bool(target["admitted"])},
        "decomposition": {"is_noop": bool(decomposition.is_noop), "conflicts": list(decomposition.conflicts)},
    }


def literal_effect_target(effect: Issue2737Effect) -> int:
    if effect is Issue2737Effect.M2775: return 2775
    if effect in (Issue2737Effect.O2772, Issue2737Effect.X2772): return 2772
    if effect is Issue2737Effect.M2776: return 2776
    if effect in (Issue2737Effect.O2773, Issue2737Effect.X2773): return 2773
    if effect is Issue2737Effect.M2777: return 2777
    if effect in (Issue2737Effect.O2774, Issue2737Effect.X2774): return 2774
    raise _blocked("unknown-effect")


def _sha256_text(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _flatten_pages(value: Any) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    for page in value if isinstance(value, list) else []:
        for row in page if isinstance(page, list) else [page]:
            if isinstance(row, Mapping):
                rows.append(row)
    return rows


def _live_issue(actions: Any, number: int) -> Mapping[str, Any]:
    issue_result = actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{number}"], check=False)
    comments_result = actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{number}/comments", "--paginate", "--slurp"], check=False)
    reactions_result = actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{number}/reactions", "--paginate", "--slurp"], check=False)
    timeline_result = actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{number}/timeline", "--paginate", "--slurp"], check=False)
    if any(result.returncode != 0 for result in (issue_result, comments_result, reactions_result, timeline_result)):
        raise _blocked("target-read")
    try:
        issue = json.loads(issue_result.stdout)
        comments = _flatten_pages(json.loads(comments_result.stdout or "[]"))
        reactions = _flatten_pages(json.loads(reactions_result.stdout or "[]"))
        timeline = _flatten_pages(json.loads(timeline_result.stdout or "[]"))
    except json.JSONDecodeError as exc:
        raise _blocked("target-json") from exc
    if not isinstance(issue, Mapping):
        raise _blocked("target-json")
    comment_reactions: dict[int, list[Mapping[str, Any]]] = {}
    for comment in comments:
        comment_id = comment.get("id")
        if not isinstance(comment_id, int):
            raise _blocked("target-comment-id")
        result = actions.gh(["api", f"repos/aevatarAI/aevatar/issues/comments/{comment_id}/reactions", "--paginate", "--slurp"], check=False)
        if result.returncode != 0:
            raise _blocked("target-comment-reactions")
        try:
            comment_reactions[comment_id] = _flatten_pages(json.loads(result.stdout or "[]"))
        except json.JSONDecodeError as exc:
            raise _blocked("target-comment-reactions-json") from exc
    return {"issue": issue, "comments": comments, "reactions": reactions, "comment_reactions": comment_reactions, "timeline": timeline}


def _reaction_facts(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    grouped: dict[str, set[str]] = {}
    for row in rows:
        content = str(row.get("content") or "")
        user = row.get("user") if isinstance(row.get("user"), Mapping) else {}
        login = str(user.get("login") or "")
        if not content or not login:
            raise _blocked("target-reaction-shape")
        grouped.setdefault(content, set()).add(login)
    return [{"content": content, "users": sorted(users)} for content, users in sorted(grouped.items())]


def _comment_facts(comment: Mapping[str, Any], reactions: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    return {
        "id": comment.get("id"), "url": str(comment.get("html_url") or ""),
        "author": str((comment.get("user") or {}).get("login") or ""),
        "body_sha256": _sha256_text(comment.get("body")), "created_at": str(comment.get("created_at") or ""),
        "updated_at": str(comment.get("updated_at") or ""),
        "minimized": bool(comment.get("minimized", False)), "reactions": _reaction_facts(reactions),
    }


def _baseline_issue_matches(
    live: Mapping[str, Any], baseline: Mapping[str, Any], allowed_extra_body: str | None, closed: bool
) -> tuple[bool, Mapping[str, Any] | None]:
    issue = live["issue"]
    comments = live["comments"]
    labels = sorted(str(row.get("name") or "") for row in issue.get("labels", []) if isinstance(row, Mapping))
    assignees = sorted(str(row.get("login") or "") for row in issue.get("assignees", []) if isinstance(row, Mapping))
    milestone = issue.get("milestone")
    fixed = (
        issue.get("number") == baseline["issue"], str(issue.get("html_url") or "") == baseline["url"],
        _sha256_text(issue.get("title")) == baseline["title_sha256"], _sha256_text(issue.get("body")) == baseline["body_sha256"],
        str((issue.get("user") or {}).get("login") or "") == baseline["author"], labels == baseline["labels"], assignees == baseline["assignees"],
        ("" if milestone is None else str(milestone)) == baseline["milestone"],
        _reaction_facts(live["reactions"]) == baseline["reactions"],
    )
    if not all(fixed): return False, None
    expected_state = "closed" if closed else baseline["state"]
    expected_reason = "not_planned" if closed else baseline["state_reason"]
    if str(issue.get("state") or "") != expected_state or str(issue.get("state_reason") or "") != expected_reason:
        return False, None
    base_comments = baseline["comments"]
    if len(comments) != len(base_comments) + (1 if allowed_extra_body is not None else 0): return False, None
    for actual, expected in zip(comments[:len(base_comments)], base_comments):
        if _comment_facts(actual, live["comment_reactions"].get(actual.get("id"), ())) != expected:
            return False, None
    if baseline["comment_high_water"] != (max((row.get("id", 0) for row in comments[:len(base_comments)]), default=0)):
        return False, None
    if allowed_extra_body is None: return True, None
    extra = comments[-1]
    comment_id = extra.get("id")
    created = str(extra.get("created_at") or "")
    baseline_cut = max((str(row["created_at"]) for row in base_comments), default="")
    expected_url = f"https://github.com/aevatarAI/aevatar/issues/{baseline['issue']}#issuecomment-{comment_id}"
    valid = (isinstance(comment_id, int) and comment_id > baseline["comment_high_water"]
             and str(extra.get("html_url") or "") == expected_url and created > baseline_cut
             and str(extra.get("body") or "") == allowed_extra_body and str((extra.get("user") or {}).get("login") or "") == "eanz17"
             and str(extra.get("created_at") or "") == str(extra.get("updated_at") or "")
             and not bool(extra.get("minimized", False)) and not live["comment_reactions"].get(extra.get("id")))
    post_cut = [row for row in live["timeline"] if str(row.get("created_at") or "") > baseline_cut]
    if closed:
        valid = (valid and len(post_cut) == 1 and post_cut[0].get("event") == "closed"
                 and str(post_cut[0].get("created_at") or "") > created
                 and str((post_cut[0].get("actor") or {}).get("login") or "") == "eanz17")
    else:
        valid = valid and not post_cut
    if not valid:
        return False, None
    return True, {"comment": extra, "close": post_cut[0] if closed else None}


def _effect_requests() -> tuple[tuple[int, str | None, bool], ...]:
    calls: list[list[str]] = []
    class Recorder:
        def gh(self, argv: Sequence[str], *, check: bool = False) -> Any:
            calls.append(list(argv))
            return type("Result", (), {"returncode": 0})()
    port = LiteralIssue2737Port(Recorder())
    for effect in ORDER: port.invoke(effect)
    result: list[tuple[int, str | None, bool]] = []
    for argv in calls:
        target = int(argv[1].split("/issues/")[1].split("/")[0])
        body = argv[-1][5:] if argv[3] == "POST" else None
        result.append((target, body, argv[3] == "PATCH"))
    return tuple(result)


def read_target_projection(actions: Any, raw: Mapping[str, Any]) -> Mapping[str, Any]:
    baseline = raw["prefix_zero_baseline"]
    parent_ok, _ = _baseline_issue_matches(_live_issue(actions, int(baseline["parent"]["issue"])), baseline["parent"], None, False)
    if not parent_ok:
        raise _blocked("parent-drift")
    invariant = baseline["invariant_pr"]
    pr_result = actions.gh(["api", f"repos/aevatarAI/aevatar/pulls/{invariant['number']}"], check=False)
    if pr_result.returncode != 0:
        raise _blocked("invariant-pr-read")
    try:
        pr = json.loads(pr_result.stdout)
    except json.JSONDecodeError as exc:
        raise _blocked("invariant-pr-json") from exc
    base = pr.get("base") if isinstance(pr, Mapping) and isinstance(pr.get("base"), Mapping) else {}
    head = pr.get("head") if isinstance(pr, Mapping) and isinstance(pr.get("head"), Mapping) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), Mapping) else {}
    head_repo = head.get("repo") if isinstance(head.get("repo"), Mapping) else {}
    pr_facts = {
        "number": pr.get("number"), "url": str(pr.get("html_url") or ""), "state": str(pr.get("state") or ""), "draft": pr.get("draft"),
        "base_repository": str(base_repo.get("full_name") or ""), "base_ref": str(base.get("ref") or ""), "base_sha": str(base.get("sha") or ""),
        "head_repository": str(head_repo.get("full_name") or ""), "head_ref": str(head.get("ref") or ""), "head_sha": str(head.get("sha") or ""),
        "title_sha256": _sha256_text(pr.get("title")), "body_sha256": _sha256_text(pr.get("body")),
    }
    if pr_facts != dict(invariant):
        raise _blocked("invariant-pr-drift")
    live = {int(row["issue"]): _live_issue(actions, int(row["issue"])) for row in baseline["children"]}
    requests = _effect_requests()
    matching: list[int] = []
    for prefix in range(len(ORDER) + 1):
        added = {target: body for target, body, closed in requests[:prefix] if body is not None}
        closed = {target for target, body, is_close in requests[:prefix] if is_close}
        observed: dict[int, Mapping[str, Any]] = {}
        valid = True
        for child in baseline["children"]:
            ok, events = _baseline_issue_matches(live[int(child["issue"])], child, added.get(int(child["issue"])), int(child["issue"]) in closed)
            valid = valid and ok
            if events is not None: observed[int(child["issue"])] = events
        if valid:
            chronology: list[str] = []
            for target, body, is_close in requests[:prefix]:
                event = observed[target]["close" if is_close else "comment"]
                chronology.append(str(event.get("created_at") or ""))
            if len(set(chronology)) == len(chronology) and chronology == sorted(chronology):
                matching.append(prefix)
    if len(matching) != 1:
        raise _blocked("target-non-prefix")
    return {"admitted": True, "prefix": matching[0]}


class LiteralIssue2737Port:
    """The only target-writing port; every branch is a complete literal request."""

    def __init__(self, actions: Any) -> None:
        self._actions = actions

    def invoke(self, effect: Issue2737Effect) -> Any:
        if effect is Issue2737Effect.M2775:
            return self._post(2775, "Recovery reselection for parent #2737: this fingerprinted, helper-tracked issue remains the canonical `materialize-nyxid-authorization-evidence` child for plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nLegacy duplicate #2772 is retained as closed AI-generated audit history. Its comments are not copied or adopted here. Canonical identity remains the existing tracking record in parent comment 4983315457.\n\nReason: preserve the modern helper-tracked fingerprinted child and retire the pre-tracking duplicate.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.O2772:
            return self._post(2772, "Recovery reselection for parent #2737: this pre-tracking issue is superseded by canonical child #2775 for `materialize-nyxid-authorization-evidence`, plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nThis issue is closed as legacy audit history. All existing comments are AI-generated design records and remain unchanged; none are copied to #2775. Canonical identity is the fingerprinted issue recorded in parent comment 4983315457.\n\nReason: superseded legacy duplicate created before modern decomposition tracking completed.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.X2772: return self._close(2772)
        if effect is Issue2737Effect.M2776:
            return self._post(2776, "Recovery reselection for parent #2737: this fingerprinted, helper-tracked issue remains the canonical `derive-scheduled-authorization-plan` child for plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nLegacy duplicate #2773 is retained as closed AI-generated audit history. Its comments are not copied or adopted here. Canonical identity remains the existing tracking record in parent comment 4983315457.\n\nReason: preserve the modern helper-tracked fingerprinted child and retire the pre-tracking duplicate.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.O2773:
            return self._post(2773, "Recovery reselection for parent #2737: this pre-tracking issue is superseded by canonical child #2776 for `derive-scheduled-authorization-plan`, plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nThis issue is closed as legacy audit history. All existing comments are AI-generated design records and remain unchanged; none are copied to #2776. Canonical identity is the fingerprinted issue recorded in parent comment 4983315457.\n\nReason: superseded legacy duplicate created before modern decomposition tracking completed.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.X2773: return self._close(2773)
        if effect is Issue2737Effect.M2777:
            return self._post(2777, "Recovery reselection for parent #2737: this fingerprinted, helper-tracked issue remains the canonical `integrate-scheduled-authorization-effects` child for plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nLegacy duplicate #2774 is retained as closed AI-generated audit history. Its comments are not copied or adopted here. Canonical identity remains the existing tracking record in parent comment 4983315457.\n\nReason: preserve the modern helper-tracked fingerprinted child and retire the pre-tracking duplicate.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.O2774:
            return self._post(2774, "Recovery reselection for parent #2737: this pre-tracking issue is superseded by canonical child #2777 for `integrate-scheduled-authorization-effects`, plan digest `20ab1fa90a1ac355b777422718d15c8e819a5756ad03c383ced8fd7a113af1e5`.\n\nThis issue is closed as legacy audit history. All existing comments are AI-generated design records and remain unchanged; none are copied to #2777. Canonical identity is the fingerprinted issue recorded in parent comment 4983315457.\n\nReason: superseded legacy duplicate created before modern decomposition tracking completed.\n\n\u27e6AI:AUTO-LOOP\u27e7\n")
        if effect is Issue2737Effect.X2774: return self._close(2774)
        raise _blocked("unknown-effect")

    def _post(self, issue: int, body: str) -> Any:
        return self._actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{issue}/comments", "-X", "POST", "-f", f"body={body}"], check=False)

    def _close(self, issue: int) -> Any:
        return self._actions.gh(["api", f"repos/aevatarAI/aevatar/issues/{issue}", "-X", "PATCH", "-f", "state=closed", "-f", "state_reason=not_planned"], check=False)


class Issue2737Recovery:
    """Private bridge. PR B absence makes this branch verify-only and fail closed."""

    def __init__(self, actions: Any) -> None:
        self._actions = actions

    def run(self, *, verify_only: bool = False) -> int:
        first = self._actions._validate_issue_2737_occurrence()
        second = self._actions._validate_issue_2737_occurrence()
        if first != second:
            raise _blocked("binding-drift")
        effect = next_effect(second.prefix)
        if effect is None or verify_only:
            return second.prefix
        fresh = self._actions._validate_issue_2737_occurrence()
        if fresh != second:
            raise _blocked("pre-effect-drift")
        self._actions._revalidate_issue_2737_effect_admission(effect)
        ambiguous: BaseException | None = None
        try:
            result = LiteralIssue2737Port(self._actions).invoke(effect)
            if getattr(result, "returncode", 1) != 0:
                ambiguous = _blocked(f"transport-ambiguous-{effect.value}")
        except BaseException as exc:
            ambiguous = exc
        try:
            after = self._actions._validate_issue_2737_occurrence()
        except BaseException as exc:
            raise _blocked(f"ambiguous-refetch-{effect.value}" if ambiguous else f"response-loss-{effect.value}") from exc
        if after.prefix != fresh.prefix + 1:
            raise _blocked(f"ambiguous-prefix-{effect.value}" if ambiguous else f"response-loss-{effect.value}")
        return after.prefix
