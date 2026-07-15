"""Helper-private async publish verification jobs and receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from .context import parse_host_env
from .processes import run_fixed_host_command


VERIFY_VERSION = 2
VERIFY_COMMANDS = ("BUILD_CMD", "TEST_CMD")
PUBLISHED_RECEIPT_MAX_BYTES = 16 * 1024
RETRY_DELAYS_SECONDS = (1800, 7200, 28800)
REQUEST_SCHEMA = "PublishVerificationRequest"
RESULT_SCHEMA = "PublishVerificationResult"
REQUEST_KEYS = frozenset({
    "schema", "version", "job_key", "issue", "action", "head_ref", "base_branch",
    "worktree", "candidate_sha", "verified_sha", "gate_id", "command_digest",
    "checkpoint_hashes", "commands", "host_env_locator", "private_ref",
})
RESULT_BASE_KEYS = frozenset({
    "schema", "version", "status", "reason", "job_key", "verified_sha", "gate_id",
    "command_digest", "checkpoint_hashes", "private_ref", "commands",
})
RESULT_MINIMAL_FAILED_KEYS = frozenset({"schema", "version", "status", "reason", "job_key", "verified_sha"})
COMMAND_RECEIPT_KEYS = frozenset({"name", "command_sha256", "exit", "log", "exit_marker"})

GitRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _is_writer_timestamp(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value > 0
    )


@dataclass(frozen=True)
class PublishVerificationJobResult:
    status: str
    reason: str
    job_dir: Path
    job_key: str
    candidate_sha: str

    @property
    def ok(self) -> bool:
        return self.status == "verified"


@dataclass(frozen=True)
class PublishVerificationReceiptValidation:
    status: str
    reason: str
    job_dir: Path
    job_key: str
    verified_sha: str = ""
    issue: str = ""
    base_branch: str = ""
    head_ref: str = ""
    private_ref: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "verified"


@dataclass(frozen=True)
class PublishVerificationPublishedValidation:
    status: str
    reason: str
    job_dir: Path
    job_key: str
    verified_sha: str = ""
    pr_number: int | None = None
    remote_oid: str = ""
    issue: str = ""
    base_branch: str = ""
    head_ref: str = ""
    private_ref: str = ""
    receipt_digest: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "published"


@dataclass(frozen=True)
class PublishVerificationRetryStatus:
    state: str
    reason: str
    failure_count: int
    next_retry_after_epoch: float | None

    @property
    def retry_now(self) -> bool:
        return self.state in {"READY", "NO_RETRY"}


def command_digest(env: Mapping[str, str], names: Sequence[str] = VERIFY_COMMANDS) -> str:
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(env.get(name) or "").strip().encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def string_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def jobs_root(repo_root: Path) -> Path:
    return repo_root / ".refactor-loop" / "state" / "publish-verification" / "jobs"


def prepare_or_schedule(
    *,
    repo_root: Path,
    worktree: Path,
    issue: str,
    action: str,
    head_ref: str,
    base_branch: str,
    candidate_sha: str,
    env: Mapping[str, str],
    git_runner: GitRunner | None = None,
    start_child: bool = True,
) -> PublishVerificationJobResult:
    repo_root = repo_root.resolve()
    worktree = worktree.resolve()
    request = build_request(
        repo_root=repo_root,
        worktree=worktree,
        issue=issue,
        action=action,
        head_ref=head_ref,
        base_branch=base_branch,
        candidate_sha=candidate_sha,
        env=env,
    )
    job_dir = jobs_root(repo_root) / str(request["job_key"])
    git = git_runner or _repo_git(repo_root)
    missing = _missing_commands(request)
    if missing:
        return PublishVerificationJobResult("failed", f"missing-{missing}", job_dir, str(request["job_key"]), candidate_sha)
    _supersede_unpublished_jobs(repo_root, request)
    job_dir.mkdir(parents=True, exist_ok=True)
    request_path = job_dir / "request.json"
    if request_path.exists():
        existing = _read_json(request_path, {})
        if existing != request:
            return PublishVerificationJobResult("failed", "request-mismatch", job_dir, str(request["job_key"]), candidate_sha)
    else:
        _write_json(request_path, request)
    pinned = git(["update-ref", str(request["private_ref"]), candidate_sha])
    if pinned.returncode != 0:
        return PublishVerificationJobResult("failed", "private-ref-pin-failed", job_dir, str(request["job_key"]), candidate_sha)
    receipt = validate_verified_receipt(job_dir, env=env, git_runner=git)
    if receipt.ok:
        retry = current_retry_status(job_dir)
        if retry.state == "RETRY_WAIT":
            return PublishVerificationJobResult("waiting", "retry-wait", job_dir, str(request["job_key"]), candidate_sha)
        if retry.state == "QUARANTINED":
            return PublishVerificationJobResult("failed", "quarantined", job_dir, str(request["job_key"]), candidate_sha)
        return PublishVerificationJobResult("verified", "verified", job_dir, str(request["job_key"]), candidate_sha)
    if receipt.status == "pending" and receipt.reason != "result-missing":
        return PublishVerificationJobResult("queued", receipt.reason, job_dir, str(request["job_key"]), candidate_sha)
    if (job_dir / "result.json").exists():
        existing_retry = current_retry_status(job_dir)
        if existing_retry.state == "RETRY_WAIT":
            return PublishVerificationJobResult("waiting", "retry-wait", job_dir, str(request["job_key"]), candidate_sha)
        if existing_retry.state == "QUARANTINED":
            return PublishVerificationJobResult("failed", "quarantined", job_dir, str(request["job_key"]), candidate_sha)
        if existing_retry.state == "READY":
            _archive_result_for_retry(job_dir)
        else:
            retry = record_failed_receipt_retry(job_dir)
            return PublishVerificationJobResult(
                "waiting" if retry.state == "RETRY_WAIT" else "failed",
                retry.reason,
                job_dir,
                str(request["job_key"]),
                candidate_sha,
            )
    if (job_dir / "result.json").exists():
        retry = record_failed_receipt_retry(job_dir)
        return PublishVerificationJobResult(
            "waiting" if retry.state == "RETRY_WAIT" else "failed",
            retry.reason,
            job_dir,
            str(request["job_key"]),
            candidate_sha,
        )
    if not start_child:
        return PublishVerificationJobResult("queued", "not-started", job_dir, str(request["job_key"]), candidate_sha)
    if _slot_busy(repo_root):
        return PublishVerificationJobResult("queued", "slot-busy", job_dir, str(request["job_key"]), candidate_sha)
    _mark_slot(repo_root, job_dir)
    try:
        _start_hidden_child(repo_root, job_dir, env)
    except OSError:
        _clear_slot(repo_root, job_dir)
        return PublishVerificationJobResult("failed", "child-start-failed", job_dir, str(request["job_key"]), candidate_sha)
    return PublishVerificationJobResult("queued", "started", job_dir, str(request["job_key"]), candidate_sha)


def build_request(
    *,
    repo_root: Path,
    worktree: Path,
    issue: str,
    action: str,
    head_ref: str,
    base_branch: str,
    candidate_sha: str,
    env: Mapping[str, str],
) -> dict[str, Any]:
    checkpoint_hashes = _checkpoint_hashes(env)
    digest = command_digest(env)
    gate_id = string_digest(f"{action}\0{digest}")
    worktree_rel = _repo_relative(repo_root, worktree)
    host_env_locator = str(env.get("CONSENSUS_RND_HOST_ENV") or "")
    key_payload = {
        "issue": str(issue),
        "action": str(action),
        "head_ref": str(head_ref),
        "base_branch": str(base_branch),
        "candidate_sha": str(candidate_sha),
        "gate_id": gate_id,
        "command_digest": digest,
    }
    job_key = string_digest(json.dumps(key_payload, sort_keys=True, separators=(",", ":")))[:32]
    return {
        "schema": REQUEST_SCHEMA,
        "version": VERIFY_VERSION,
        "job_key": job_key,
        "issue": str(issue),
        "action": str(action),
        "head_ref": str(head_ref),
        "base_branch": str(base_branch),
        "worktree": worktree_rel,
        "candidate_sha": str(candidate_sha),
        "verified_sha": str(candidate_sha),
        "gate_id": gate_id,
        "command_digest": digest,
        "checkpoint_hashes": checkpoint_hashes,
        "commands": {name: str(env.get(name) or "").strip() for name in VERIFY_COMMANDS},
        "host_env_locator": host_env_locator,
        "private_ref": f"refs/consensus/publish/{job_key}",
    }


def run_one_publish_ratchet(job_dir: Path, *, git_runner: GitRunner | None = None) -> int:
    job_dir = job_dir.resolve()
    request = _read_request(job_dir)
    repo_root = _repo_root_from_job_dir(job_dir)
    private_git = git_runner or _repo_git(repo_root)
    worktree = _artifact_path(repo_root, str(request["worktree"]))
    worktree_git = git_runner or _repo_git(worktree)
    if (job_dir / "superseded.json").exists():
        _write_result(job_dir, _failed_result(request, "superseded"))
        _clear_slot(repo_root, job_dir)
        return 3
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "version": VERIFY_VERSION,
        "status": "RUNNING",
        "reason": "running",
        "job_key": request["job_key"],
        "verified_sha": request["verified_sha"],
        "gate_id": request["gate_id"],
        "command_digest": request["command_digest"],
        "checkpoint_hashes": request["checkpoint_hashes"],
        "private_ref": request["private_ref"],
        "commands": [],
    }
    _write_result(job_dir, payload)
    env = _env_for_child(repo_root, request)
    try:
        ok, reason, tested_sha = _verify_worktree_subject(worktree_git, str(request.get("candidate_sha") or ""))
        payload["tested_sha"] = tested_sha
        if not ok:
            payload.update({"status": "FAILED", "reason": reason})
            _write_result(job_dir, payload)
            return 3
        for name in VERIFY_COMMANDS:
            command = str(request["commands"].get(name) or "").strip()
            if not command:
                payload.update({"status": "FAILED", "reason": f"missing-{name}"})
                _write_result(job_dir, payload)
                return 3
            log = job_dir / f"{name}.log"
            exit_code = run_fixed_host_command(command, cwd=worktree, env=env, log=log)
            command_record = {
                "name": name,
                "command_sha256": string_digest(command),
                "exit": exit_code,
                "log": _repo_relative(repo_root, log),
                "exit_marker": _log_has_exit_zero(log),
            }
            payload["commands"].append(command_record)
            _write_result(job_dir, payload)
            if exit_code != 0 or command_record["exit_marker"] is not True:
                payload.update({"status": "FAILED", "reason": f"{name}-failed:{exit_code}"})
                _write_result(job_dir, payload)
                return 3
        ok, reason, post_tested_sha = _verify_worktree_subject(worktree_git, str(request.get("candidate_sha") or ""))
        payload["post_tested_sha"] = post_tested_sha
        if not ok:
            payload.update({"status": "FAILED", "reason": reason})
            _write_result(job_dir, payload)
            return 3
        private_ref_oid = _private_ref_oid(private_git, str(request["private_ref"]))
        if private_ref_oid != request.get("candidate_sha"):
            payload.update({"status": "FAILED", "reason": "private-ref-mismatch", "private_ref_oid": private_ref_oid})
            _write_result(job_dir, payload)
            return 3
        payload.update(
            {
                "status": "VERIFIED",
                "reason": "verified",
                "private_ref_oid": private_ref_oid,
                "completed_at_epoch": time.time(),
            }
        )
        _write_result(job_dir, payload)
        return 0
    finally:
        _clear_slot(repo_root, job_dir)


def validate_verified_receipt(
    job_dir: Path,
    *,
    env: Mapping[str, str],
    git_runner: GitRunner | None = None,
) -> PublishVerificationReceiptValidation:
    job_dir = job_dir.resolve()
    request = _read_json(job_dir / "request.json", {})
    result_path = job_dir / "result.json"
    result = _read_json(result_path, {})
    job_key = str(request.get("job_key") or "")
    if (not isinstance(request, dict) or set(request) != REQUEST_KEYS
            or request.get("schema") != REQUEST_SCHEMA or not job_key):
        return PublishVerificationReceiptValidation("failed", "request-invalid", job_dir, job_key)
    key_payload = {
        "issue": request.get("issue"), "action": request.get("action"),
        "head_ref": request.get("head_ref"), "base_branch": request.get("base_branch"),
        "candidate_sha": request.get("candidate_sha"),
        "gate_id": request.get("gate_id"), "command_digest": request.get("command_digest"),
    }
    expected_job_key = string_digest(json.dumps(key_payload, sort_keys=True, separators=(",", ":")))[:32]
    if job_key != expected_job_key or job_dir.name != job_key:
        return PublishVerificationReceiptValidation("failed", "job-key-mismatch", job_dir, job_key)
    if (job_dir / "superseded.json").exists():
        return PublishVerificationReceiptValidation("failed", "superseded", job_dir, job_key)
    if not result_path.exists():
        return PublishVerificationReceiptValidation("pending", "result-missing", job_dir, job_key)
    if (not isinstance(result, dict) or result.get("schema") != RESULT_SCHEMA
            or not _result_keys_are_canonical(result)):
        return PublishVerificationReceiptValidation("failed", "result-invalid", job_dir, job_key)
    if result.get("status") == "RUNNING":
        return PublishVerificationReceiptValidation("pending", "running", job_dir, job_key)
    if result.get("status") != "VERIFIED":
        return PublishVerificationReceiptValidation("failed", str(result.get("reason") or "not-verified"), job_dir, job_key)
    if not _is_writer_timestamp(result.get("completed_at_epoch")):
        return PublishVerificationReceiptValidation("failed", "completed-at-invalid", job_dir, job_key)
    for key in ("job_key", "verified_sha", "gate_id", "command_digest", "checkpoint_hashes", "private_ref"):
        if result.get(key) != request.get(key):
            return PublishVerificationReceiptValidation("failed", f"{key}-mismatch", job_dir, job_key)
    if command_digest(env) != request.get("command_digest"):
        return PublishVerificationReceiptValidation("failed", "command-digest-mismatch", job_dir, job_key)
    if _checkpoint_hashes(env) != request.get("checkpoint_hashes"):
        return PublishVerificationReceiptValidation("failed", "checkpoint-hashes-mismatch", job_dir, job_key)
    if _command_receipts_valid(result.get("commands"), request.get("checkpoint_hashes")) is not True:
        return PublishVerificationReceiptValidation("failed", "command-receipts-invalid", job_dir, job_key)
    candidate_sha = request.get("candidate_sha")
    if not _is_full_sha(candidate_sha) or request.get("verified_sha") != candidate_sha:
        return PublishVerificationReceiptValidation("failed", "request-sha-mismatch", job_dir, job_key)
    if result.get("tested_sha") != candidate_sha or result.get("post_tested_sha") != candidate_sha:
        return PublishVerificationReceiptValidation("failed", "tested-sha-mismatch", job_dir, job_key)
    git = git_runner or _repo_git(_repo_root_from_job_dir(job_dir))
    private_oid = _private_ref_oid(git, str(request["private_ref"]))
    if private_oid != candidate_sha or result.get("private_ref_oid") != private_oid:
        return PublishVerificationReceiptValidation("failed", "private-ref-mismatch", job_dir, job_key)
    issue = request.get("issue")
    base_branch = request.get("base_branch")
    head_ref = request.get("head_ref")
    private_ref = request.get("private_ref")
    if (not isinstance(issue, str) or not issue or not isinstance(base_branch, str) or not base_branch
            or not isinstance(head_ref, str) or not head_ref or not isinstance(private_ref, str) or not private_ref):
        return PublishVerificationReceiptValidation("failed", "request-identity-invalid", job_dir, job_key)
    return PublishVerificationReceiptValidation(
        "verified", "verified", job_dir, job_key, str(request["verified_sha"]),
        issue, base_branch, head_ref, private_ref,
    )


def validate_published_receipt(
    job_dir: Path,
    *,
    env: Mapping[str, str],
    git_runner: GitRunner | None = None,
) -> PublishVerificationPublishedValidation:
    verified = validate_verified_receipt(job_dir, env=env, git_runner=git_runner)
    if not verified.ok:
        return PublishVerificationPublishedValidation(
            "failed", f"verified-receipt-{verified.reason}", verified.job_dir, verified.job_key,
        )
    state, row, receipt_digest = _read_published_receipt(verified.job_dir)
    if state == "MISSING":
        return PublishVerificationPublishedValidation(
            "verified", "published-missing", verified.job_dir, verified.job_key,
            verified.verified_sha, None, "", verified.issue, verified.base_branch,
            verified.head_ref, verified.private_ref,
        )
    if state != "VALID":
        return PublishVerificationPublishedValidation("failed", "published-invalid", verified.job_dir, verified.job_key)
    expected_keys = {"schema", "pr_number", "remote_oid", "published_at_epoch"}
    if not isinstance(row, dict) or set(row) != expected_keys or row.get("schema") != "PublishVerificationPublished":
        return PublishVerificationPublishedValidation("failed", "published-invalid", verified.job_dir, verified.job_key)
    pr_number = row.get("pr_number")
    published_at = row.get("published_at_epoch")
    if (isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0
            or not _is_writer_timestamp(published_at)
            or row.get("remote_oid") != verified.verified_sha):
        return PublishVerificationPublishedValidation("failed", "published-binding-invalid", verified.job_dir, verified.job_key)
    return PublishVerificationPublishedValidation(
        "published", "published", verified.job_dir, verified.job_key,
        verified.verified_sha, pr_number, str(row["remote_oid"]), verified.issue,
        verified.base_branch, verified.head_ref, verified.private_ref, receipt_digest,
    )


def record_failed_receipt_retry(job_dir: Path, *, now: float | None = None) -> PublishVerificationRetryStatus:
    result = _read_json(job_dir / "result.json", {})
    reason = str(result.get("reason") or "failed") if isinstance(result, dict) else "failed"
    return record_job_retry(job_dir, f"failed:{reason}", now=now)


def record_job_retry(job_dir: Path, reason: str, *, now: float | None = None) -> PublishVerificationRetryStatus:
    now_value = time.time() if now is None else now
    path = job_dir / "retry.json"
    previous = _read_json(path, {})
    old_count = previous.get("failure_count") if isinstance(previous, dict) else 0
    failure_count = (old_count if isinstance(old_count, int) and old_count > 0 else 0) + 1
    if failure_count > len(RETRY_DELAYS_SECONDS):
        payload = {
            "state": "QUARANTINED",
            "reason": reason,
            "failure_count": failure_count,
            "next_retry_after_epoch": None,
            "updated_at_epoch": now_value,
        }
        _write_json(path, payload)
        return PublishVerificationRetryStatus("QUARANTINED", reason, failure_count, None)
    delay = RETRY_DELAYS_SECONDS[failure_count - 1]
    next_retry = now_value + delay
    payload = {
        "state": "RETRY_WAIT",
        "reason": reason,
        "failure_count": failure_count,
        "next_retry_after_epoch": next_retry,
        "updated_at_epoch": now_value,
    }
    _write_json(path, payload)
    return PublishVerificationRetryStatus("RETRY_WAIT", reason, failure_count, next_retry)


def current_retry_status(job_dir: Path, *, now: float | None = None) -> PublishVerificationRetryStatus:
    payload = _read_json(job_dir / "retry.json", {})
    if not isinstance(payload, dict) or not payload:
        return PublishVerificationRetryStatus("NO_RETRY", "", 0, None)
    state = str(payload.get("state") or "")
    count = payload.get("failure_count")
    failure_count = count if isinstance(count, int) and count > 0 else 0
    reason = str(payload.get("reason") or "")
    if state == "QUARANTINED":
        return PublishVerificationRetryStatus("QUARANTINED", reason, failure_count, None)
    next_retry = payload.get("next_retry_after_epoch")
    if state == "RETRY_WAIT" and isinstance(next_retry, (int, float)):
        now_value = time.time() if now is None else now
        if now_value < float(next_retry):
            return PublishVerificationRetryStatus("RETRY_WAIT", reason, failure_count, float(next_retry))
        return PublishVerificationRetryStatus("READY", reason, failure_count, None)
    return PublishVerificationRetryStatus("NO_RETRY", "", 0, None)


def mark_published(
    job_dir: Path,
    *,
    pr_number: int,
    verified_sha: str,
    env: Mapping[str, str],
    git_runner: GitRunner | None = None,
) -> None:
    verified = validate_verified_receipt(job_dir, env=env, git_runner=git_runner)
    if (not verified.ok or verified.verified_sha != verified_sha
            or isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0):
        raise RuntimeError("publication receipt identity is not verified")

    payload = {
        "schema": "PublishVerificationPublished",
        "pr_number": pr_number,
        "remote_oid": verified_sha,
        "published_at_epoch": time.time(),
    }
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    expected_digest = hashlib.sha256(encoded).hexdigest()
    dir_fd = _open_published_directory(verified.job_dir)
    fd, temporary_name = tempfile.mkstemp(prefix=".published.", dir=verified.job_dir)
    temporary_path = Path(temporary_name)
    created = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path.name, "published.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                    follow_symlinks=False)
            os.fsync(dir_fd)
            created = True
        except FileExistsError:
            published = validate_published_receipt(verified.job_dir, env=env, git_runner=git_runner)
            if not published.ok or published.pr_number != pr_number or published.remote_oid != verified_sha:
                raise RuntimeError("existing publication receipt conflicts with verified identity")
        published = validate_published_receipt(verified.job_dir, env=env, git_runner=git_runner)
        if (not published.ok or published.pr_number != pr_number or published.remote_oid != verified_sha
                or (created and published.receipt_digest != expected_digest)):
            raise RuntimeError("publication receipt postvalidation failed")
    finally:
        temporary_path.unlink(missing_ok=True)
        os.close(dir_fd)
    (job_dir / "retry.json").unlink(missing_ok=True)


def _open_published_directory(job_dir: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("published receipt no-follow support unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        before = os.stat(job_dir, follow_symlinks=False)
        fd = os.open(job_dir, flags)
        opened = os.fstat(fd)
        after = os.stat(job_dir, follow_symlinks=False)
        if (not stat.S_ISDIR(opened.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)):
            raise RuntimeError("published receipt directory identity changed")
        return fd
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise


def _read_published_receipt(job_dir: Path) -> tuple[str, dict[str, Any], str]:
    """Read the sole receipt basename without following or accepting object races."""
    try:
        dir_fd = _open_published_directory(job_dir)
    except (OSError, RuntimeError):
        return "INVALID", {}, ""
    try:
        try:
            before = os.stat("published.json", dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "MISSING", {}, ""
        except OSError:
            return "INVALID", {}, ""
        if not stat.S_ISREG(before.st_mode):
            return "INVALID", {}, ""
        try:
            fd = os.open("published.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:
            return "INVALID", {}, ""
        try:
            opened = os.fstat(fd)
            if ((before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
                    != (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode))
                    or not stat.S_ISREG(opened.st_mode)):
                return "INVALID", {}, ""
            data = b""
            while len(data) <= PUBLISHED_RECEIPT_MAX_BYTES:
                chunk = os.read(fd, PUBLISHED_RECEIPT_MAX_BYTES + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            finished = os.fstat(fd)
        except OSError:
            return "INVALID", {}, ""
        finally:
            os.close(fd)
        try:
            final = os.stat("published.json", dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return "INVALID", {}, ""
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (not data or len(data) > PUBLISHED_RECEIPT_MAX_BYTES
                or any(getattr(opened, key) != getattr(finished, key) for key in stable_fields)
                or (final.st_dev, final.st_ino, stat.S_IFMT(final.st_mode), final.st_size)
                != (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode), opened.st_size)):
            return "INVALID", {}, ""
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            row: dict[str, Any] = {}
            for key, value in pairs:
                if key in row:
                    raise ValueError("duplicate key")
                row[key] = value
            return row
        row = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
        if not isinstance(row, dict):
            return "INVALID", {}, ""
        return "VALID", row, hashlib.sha256(data).hexdigest()
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return "INVALID", {}, ""
    finally:
        os.close(dir_fd)


def evidence_path(repo_root: Path, issue: str, head_ref: str) -> Path:
    safe_head = head_ref.replace("/", "__")
    return repo_root / ".refactor-loop" / "state" / "publish-verification" / f"issue-{issue}-{safe_head}.json"


def _missing_commands(request: Mapping[str, Any]) -> str:
    commands = request.get("commands")
    if not isinstance(commands, Mapping):
        return "commands"
    for name in VERIFY_COMMANDS:
        if not str(commands.get(name) or "").strip():
            return name
    return ""


def _supersede_unpublished_jobs(repo_root: Path, request: Mapping[str, Any]) -> None:
    root = jobs_root(repo_root)
    if not root.is_dir():
        return
    for path in root.glob("*/request.json"):
        old = _read_json(path, {})
        if not isinstance(old, dict):
            continue
        if old.get("job_key") == request.get("job_key"):
            continue
        if old.get("issue") != request.get("issue") or old.get("head_ref") != request.get("head_ref"):
            continue
        if (path.parent / "published.json").exists():
            continue
        _write_json(
            path.parent / "superseded.json",
            {
                "schema": "PublishVerificationSuperseded",
                "superseded_by": request.get("job_key"),
                "candidate_sha": request.get("candidate_sha"),
                "gate_id": request.get("gate_id"),
                "superseded_at_epoch": time.time(),
            },
        )


def _start_hidden_child(repo_root: Path, job_dir: Path, env: Mapping[str, str]) -> None:
    cli = Path(__file__).resolve().parents[1] / "consensus-rnd-cli"
    child_env = dict(os.environ)
    child_env.update(env)
    child_env["REPO_ROOT"] = str(repo_root)
    subprocess.Popen(
        [str(cli), "publish-verification-worker", str(job_dir)],
        cwd=str(repo_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=child_env,
    )


def _slot_path(repo_root: Path) -> Path:
    return repo_root / ".refactor-loop" / "state" / "publish-verification" / "active-child.json"


def _slot_busy(repo_root: Path) -> bool:
    payload = _read_json(_slot_path(repo_root), {})
    if not isinstance(payload, dict) or not payload.get("job_dir"):
        return False
    job_dir = Path(str(payload["job_dir"]))
    return not (job_dir / "result.json").exists()


def _mark_slot(repo_root: Path, job_dir: Path) -> None:
    _write_json(_slot_path(repo_root), {"job_dir": str(job_dir), "started_at_epoch": time.time()})


def _clear_slot(repo_root: Path, job_dir: Path) -> None:
    path = _slot_path(repo_root)
    payload = _read_json(path, {})
    if isinstance(payload, dict) and str(payload.get("job_dir") or "") == str(job_dir):
        path.unlink(missing_ok=True)


def _read_request(job_dir: Path) -> dict[str, Any]:
    request = _read_json(job_dir / "request.json", {})
    if not isinstance(request, dict) or request.get("schema") != REQUEST_SCHEMA:
        raise RuntimeError(f"publish verification request invalid: {job_dir}")
    return request


def _failed_result(request: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "version": VERIFY_VERSION,
        "status": "FAILED",
        "reason": reason,
        "job_key": request.get("job_key"),
        "verified_sha": request.get("verified_sha"),
    }


def _write_result(job_dir: Path, payload: Mapping[str, Any]) -> None:
    _write_json(job_dir / "result.json", payload)


def _archive_result_for_retry(job_dir: Path) -> None:
    result = job_dir / "result.json"
    if not result.exists():
        return
    retry = current_retry_status(job_dir)
    target = job_dir / f"result-retry-{retry.failure_count}-{int(time.time() * 1000)}.json"
    os.replace(result, target)


def _checkpoint_hashes(env: Mapping[str, str]) -> dict[str, str]:
    return {name: string_digest(str(env.get(name) or "").strip()) for name in VERIFY_COMMANDS}


def _command_receipts_valid(commands: object, checkpoint_hashes: object) -> bool:
    if not isinstance(commands, list) or len(commands) != len(VERIFY_COMMANDS):
        return False
    if not isinstance(checkpoint_hashes, Mapping):
        return False
    by_name = {item.get("name"): item for item in commands if isinstance(item, dict)}
    for name in VERIFY_COMMANDS:
        item = by_name.get(name)
        if (not isinstance(item, dict) or set(item) != COMMAND_RECEIPT_KEYS
                or item.get("exit") != 0 or item.get("exit_marker") is not True):
            return False
        if item.get("command_sha256") != checkpoint_hashes.get(name):
            return False
    return True


def _result_keys_are_canonical(result: Mapping[str, Any]) -> bool:
    status = result.get("status")
    keys = frozenset(result)
    if status == "VERIFIED":
        return keys == RESULT_BASE_KEYS | {
            "tested_sha", "post_tested_sha", "private_ref_oid", "completed_at_epoch",
        }
    if status == "RUNNING":
        return keys in {
            RESULT_BASE_KEYS,
            RESULT_BASE_KEYS | {"tested_sha"},
            RESULT_BASE_KEYS | {"tested_sha", "post_tested_sha"},
        }
    if status == "FAILED":
        return keys == RESULT_MINIMAL_FAILED_KEYS or keys in {
            RESULT_BASE_KEYS,
            RESULT_BASE_KEYS | {"tested_sha"},
            RESULT_BASE_KEYS | {"tested_sha", "post_tested_sha"},
            RESULT_BASE_KEYS | {"tested_sha", "post_tested_sha", "private_ref_oid"},
        }
    return False


def _env_for_child(repo_root: Path, request: Mapping[str, Any]) -> dict[str, str]:
    env = dict(os.environ)
    locator = str(request.get("host_env_locator") or "")
    if locator:
        locator_path = Path(locator)
        host_env_path = locator_path if locator_path.is_absolute() else repo_root / locator_path
        if host_env_path.is_file():
            env.update(parse_host_env(host_env_path))
        env["CONSENSUS_RND_HOST_ENV"] = locator
    commands = request.get("commands")
    if isinstance(commands, Mapping):
        for name in VERIFY_COMMANDS:
            env[name] = str(commands.get(name) or "")
    env["REPO_ROOT"] = str(repo_root)
    return env


def _private_ref_oid(git: GitRunner, private_ref: str) -> str:
    result = git(["rev-parse", "--verify", private_ref])
    return result.stdout.strip() if result.returncode == 0 else ""


def _verify_worktree_subject(git: GitRunner, expected_sha: str) -> tuple[bool, str, str]:
    head = git(["rev-parse", "HEAD"])
    tested_sha = head.stdout.strip() if head.returncode == 0 else ""
    if not _is_full_sha(tested_sha):
        return False, "worktree-head-unavailable", tested_sha
    if tested_sha != expected_sha:
        return False, "worktree-head-mismatch", tested_sha
    status = git(["status", "--porcelain"])
    if status.returncode != 0:
        return False, "worktree-status-unavailable", tested_sha
    if status.stdout.strip():
        return False, "worktree-dirty", tested_sha
    return True, "verified", tested_sha


def _is_full_sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _repo_git(repo_root: Path) -> GitRunner:
    def run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(repo_root), *[str(arg) for arg in args]], capture_output=True, text=True, check=False)

    return run


def _repo_root_from_job_dir(job_dir: Path) -> Path:
    return job_dir.resolve().parents[4]


def _artifact_path(repo_root: Path, text: str) -> Path:
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or "\\" in text or ".." in pure.parts:
        raise RuntimeError(f"publish verification artifact path invalid: {text!r}")
    path = (repo_root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"publish verification artifact path escapes repo: {text!r}") from exc
    return path


def _repo_relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def _log_has_exit_zero(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
    except OSError:
        return False
    return any(line == "EXIT=0" for line in lines)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="consensus-rnd-cli publish-verification-worker")
    parser.add_argument("job_dir")
    args = parser.parse_args(list(argv) if argv is not None else None)
    return run_one_publish_ratchet(Path(args.job_dir))


__all__ = [
    "PublishVerificationJobResult",
    "PublishVerificationReceiptValidation",
    "PublishVerificationRetryStatus",
    "command_digest",
    "current_retry_status",
    "evidence_path",
    "jobs_root",
    "mark_published",
    "prepare_or_schedule",
    "record_failed_receipt_retry",
    "record_job_retry",
    "main",
    "run_one_publish_ratchet",
    "string_digest",
    "validate_verified_receipt",
    "validate_published_receipt",
]
