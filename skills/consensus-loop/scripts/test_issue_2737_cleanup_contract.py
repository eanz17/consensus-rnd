import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
CONTRACT = json.loads((SCRIPT_DIR / "fixtures/issue_2737_pr_a_cleanup_contract.json").read_text(encoding="utf-8"))

sys.path.insert(0, str(SCRIPT_DIR))
from codex_refactor_loop.issue_2737_recovery import (  # noqa: E402
    parse_occurrence_record,
    validate_singleton_pr_b_changes,
)
from test_issue_2737_recovery import record_bytes  # noqa: E402


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cleanup_tree_errors(files: dict[str, bytes], changed: dict[str, str]) -> list[str]:
    """Validate a cleanup result as exact subtraction from the frozen PR-A closure."""
    errors: list[str] = []
    required_deletes = set(CONTRACT["temporary_whole_files"]) | {CONTRACT["future_occurrence_path"]}
    retained = CONTRACT["retained_generic_sha256"]
    restored = CONTRACT["restored_base_sha256"]
    controller_path = "skills/consensus-loop/scripts/codex_refactor_loop/controller_actions.py"
    expected_changes = {
        **{path: "D" for path in required_deletes},
        **{path: "M" for path in restored},
        controller_path: "M",
    }
    if changed != expected_changes:
        errors.append("changed-path-set")
    for path, status in changed.items():
        if path not in expected_changes or status.startswith(("A", "R", "C")):
            errors.append(f"non-subtractive:{status}:{path}")
    for path in required_deletes:
        if path in files or changed.get(path) != "D":
            errors.append(f"not-deleted:{path}")
    for path, expected in retained.items():
        if path not in files or _digest(files[path]) != expected:
            errors.append(f"retained-drift:{path}")
    for path, expected in restored.items():
        if path not in files or _digest(files[path]) != expected:
            errors.append(f"base-restore-drift:{path}")
    unique_symbols = {name for name in CONTRACT["incident_module_symbols"] if "2737" in name}
    residue = unique_symbols | set(CONTRACT["effects"]) | {
        CONTRACT["future_occurrence_path"],
        *CONTRACT["temporary_controller_members"],
    }
    for path, data in files.items():
        if path.endswith((".py", ".md", ".json", ".sh", ".toml", ".yaml", ".yml")):
            text = data.decode("utf-8")
            if any(value in text for value in residue):
                errors.append(f"incident-residue:{path}")
    return errors


def _git_bytes(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"], cwd=REPO_ROOT, capture_output=True, check=True,
    ).stdout


@dataclass(frozen=True)
class CleanupCoordinates:
    pr_a_base: str
    pr_a_head: str
    pr_a_merge: str
    pr_b_base: str
    pr_b_head: str
    pr_b_merge: str
    cleanup_base: str
    cleanup_head: str

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"invalid cleanup coordinate: {name}")


@dataclass(frozen=True)
class ReviewedPullProjection:
    repository: str
    number: int
    base_ref: str
    head_ref: str
    base_sha: str
    head_sha: str
    merge_sha: str
    head_tree: str
    merge_tree: str


def _git(repo: Path, argv: list[str], *, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *argv], cwd=repo, capture_output=True, check=True, text=text,
    )


def _commit_identity(repo: Path, commit: str) -> tuple[list[str], str]:
    kind = _git(repo, ["cat-file", "-t", commit], text=True).stdout.strip()
    if kind != "commit":
        raise ValueError(f"cleanup coordinate is not a commit: {commit}")
    parents = _git(repo, ["show", "-s", "--format=%P", commit], text=True).stdout.strip().split()
    tree = _git(repo, ["show", "-s", "--format=%T", commit], text=True).stdout.strip()
    return parents, tree


def _nul_status(repo: Path, older: str, newer: str) -> tuple[tuple[str, str], ...]:
    raw = _git(repo, ["diff", "--name-status", "-z", "--no-renames", older, newer]).stdout
    fields = raw.split(b"\0")
    if fields[-1:] != [b""] or len(fields) % 2 != 1:
        raise ValueError("git diff is not a complete NUL-delimited status projection")
    rows: list[tuple[str, str]] = []
    for index in range(0, len(fields) - 1, 2):
        rows.append((fields[index].decode("ascii"), fields[index + 1].decode("utf-8")))
    return tuple(rows)


def _validate_cleanup_lifecycle(
    repo: Path,
    coordinates: CleanupCoordinates,
    pr_a: ReviewedPullProjection,
    pr_b: ReviewedPullProjection,
) -> None:
    origin = _git(repo, ["remote", "get-url", "origin"], text=True).stdout.strip()
    if origin not in (
        "git@github.com:eanz17/consensus-rnd.git",
        "https://github.com/eanz17/consensus-rnd.git",
    ):
        raise ValueError("cleanup lifecycle is not in the fixed fork repository")

    identities = {
        name: _commit_identity(repo, value)
        for name, value in coordinates.__dict__.items()
        if name not in {"pr_b_base", "cleanup_base"}
    }
    if (
        pr_a.repository != "eanz17/consensus-rnd"
        or pr_b.repository != "eanz17/consensus-rnd"
        or (pr_a.base_sha, pr_a.head_sha, pr_a.merge_sha) != (
            coordinates.pr_a_base, coordinates.pr_a_head, coordinates.pr_a_merge
        )
        or (pr_b.base_sha, pr_b.head_sha, pr_b.merge_sha) != (
            coordinates.pr_b_base, coordinates.pr_b_head, coordinates.pr_b_merge
        )
        or (pr_a.head_tree, pr_a.merge_tree) != (
            identities["pr_a_head"][1], identities["pr_a_merge"][1]
        )
        or (pr_b.head_tree, pr_b.merge_tree) != (
            identities["pr_b_head"][1], identities["pr_b_merge"][1]
        )
    ):
        raise ValueError("cleanup coordinates do not match live PR projections")
    if coordinates.pr_b_base != coordinates.pr_a_merge:
        raise ValueError("PR-B base is not the exact reviewed PR-A merge")
    if coordinates.cleanup_base != coordinates.pr_b_merge:
        raise ValueError("cleanup base is not the exact admitted PR-B merge")
    if identities["pr_a_merge"] != (
        [coordinates.pr_a_base, coordinates.pr_a_head], identities["pr_a_head"][1]
    ):
        raise ValueError("PR-A merge does not have the exact reviewed topology")
    if identities["pr_b_merge"] != (
        [coordinates.pr_b_base, coordinates.pr_b_head], identities["pr_b_head"][1]
    ):
        raise ValueError("PR-B merge does not have the exact reviewed topology")
    if identities["cleanup_head"][0] != [coordinates.cleanup_base]:
        raise ValueError("cleanup head is not the direct child of the admitted PR-B merge")

    occurrence_path = CONTRACT["future_occurrence_path"]
    try:
        head_bytes = _git(repo, ["show", f"{coordinates.pr_b_head}:{occurrence_path}"]).stdout
        merge_bytes = _git(repo, ["show", f"{coordinates.pr_b_merge}:{occurrence_path}"]).stdout
    except subprocess.CalledProcessError as exc:
        raise ValueError("canonical occurrence record is absent from PR-B head or merge") from exc
    if head_bytes != merge_bytes:
        raise ValueError("canonical occurrence bytes differ between PR-B head and merge")
    occurrence = parse_occurrence_record(head_bytes)
    implementation = occurrence.raw["implementation"]
    authorization = occurrence.raw["authorization_pr"]
    if (
        implementation["reviewed_head_sha"] != coordinates.pr_a_head
        or implementation["merge_sha"] != coordinates.pr_a_merge
        or implementation["reviewed_tree_oid"] != identities["pr_a_head"][1]
        or implementation["merge_tree_oid"] != identities["pr_a_merge"][1]
        or implementation["pr_number"] != pr_a.number
        or authorization["number"] != pr_b.number
        or authorization["base_ref"] != pr_b.base_ref
        or authorization["head_ref"] != pr_b.head_ref
        or authorization["expected_base_sha"] != coordinates.pr_b_base
    ):
        raise ValueError("canonical occurrence does not bind the reviewed PR-A lifecycle")
    for bound in implementation["bound_files"]:
        path = str(bound["path"])
        head_entry = _git(repo, ["ls-tree", coordinates.pr_a_head, "--", path], text=True).stdout.split()
        merge_entry = _git(repo, ["ls-tree", coordinates.pr_a_merge, "--", path], text=True).stdout.split()
        if (
            len(head_entry) < 4
            or head_entry != merge_entry
            or head_entry[0] != "100644"
            or head_entry[1] != "blob"
            or head_entry[2] != bound["blob_oid"]
            or _digest(_git(repo, ["show", f"{coordinates.pr_a_head}:{path}"]).stdout) != bound["sha256"]
        ):
            raise ValueError(f"canonical occurrence bound file drift: {path}")

    pr_b_status = _nul_status(repo, coordinates.pr_b_base, coordinates.pr_b_head)
    git_files: list[tuple[str, str, str]] = []
    api_files: list[dict[str, object]] = []
    for status, path in pr_b_status:
        entry = _git(repo, ["ls-tree", coordinates.pr_b_head, "--", path], text=True).stdout.split()
        mode = entry[0] if entry else ""
        git_files.append((path, status, mode))
        api_files.append({"filename": path, "status": "added" if status == "A" else "modified", "previous_filename": None})
    try:
        validate_singleton_pr_b_changes(tuple(api_files), tuple(git_files))
    except Exception as exc:
        raise ValueError("PR-B is not the exact singleton occurrence addition") from exc


def _actual_cleanup_tree(
    repo: Path,
    coordinates: CleanupCoordinates,
    pr_a: ReviewedPullProjection,
    pr_b: ReviewedPullProjection,
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Read an independently authored cleanup diff and result tree from exact git coordinates."""
    _validate_cleanup_lifecycle(repo, coordinates, pr_a, pr_b)

    changed: dict[str, str] = {}
    for status, path in _nul_status(repo, coordinates.cleanup_base, coordinates.cleanup_head):
        if path in changed:
            raise ValueError(f"duplicate cleanup status path: {path}")
        changed[path] = status

    raw_tree = _git(
        repo, ["ls-tree", "-r", "-z", "--full-tree", coordinates.cleanup_head, "--", "skills/consensus-loop"],
    ).stdout
    entries = raw_tree.split(b"\0")
    if entries[-1:] != [b""]:
        raise ValueError("cleanup tree is not a complete NUL-delimited projection")
    files: dict[str, bytes] = {}
    for entry in entries[:-1]:
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, _oid = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if mode not in ("100644", "100755") or kind != "blob" or path in files:
            raise ValueError(f"unsupported cleanup result entry: {path}")
        files[path] = _git(repo, ["show", f"{coordinates.cleanup_head}:{path}"]).stdout
    return files, changed


def _candidate_cleanup_tree() -> tuple[dict[str, bytes], dict[str, str]]:
    skill_root = REPO_ROOT / "skills/consensus-loop"
    files = {
        path.relative_to(REPO_ROOT).as_posix(): path.read_bytes()
        for path in skill_root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    before = dict(files)
    # PR B does not exist in PR A. Model only its required path presence in the
    # future cleanup base; no occurrence fields or authority values are created.
    before.setdefault(CONTRACT["future_occurrence_path"], b"future-occurrence-path-present\n")
    for path in CONTRACT["temporary_whole_files"] + [CONTRACT["future_occurrence_path"]]:
        files.pop(path, None)
    for path in CONTRACT["restored_base_sha256"]:
        files[path] = _git_bytes(CONTRACT["base_commit"], path)

    controller_path = "skills/consensus-loop/scripts/codex_refactor_loop/controller_actions.py"
    controller_text = files[controller_path].decode()
    module = ast.parse(controller_text)
    owner = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "ControllerActions")
    incident = [
        node for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name in CONTRACT["temporary_controller_members"]
    ]
    lines = controller_text.splitlines(keepends=True)
    removed = set(range(incident[0].lineno, incident[-1].end_lineno + 1))
    files[controller_path] = "".join(
        line for number, line in enumerate(lines, 1)
        if number not in removed and line.rstrip("\n") not in CONTRACT["temporary_controller_imports"]
    ).encode()

    changed: dict[str, str] = {}
    for path in sorted(set(before) | set(files)):
        if path not in files:
            changed[path] = "D"
        elif path not in before:
            changed[path] = "A"
        elif before[path] != files[path]:
            changed[path] = "M"
    return files, changed


def _commit_tree(repo: Path, tree: str, parents: tuple[str, ...], message: str) -> str:
    argv = ["commit-tree", tree]
    for parent in parents:
        argv.extend(("-p", parent))
    return subprocess.run(
        ["git", *argv], cwd=repo, input=message + "\n", text=True,
        capture_output=True, check=True,
    ).stdout.strip()


def _canonical_occurrence(repo: Path, pr_a_head: str, pr_a_merge: str) -> bytes:
    raw = json.loads(record_bytes())
    head_tree = _git(repo, ["show", "-s", "--format=%T", pr_a_head], text=True).stdout.strip()
    merge_tree = _git(repo, ["show", "-s", "--format=%T", pr_a_merge], text=True).stdout.strip()
    bound = raw["implementation"]["bound_files"][0]
    path = bound["path"]
    bound["blob_oid"] = _git(repo, ["rev-parse", f"{pr_a_head}:{path}"], text=True).stdout.strip()
    bound["sha256"] = _digest(_git(repo, ["show", f"{pr_a_head}:{path}"]).stdout)
    raw["implementation"].update(
        reviewed_head_sha=pr_a_head,
        reviewed_tree_oid=head_tree,
        merge_sha=pr_a_merge,
        merge_tree_oid=merge_tree,
    )
    raw["authorization_pr"]["expected_base_sha"] = pr_a_merge
    return json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _build_review_history(
    repo: Path, cleanup_files: dict[str, bytes], *, extra_pr_b_path: str | None = None
) -> tuple[CleanupCoordinates, ReviewedPullProjection, ReviewedPullProjection]:
    _git(repo, ["init", "-q"])
    _git(repo, ["config", "user.email", "cleanup-review@example.invalid"])
    _git(repo, ["config", "user.name", "Cleanup Review"])
    _git(repo, ["remote", "add", "origin", "https://github.com/eanz17/consensus-rnd.git"])
    marker = repo / ".cleanup-coordinate-base"
    marker.write_text("base\n", encoding="utf-8")
    _git(repo, ["add", "."])
    _git(repo, ["commit", "-q", "-m", "coordinate base"])
    pr_a_base = _git(repo, ["rev-parse", "HEAD"], text=True).stdout.strip()
    marker.unlink()
    _git(repo, ["add", "-A"])
    _git(repo, ["commit", "-q", "-m", "reviewed PR A"])
    pr_a_head = _git(repo, ["rev-parse", "HEAD"], text=True).stdout.strip()
    pr_a_tree = _git(repo, ["show", "-s", "--format=%T", pr_a_head], text=True).stdout.strip()
    pr_a_merge = _commit_tree(repo, pr_a_tree, (pr_a_base, pr_a_head), "merge reviewed PR A")

    occurrence = repo / CONTRACT["future_occurrence_path"]
    occurrence.parent.mkdir(parents=True, exist_ok=True)
    occurrence.write_bytes(_canonical_occurrence(repo, pr_a_head, pr_a_merge))
    if extra_pr_b_path is not None:
        extra = repo / extra_pr_b_path
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("def write_item():\n    return True\n", encoding="utf-8")
    _git(repo, ["add", CONTRACT["future_occurrence_path"]] + ([extra_pr_b_path] if extra_pr_b_path else []))
    pr_b_tree = _git(repo, ["write-tree"], text=True).stdout.strip()
    pr_b_head = _commit_tree(repo, pr_b_tree, (pr_a_merge,), "reviewed PR B occurrence")
    pr_b_merge = _commit_tree(repo, pr_b_tree, (pr_a_merge, pr_b_head), "merge reviewed PR B")

    for path in set(CONTRACT["temporary_whole_files"]) | {CONTRACT["future_occurrence_path"]}:
        (repo / path).unlink(missing_ok=True)
    for path, data in cleanup_files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    _git(repo, ["add", "-A"])
    cleanup_tree = _git(repo, ["write-tree"], text=True).stdout.strip()
    cleanup_head = _commit_tree(repo, cleanup_tree, (pr_b_merge,), "independently authored cleanup")
    coordinates = CleanupCoordinates(
        pr_a_base, pr_a_head, pr_a_merge, pr_a_merge,
        pr_b_head, pr_b_merge, pr_b_merge, cleanup_head,
    )
    return coordinates, ReviewedPullProjection(
        "eanz17/consensus-rnd", 1, "main", "implementation", pr_a_base, pr_a_head,
        pr_a_merge, pr_a_tree, pr_a_tree,
    ), ReviewedPullProjection(
        "eanz17/consensus-rnd", 2, "main", "authorize", pr_a_merge, pr_b_head,
        pr_b_merge, pr_b_tree, pr_b_tree,
    )


class FrozenOwnershipClosureTests(unittest.TestCase):
    def test_current_pr_a_matches_complete_frozen_owner_closure(self):
        self.assertEqual(
            [CONTRACT["base_commit"], CONTRACT["base_tree"]],
            subprocess.run(
                ["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=REPO_ROOT,
                text=True, capture_output=True, check=True,
            ).stdout.splitlines(),
        )
        for path in CONTRACT["temporary_whole_files"]:
            self.assertTrue((REPO_ROOT / path).is_file(), path)
        incident_path = REPO_ROOT / CONTRACT["temporary_whole_files"][0]
        module = ast.parse(incident_path.read_text(encoding="utf-8"))
        imports = [ast.unparse(node) for node in module.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        symbols = [node.name for node in module.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
        self.assertEqual(CONTRACT["incident_module_imports"], imports)
        self.assertEqual(CONTRACT["incident_module_symbols"], symbols)

        controller_path = REPO_ROOT / "skills/consensus-loop/scripts/codex_refactor_loop/controller_actions.py"
        controller_text = controller_path.read_text(encoding="utf-8")
        controller = ast.parse(controller_text)
        owner = next(node for node in controller.body if isinstance(node, ast.ClassDef) and node.name == "ControllerActions")
        members = [node.name for node in owner.body if isinstance(node, ast.FunctionDef) and "2737" in node.name]
        self.assertEqual(CONTRACT["temporary_controller_members"], members)
        lines = controller_text.splitlines(keepends=True)
        incident_nodes = [
            node for node in owner.body
            if isinstance(node, ast.FunctionDef) and node.name in CONTRACT["temporary_controller_members"]
        ]
        deleted_lines = set(range(incident_nodes[0].lineno, incident_nodes[-1].end_lineno + 1))
        cleaned_controller = "".join(
            line for number, line in enumerate(lines, 1)
            if number not in deleted_lines and line.rstrip("\n") not in CONTRACT["temporary_controller_imports"]
        )
        self.assertEqual(
            CONTRACT["retained_generic_sha256"]["skills/consensus-loop/scripts/codex_refactor_loop/controller_actions.py"],
            _digest(cleaned_controller.encode()),
        )
        calls = sorted({
            node.attr for node in ast.walk(module)
            if isinstance(node, ast.Attribute) and node.attr in CONTRACT["temporary_controller_members"]
        })
        self.assertEqual(sorted(CONTRACT["temporary_controller_members"][1:]), calls)
        for owner_import in CONTRACT["temporary_controller_imports"]:
            self.assertEqual(1, controller_text.count(owner_import))
        for path, anchor in CONTRACT["temporary_anchors"].items():
            self.assertEqual(1, (REPO_ROOT / path).read_text(encoding="utf-8").count(f'id="{anchor}"'))
        allowance = CONTRACT["temporary_anchor_allowance"]
        self.assertEqual(1, (REPO_ROOT / allowance["path"]).read_text(encoding="utf-8").count(allowance["value"]))
        for path in CONTRACT["forbidden_route_owners"]:
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            self.assertFalse(any(name in text for name in CONTRACT["temporary_controller_members"]), path)

    def test_actual_candidate_cleanup_diff_tree_and_surviving_gates(self):
        files, changed = _candidate_cleanup_tree()
        self.assertEqual([], _cleanup_tree_errors(files, changed))
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            shutil.copytree(REPO_ROOT, candidate, ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__"))
            for path in set(CONTRACT["temporary_whole_files"]) | {CONTRACT["future_occurrence_path"]}:
                (candidate / path).unlink(missing_ok=True)
            for path, data in files.items():
                target = candidate / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            result = subprocess.run(
                [
                    "python3", "-m", "unittest",
                    "skills/consensus-loop/scripts/test_issue_decomposition.py",
                    "skills/consensus-loop/scripts/test_controller_actions.py",
                    "skills/consensus-loop/scripts/test_skill_reference_anchors.py",
                ],
                cwd=candidate, text=True, capture_output=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_coordinate_bound_cleanup_gate_consumes_real_commits_and_surviving_gates(self):
        files, changed = _candidate_cleanup_tree()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "cleanup-review"
            shutil.copytree(REPO_ROOT, repo, ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__"))
            coordinates, pr_a, pr_b = _build_review_history(repo, files)
            actual_files, actual_changed = _actual_cleanup_tree(repo, coordinates, pr_a, pr_b)
            self.assertEqual([], _cleanup_tree_errors(actual_files, actual_changed))
            executable_modes = _git(
                repo, ["ls-tree", "-r", coordinates.cleanup_head, "--", "skills/consensus-loop"], text=True,
            ).stdout
            self.assertIn("100755 blob", executable_modes)
            result = subprocess.run(
                ["python3", "-m", "unittest", "skills/consensus-loop/scripts/test_issue_decomposition.py",
                 "skills/consensus-loop/scripts/test_controller_actions.py",
                 "skills/consensus-loop/scripts/test_skill_reference_anchors.py"],
                cwd=repo, text=True, capture_output=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_coordinate_bound_cleanup_gate_rejects_identity_topology_and_boundary_mismatches(self):
        files, _changed = _candidate_cleanup_tree()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "cleanup-review"
            shutil.copytree(REPO_ROOT, repo, ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__"))
            exact, pr_a, pr_b = _build_review_history(repo, files)
            a_tree = _git(repo, ["show", "-s", "--format=%T", exact.pr_a_head], text=True).stdout.strip()
            b_tree = _git(repo, ["show", "-s", "--format=%T", exact.pr_b_head], text=True).stdout.strip()
            base_tree = _git(repo, ["show", "-s", "--format=%T", exact.pr_a_base], text=True).stdout.strip()
            unrelated = _commit_tree(repo, a_tree, (exact.pr_a_base,), "unrelated")
            reversed_a = _commit_tree(repo, a_tree, (exact.pr_a_head, exact.pr_a_base), "reversed A")
            missing_a = _commit_tree(repo, a_tree, (exact.pr_a_base,), "missing A parent")
            extra_a = _commit_tree(repo, a_tree, (exact.pr_a_base, exact.pr_a_head, unrelated), "extra A parent")
            wrong_tree_a = _commit_tree(repo, base_tree, (exact.pr_a_base, exact.pr_a_head), "wrong A tree")
            reversed_b = _commit_tree(repo, b_tree, (exact.pr_b_head, exact.pr_b_base), "reversed B")
            missing_b = _commit_tree(repo, b_tree, (exact.pr_b_base,), "missing B parent")
            extra_b = _commit_tree(repo, b_tree, (exact.pr_b_base, exact.pr_b_head, unrelated), "extra B parent")
            wrong_tree_b = _commit_tree(repo, a_tree, (exact.pr_b_base, exact.pr_b_head), "wrong B tree")
            bad = (
                {"pr_a_merge": exact.pr_a_head, "pr_b_base": exact.pr_a_head},
                {"pr_b_merge": exact.pr_b_head, "cleanup_base": exact.pr_b_head},
                {"pr_a_merge": reversed_a, "pr_b_base": reversed_a},
                {"pr_a_merge": missing_a, "pr_b_base": missing_a},
                {"pr_a_merge": extra_a, "pr_b_base": extra_a},
                {"pr_a_merge": wrong_tree_a, "pr_b_base": wrong_tree_a},
                {"pr_b_merge": reversed_b, "cleanup_base": reversed_b},
                {"pr_b_merge": missing_b, "cleanup_base": missing_b},
                {"pr_b_merge": extra_b, "cleanup_base": extra_b},
                {"pr_b_merge": wrong_tree_b, "cleanup_base": wrong_tree_b},
                {"pr_b_base": unrelated},
                {"cleanup_base": unrelated},
                {"cleanup_head": unrelated},
            )
            for changes in bad:
                coordinates = CleanupCoordinates(**{**exact.__dict__, **changes})
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    _actual_cleanup_tree(repo, coordinates, pr_a, pr_b)
            projection_cases = (
                {"number": 99}, {"head_ref": "wrong"}, {"base_ref": "wrong"},
                {"head_sha": unrelated}, {"merge_sha": unrelated}, {"head_tree": base_tree},
            )
            for changes in projection_cases:
                changed_pr_b = ReviewedPullProjection(**{**pr_b.__dict__, **changes})
                with self.subTest(projection=changes), self.assertRaises(ValueError):
                    _actual_cleanup_tree(repo, exact, pr_a, changed_pr_b)

    def test_coordinate_bound_cleanup_gate_rejects_non_singleton_pr_b_before_cleanup(self):
        files, _changed = _candidate_cleanup_tree()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "cleanup-review"
            shutil.copytree(REPO_ROOT, repo, ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__"))
            coordinates, pr_a, pr_b = _build_review_history(
                repo, files,
                extra_pr_b_path="skills/consensus-loop/scripts/codex_refactor_loop/maintenance_writer.py",
            )
            with self.assertRaisesRegex(ValueError, "singleton"):
                _actual_cleanup_tree(repo, coordinates, pr_a, pr_b)

    def test_coordinate_bound_cleanup_gate_rejects_incomplete_or_non_regular_projections(self):
        coordinates = CleanupCoordinates(*[str(index) * 40 for index in range(1, 9)])
        projection = ReviewedPullProjection("eanz17/consensus-rnd", 1, "main", "head", *(["1" * 40] * 5))
        malformed = subprocess.CompletedProcess([], 0, b"M\0unterminated", b"")
        with mock.patch.object(
            sys.modules[__name__], "_validate_cleanup_lifecycle"
        ), mock.patch.object(sys.modules[__name__], "_git", return_value=malformed), self.assertRaises(ValueError):
            _actual_cleanup_tree(REPO_ROOT, coordinates, projection, projection)
        empty = subprocess.CompletedProcess([], 0, b"", b"")
        non_regular = subprocess.CompletedProcess(
            [], 0, b"120000 blob " + b"a" * 40 + b"\tbad\0", b""
        )
        with mock.patch.object(
                sys.modules[__name__], "_validate_cleanup_lifecycle"
        ), mock.patch.object(
            sys.modules[__name__], "_git", side_effect=(empty, non_regular)
        ), self.assertRaises(ValueError):
            _actual_cleanup_tree(REPO_ROOT, coordinates, projection, projection)

    def test_cleanup_rejects_move_copy_add_residue_owner_and_generic_drift(self):
        old = CONTRACT["retained_generic_sha256"]
        old_restored = CONTRACT["restored_base_sha256"]
        retained = {path: b"x" for path in old}
        restored = {path: b"base" for path in old_restored}
        try:
            CONTRACT["retained_generic_sha256"] = {path: _digest(data) for path, data in retained.items()}
            CONTRACT["restored_base_sha256"] = {path: _digest(data) for path, data in restored.items()}
            base_changed = {path: "D" for path in CONTRACT["temporary_whole_files"] + [CONTRACT["future_occurrence_path"]]}
            base_changed.update({path: "M" for path in restored})
            base_changed["skills/consensus-loop/scripts/codex_refactor_loop/controller_actions.py"] = "M"
            clean = {**retained, **restored}
            cases = []
            for status in ("A", "R100", "C100"):
                cases.append(({**clean, "skills/copied.py": b"pass\n"}, {**base_changed, "skills/copied.py": status}))
            cases.append(({**clean, "skills/copied.py": b"class Issue2737Effect: pass\n"}, {**base_changed, "skills/copied.py": "M"}))
            cases.append(({**clean, next(iter(retained)): b"drift"}, base_changed))
            cases.append(({**clean, CONTRACT["temporary_whole_files"][0]: b"renamed semantics"}, base_changed))
            for files, changed in cases:
                with self.subTest(changed=changed):
                    self.assertTrue(_cleanup_tree_errors(files, changed))
        finally:
            CONTRACT["retained_generic_sha256"] = old
            CONTRACT["restored_base_sha256"] = old_restored


if __name__ == "__main__":
    unittest.main()
