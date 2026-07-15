"""Git subprocess primitives that preserve existing controller semantics."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

@dataclass(frozen=True)
class Git:
    repo_root: Path

    def run(self, args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed with exit {result.returncode}")
        return result

    def merge_ff_only(self, ref: str) -> subprocess.CompletedProcess[str]:
        return self.run(["merge", "--ff-only", ref])

    def push(self, remote: str, refspec: str, *, force_with_lease: bool = False) -> subprocess.CompletedProcess[str]:
        args = ["push"]
        if force_with_lease:
            args.append("--force-with-lease")
        args.extend([remote, refspec])
        return self.run(args)
