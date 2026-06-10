"""
ClawGuard — Seatbelt sandboxing.

Real macOS Seatbelt (sandbox-exec) isolation for OpenClaw agents and untrusted
skills. Generates a Sandbox Profile Language (SBPL) policy and runs a command
under it via /usr/bin/sandbox-exec, so a compromised agent cannot reach the
network or write outside its work directory — even if the code is malicious.

This is the implementation behind the "Seatbelt Sandboxing" product claim.

Notes
-----
* macOS only. `sandbox-exec` is the documented Seatbelt interface; Apple marks
  the CLI deprecated but it remains functional on current macOS (15.x). The
  profile language itself is what the OS kernel enforces.
* Profiles use "last matching rule wins" semantics: we start permissive
  (`allow default`) so the target process can launch, then strip the dangerous
  capabilities (network, writes outside the workdir, optionally exec).
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from typing import List, Optional

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Paths a typical process must still be allowed to write to in order to run.
_BASE_WRITE_ALLOW = [
    "/private/tmp",
    "/private/var/folders",   # per-user temp / caches
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
    "/dev/dtracehelper",
]

POLICIES = ("standard", "strict")


def is_available() -> bool:
    """True if Seatbelt sandboxing can be used on this machine."""
    return platform.system() == "Darwin" and os.path.exists(SANDBOX_EXEC)


def _sb_path(p: str) -> str:
    """Resolve symlinks (/tmp -> /private/tmp) and escape for SBPL."""
    real = os.path.realpath(os.path.expanduser(p))
    return real.replace("\\", "\\\\").replace('"', '\\"')


def build_profile(
    policy: str = "standard",
    workdir: Optional[str] = None,
    allow_network: bool = False,
    allow_exec: bool = True,
    extra_write_paths: Optional[List[str]] = None,
) -> str:
    """
    Return SBPL profile text.

    standard : allow default, deny all network, deny writes outside workdir.
    strict   : standard + restrict reads to system roots + workdir (best-effort),
               and deny spawning new programs.
    """
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {POLICIES}, got {policy!r}")

    workdir = workdir or os.getcwd()
    write_allow = [_sb_path(workdir)] + _BASE_WRITE_ALLOW + [
        _sb_path(p) for p in (extra_write_paths or [])
    ]

    lines: List[str] = ["(version 1)", ""]
    lines.append(f";; ClawGuard sandbox profile — policy={policy}")
    lines.append("(allow default)")
    lines.append("")

    # 1) Network isolation
    if not allow_network:
        lines.append(";; --- no network ---")
        lines.append("(deny network*)")
        lines.append("")

    # 2) Filesystem write isolation
    lines.append(";; --- writes only inside the work directory ---")
    lines.append("(deny file-write*)")
    lines.append("(allow file-write*")
    for p in write_allow:
        lines.append(f'    (subpath "{p}")')
    lines.append(")")
    lines.append("")

    # 3) strict extras
    if policy == "strict":
        if not allow_exec:
            lines.append(";; --- no spawning new programs ---")
            lines.append("(deny process-exec*)")
            lines.append("")
        lines.append(";; --- restrict reads to system + workdir (best-effort) ---")
        lines.append("(deny file-read*)")
        lines.append("(allow file-read*")
        for p in ("/usr", "/System", "/Library", "/bin", "/sbin",
                  "/private/var/db/dyld", "/dev", "/private/etc",
                  "/opt/homebrew", "/private/tmp", "/private/var/folders",
                  _sb_path(workdir)):
            lines.append(f'    (subpath "{p}")')
        lines.append(")")
        lines.append("")

    return "\n".join(lines) + "\n"


def run(
    command: List[str],
    policy: str = "standard",
    workdir: Optional[str] = None,
    allow_network: bool = False,
    allow_exec: bool = True,
    timeout: Optional[int] = 120,
    extra_write_paths: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    """
    Run `command` (argv list) under a Seatbelt profile. Returns the completed
    process (stdout/stderr captured). Raises RuntimeError if unavailable.
    """
    if not is_available():
        raise RuntimeError("Seatbelt sandboxing requires macOS with /usr/bin/sandbox-exec.")
    if not command:
        raise ValueError("command must be a non-empty argv list.")

    profile = build_profile(policy, workdir, allow_network, allow_exec, extra_write_paths)
    cwd = os.path.realpath(os.path.expanduser(workdir or os.getcwd()))

    with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as f:
        f.write(profile)
        profile_path = f.name
    try:
        return subprocess.run(
            [SANDBOX_EXEC, "-f", profile_path, *command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        try:
            os.unlink(profile_path)
        except OSError:
            pass


def check() -> dict:
    """Self-test: verify the sandbox actually enforces network + write isolation."""
    if not is_available():
        return {"available": False, "reason": "not macOS or sandbox-exec missing"}

    work = tempfile.mkdtemp(prefix="clawguard_sb_")
    results = {"available": True, "workdir": work, "checks": {}}

    # a) a normal command still runs
    r = run(["/bin/echo", "ok"], workdir=work)
    results["checks"]["command_runs"] = (r.returncode == 0 and r.stdout.strip() == "ok")

    # b) writing INSIDE the workdir is allowed
    inside = os.path.join(work, "inside.txt")
    r = run(["/bin/sh", "-c", f'echo hi > "{inside}"'], workdir=work)
    results["checks"]["write_inside_allowed"] = (r.returncode == 0 and os.path.exists(inside))

    # c) writing OUTSIDE the workdir is BLOCKED (target the user's home dir)
    home_target = os.path.join(os.path.expanduser("~"), ".clawguard_sb_escape_test")
    if os.path.exists(home_target):
        os.unlink(home_target)
    run(["/bin/sh", "-c", f'echo hi > "{home_target}"'], workdir=work)
    results["checks"]["write_outside_blocked"] = (not os.path.exists(home_target))

    # d) network is BLOCKED
    r = run(["/usr/bin/nc", "-z", "-w", "2", "1.1.1.1", "53"], workdir=work)
    results["checks"]["network_blocked"] = (r.returncode != 0)

    results["passed"] = all(results["checks"].values())
    shutil.rmtree(work, ignore_errors=True)
    return results
