#!/usr/bin/env python3
"""
KernelSU stealth feature regression checks.

Runs from host and verifies:
1) feature control-plane consistency (check/get/set/save)
2) key runtime effects for stealth page features
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shlex
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


FEATURES_TO_VERIFY = [
    "prop_spoof",
    "proc_hide",
    "debug_disable",
    "log_silent",
    "symbol_hide",
    "mount_sanitize",
    "stealth_filter_io",
    "stealth_modloader",
    "stealth_exec",
    "stealth_fileio",
    "stealth_ipc",
]

# Keep symbol_hide out of forced toggles because hiding operations are not
# always fully reversible at runtime on all kernels.
FEATURES_TO_TOGGLE = [
    "prop_spoof",
    "proc_hide",
    "debug_disable",
    "log_silent",
    "mount_sanitize",
    "stealth_filter_io",
    "stealth_modloader",
    "stealth_exec",
    "stealth_fileio",
    "stealth_ipc",
]

PROP_SPOOF_EXPECTED = {
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.build.type": "user",
    "ro.build.tags": "release-keys",
}


@dataclasses.dataclass
class CmdResult:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class Runner:
    def __init__(self, adb_bin: str, ksud_bin: str, observer_uid: Optional[int]) -> None:
        self.adb_bin = adb_bin
        self.ksud_bin = ksud_bin
        self.observer_uid = observer_uid
        self.failures: List[str] = []
        self.skips: List[str] = []
        self.passes: List[str] = []

    def run_host(self, args: List[str]) -> CmdResult:
        proc = subprocess.run(args, capture_output=True, text=True)
        return CmdResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())

    def adb_shell(self, cmd: str, root: bool = False) -> CmdResult:
        shell_cmd = f"su -c {shlex.quote(cmd)}" if root else cmd
        return self.run_host([self.adb_bin, "shell", shell_cmd])

    def adb_shell_as_uid(self, uid: int, cmd: str) -> CmdResult:
        inner = f"sh -c {shlex.quote(cmd)}"
        primary = f"su {uid} -c {shlex.quote(inner)}"
        result = self.run_host([self.adb_bin, "shell", primary])
        if result.ok:
            return result

        usage_hint = (result.out + "\n" + result.err).lower()
        if "usage" in usage_hint or "invalid" in usage_hint:
            fallback = f"su -c {shlex.quote(inner)} {uid}"
            return self.run_host([self.adb_bin, "shell", fallback])
        return result

    def ksud(self, args: str, root: bool = True) -> CmdResult:
        return self.adb_shell(f"{self.ksud_bin} {args}", root=root)

    def log_pass(self, msg: str) -> None:
        self.passes.append(msg)
        print(f"[PASS] {msg}")

    def log_fail(self, msg: str) -> None:
        self.failures.append(msg)
        print(f"[FAIL] {msg}")

    def log_skip(self, msg: str) -> None:
        self.skips.append(msg)
        print(f"[SKIP] {msg}")


def parse_feature_value(output: str) -> Optional[int]:
    match = re.search(r"^Value:\s*(\d+)\s*$", output, flags=re.MULTILINE)
    if not match:
        return None
    return int(match.group(1))


def parse_feature_check(output: str) -> Optional[str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return None
    return lines[-1]


def require_ok(r: Runner, result: CmdResult, action: str) -> bool:
    if result.ok:
        return True
    r.log_fail(f"{action} failed (code={result.code}): {result.out or result.err}")
    return False


def ensure_device_ready(r: Runner) -> bool:
    version = r.run_host([r.adb_bin, "version"])
    if not version.ok:
        r.log_fail(f"adb not available: {version.err or version.out}")
        return False

    state = r.run_host([r.adb_bin, "get-state"])
    if not state.ok or state.out.strip() != "device":
        r.log_fail(f"adb device not ready: {state.out or state.err}")
        return False

    uid = r.adb_shell("id -u", root=True)
    if not uid.ok or uid.out.strip() != "0":
        r.log_fail("root shell not available via `su -c`")
        return False

    which_ksud = r.adb_shell(f"command -v {shlex.quote(r.ksud_bin)}", root=True)
    if not which_ksud.ok or not which_ksud.out.strip():
        r.log_fail(f"cannot find ksud binary: {r.ksud_bin}")
        return False

    r.log_pass("adb + root + ksud environment ready")
    return True


def get_feature_values(r: Runner, features: List[str]) -> Optional[Dict[str, int]]:
    values: Dict[str, int] = {}
    for feature in features:
        check = r.ksud(f"feature check {shlex.quote(feature)}")
        if not check.ok:
            r.log_fail(f"feature check failed for {feature}: {check.out or check.err}")
            return None
        status = parse_feature_check(check.out)
        if status == "unsupported":
            r.log_fail(f"feature not supported: {feature}")
            return None

        getv = r.ksud(f"feature get {shlex.quote(feature)}")
        if not getv.ok:
            r.log_fail(f"feature get failed for {feature}: {getv.out or getv.err}")
            return None
        value = parse_feature_value(getv.out)
        if value is None:
            r.log_fail(f"cannot parse feature value for {feature}: {getv.out or getv.err}")
            return None
        values[feature] = value
    return values


def set_feature(r: Runner, feature: str, value: int) -> bool:
    cmd = r.ksud(f"feature set {shlex.quote(feature)} {value}")
    if not require_ok(r, cmd, f"set feature {feature}={value}"):
        return False

    getv = r.ksud(f"feature get {shlex.quote(feature)}")
    if not getv.ok:
        r.log_fail(f"verify feature get failed for {feature}: {getv.out or getv.err}")
        return False
    parsed = parse_feature_value(getv.out)
    if parsed != value:
        r.log_fail(f"feature {feature} expected {value}, got {parsed}")
        return False
    return True


def spawn_probe_pid(r: Runner) -> Optional[int]:
    proc = r.adb_shell("sh -c 'sleep 300 >/dev/null 2>&1 & echo $!'", root=True)
    if not proc.ok:
        r.log_fail(f"spawn probe process failed: {proc.out or proc.err}")
        return None
    lines = [line.strip() for line in proc.out.splitlines() if line.strip()]
    if not lines:
        r.log_fail("spawn probe process returned empty pid output")
        return None
    try:
        pid = int(lines[-1])
    except ValueError:
        r.log_fail(f"invalid pid output: {proc.out}")
        return None
    if pid <= 0:
        r.log_fail(f"invalid pid value: {pid}")
        return None
    return pid


def run_prop_spoof_checks(r: Runner) -> None:
    apply_res = r.ksud("debug apply prop-spoof")
    if not apply_res.ok:
        r.log_fail(f"prop_spoof apply command failed: {apply_res.out or apply_res.err}")
        return
    r.log_pass("prop_spoof apply command")

    for prop, expected in PROP_SPOOF_EXPECTED.items():
        got = r.adb_shell(f"getprop {shlex.quote(prop)}", root=True)
        if not got.ok:
            r.log_fail(f"getprop failed for {prop}: {got.out or got.err}")
            continue
        value = got.out.strip()
        if value != expected:
            r.log_fail(f"prop_spoof mismatch {prop}: expected '{expected}', got '{value}'")
        else:
            r.log_pass(f"prop_spoof value {prop}={expected}")


def run_debug_disable_checks(r: Runner) -> None:
    expect = {
        "/proc/sys/kernel/dmesg_restrict": "1",
        "/proc/sys/kernel/kptr_restrict": "2",
    }
    for path, expected in expect.items():
        res = r.adb_shell(f"cat {path}", root=True)
        if not res.ok:
            r.log_fail(f"debug_disable check failed reading {path}: {res.out or res.err}")
            continue
        got = res.out.strip()
        if got != expected:
            r.log_fail(f"debug_disable mismatch {path}: expected '{expected}', got '{got}'")
        else:
            r.log_pass(f"debug_disable sysctl {path}={expected}")

    ptrace_scope = r.adb_shell("cat /proc/sys/kernel/yama/ptrace_scope", root=True)
    if ptrace_scope.ok:
        if ptrace_scope.out.strip() != "2":
            r.log_fail(
                "debug_disable mismatch /proc/sys/kernel/yama/ptrace_scope: "
                f"expected '2', got '{ptrace_scope.out.strip()}'"
            )
        else:
            r.log_pass("debug_disable yama ptrace_scope=2")
    else:
        r.log_skip("debug_disable ptrace_scope check skipped (CONFIG_SECURITY_YAMA may be off)")


def run_observer_checks(r: Runner, observer_uid: int, pid: int, real_exe: str) -> None:
    probe = r.adb_shell_as_uid(observer_uid, "id -u")
    if not probe.ok:
        r.log_skip(
            f"observer uid checks skipped (cannot run `su {observer_uid} -c`): {probe.out or probe.err}"
        )
        return

    tests: List[Tuple[str, str, str]] = [
        ("proc dir hidden", f"ls /proc/{pid} >/dev/null 2>&1", "expect non-zero exit"),
        (
            "relative openat block",
            f"cd /proc/{pid} && ls exe >/dev/null 2>&1",
            "expect non-zero exit",
        ),
        (
            "relative readlinkat no real leak",
            f"cd /proc/{pid} && readlink exe",
            "expect non-zero exit or non-real-path output",
        ),
        (
            "mount sanitize",
            "cat /proc/self/mountinfo | grep -F '/data/adb/' >/dev/null 2>&1",
            "expect non-zero exit",
        ),
        (
            "symbol hide /proc/modules",
            "cat /proc/modules | grep -Ei 'kernelsu|\\bksu\\b' >/dev/null 2>&1",
            "expect non-zero exit",
        ),
        (
            "symbol hide /proc/kallsyms",
            "cat /proc/kallsyms | grep -Ei 'kernelsu|\\bksu_\\b|\\bksu\\b' >/dev/null 2>&1",
            "expect non-zero exit",
        ),
        (
            "log silent dmesg",
            "dmesg 2>/dev/null | grep -Ei 'kernelsu|\\bksu_\\b|\\bksu\\b' >/dev/null 2>&1",
            "expect non-zero exit",
        ),
    ]

    for name, cmd, _desc in tests:
        res = r.adb_shell_as_uid(observer_uid, cmd)
        if name == "relative readlinkat no real leak" and res.code == 0:
            leaked = res.out.strip() == real_exe.strip() and bool(real_exe.strip())
            if leaked:
                r.log_fail(f"{name} failed: leaked real path `{real_exe}`")
            else:
                r.log_pass(f"{name} ({cmd})")
            continue

        if res.code != 0:
            r.log_pass(f"{name} ({cmd})")
        else:
            r.log_fail(f"{name} failed: command unexpectedly succeeded")


def main() -> int:
    parser = argparse.ArgumentParser(description="KernelSU stealth feature regression checks via adb")
    parser.add_argument("--adb", default="adb", help="adb executable path (default: adb)")
    parser.add_argument("--ksud-bin", default="ksud", help="ksud binary name/path on device")
    parser.add_argument(
        "--observer-uid",
        type=int,
        default=10000,
        help="uid used for visibility checks (default: 10000). set -1 to skip observer checks",
    )
    args = parser.parse_args()

    observer_uid = None if args.observer_uid < 0 else args.observer_uid
    runner = Runner(args.adb, args.ksud_bin, observer_uid)

    if not ensure_device_ready(runner):
        return 1

    original_values = get_feature_values(runner, FEATURES_TO_VERIFY)
    if original_values is None:
        return 1

    probe_pid: Optional[int] = None
    restore_errors = False
    try:
        for feature in FEATURES_TO_TOGGLE:
            if set_feature(runner, feature, 1):
                runner.log_pass(f"feature enabled: {feature}")
            else:
                return 1

        save_res = runner.ksud("feature save")
        if save_res.ok:
            runner.log_pass("feature save after enable")
        else:
            runner.log_fail(f"feature save after enable failed: {save_res.out or save_res.err}")
            return 1

        probe_pid = spawn_probe_pid(runner)
        if probe_pid is None:
            return 1
        runner.log_pass(f"probe pid spawned: {probe_pid}")

        real_exe_res = runner.adb_shell(f"readlink /proc/{probe_pid}/exe", root=True)
        real_exe = real_exe_res.out.strip() if real_exe_res.ok else ""

        if not require_ok(
            runner,
            runner.ksud(f"debug stealth pid mark {probe_pid}"),
            "stealth pid mark",
        ):
            return 1

        if not require_ok(
            runner,
            runner.ksud(
                f"debug stealth pid disguise {probe_pid} --fake-comm logd --fake-exe /system/bin/logd"
            ),
            "stealth pid disguise",
        ):
            return 1

        if not require_ok(
            runner,
            runner.ksud("debug stealth probe-ipc __ksu_probe__"),
            "stealth ipc probe",
        ):
            return 1

        run_prop_spoof_checks(runner)
        run_debug_disable_checks(runner)

        if observer_uid is not None:
            run_observer_checks(runner, observer_uid, probe_pid, real_exe)
        else:
            runner.log_skip("observer uid checks skipped by argument")

        smoke = runner.ksud(
            f"debug stealth smoke {probe_pid} --fake-comm logd --fake-exe /system/bin/logd --module-id __ksu_probe__"
        )
        if smoke.ok:
            runner.log_pass("stealth smoke chain")
        else:
            runner.log_fail(f"stealth smoke chain failed: {smoke.out or smoke.err}")
    finally:
        if probe_pid is not None:
            _ = runner.ksud(f"debug stealth pid unmark {probe_pid}")
            _ = runner.adb_shell(f"kill -9 {probe_pid} >/dev/null 2>&1 || true", root=True)

        for feature in FEATURES_TO_TOGGLE:
            old_value = original_values.get(feature)
            if old_value is None:
                continue
            if not set_feature(runner, feature, old_value):
                restore_errors = True

        save_restore = runner.ksud("feature save")
        if not save_restore.ok:
            runner.log_fail(f"feature save after restore failed: {save_restore.out or save_restore.err}")
            restore_errors = True

    print("\n=== Summary ===")
    print(f"PASS: {len(runner.passes)}")
    print(f"SKIP: {len(runner.skips)}")
    print(f"FAIL: {len(runner.failures)}")

    if restore_errors:
        print("Restore state had errors.")
        return 1
    if runner.failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
