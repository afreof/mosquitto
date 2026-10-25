#!/usr/bin/env python3
"""Build Mosquitto in several configurations and run the tests for each.

Each selected combination of build system (make, cmake), build variant (a set
of features switched on or off) and test mode is built from a snapshot of the
source tree and tested:

  plain     the normal test suite
  asan      the test suite on a build instrumented with AddressSanitizer,
            LeakSanitizer and UndefinedBehaviorSanitizer
  valgrind  the test suite with every broker run under valgrind memcheck

The plain and valgrind modes share a build. A run fails if the build or the
tests fail, or if a sanitizer or valgrind reports an error, even when the
tests themselves passed. The tests include a 5 second run of the SIGHUP TLS
reload stress test; optionally, a longer run is done for every TLS-enabled
build as well.

Variants whose requirements aren't met on this machine, e.g. libwebsockets or
OpenSSL engine headers not being installed, are skipped rather than failed.

Examples:

  test/build_variants.py --list
  test/build_variants.py -b cmake -V default,no-tls -m plain
  test/build_variants.py -m asan,valgrind -R '08-ssl-hup|08-tls-psk-hup' --stress-duration 60
"""

import argparse
import dataclasses
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Build options that can be switched in a variant: name -> (CMake option, make variable).
# The test scripts check the CMake option names, see mosq_test.check_features().
FEATURES = {
    "tls": ("WITH_TLS", "WITH_TLS"),
    "tls_psk": ("WITH_TLS_PSK", "WITH_TLS_PSK"),
    "threading": ("WITH_THREADING", "WITH_THREADING"),
    "bridge": ("INC_BRIDGE_SUPPORT", "WITH_BRIDGE"),
    "persistence": ("WITH_PERSISTENCE", "WITH_PERSISTENCE"),
    "sys_tree": ("WITH_SYS_TREE", "WITH_SYS_TREE"),
    "socks": ("WITH_SOCKS", "WITH_SOCKS"),
    "unix_sockets": ("WITH_UNIX_SOCKETS", "WITH_UNIX_SOCKETS"),
    "memtrack": ("INC_MEMTRACK", "WITH_MEMORY_TRACKING"),
}

# The make build doesn't set OPENSSL_API_COMPAT, so with OpenSSL 3 it compiles
# the ENGINE code out even when the ENGINE headers are available.
OPENSSL_LEGACY_API = "-DOPENSSL_API_COMPAT=0x10100000L"


@dataclasses.dataclass
class Variant:
    name: str
    description: str
    features: dict = dataclasses.field(default_factory=dict)
    # "builtin", "lws" or "off"
    websockets: str = "builtin"
    # None: whatever the OpenSSL headers provide, False: force ENGINE support
    # off, True: require ENGINE support.
    engine: bool = None

    @property
    def tls(self):
        return self.features.get("tls", True)


VARIANTS = [
    Variant("default", "default options"),
    Variant("engine", "OpenSSL ENGINE support enabled, requires OpenSSL with ENGINE headers "
            "(e.g. openssl-devel-engine on Fedora)", engine=True),
    Variant("no-engine", "OpenSSL ENGINE support compiled out (-DOPENSSL_NO_ENGINE), "
            "as with an OpenSSL built with no-engine", engine=False),
    Variant("no-tls", "TLS and websockets disabled (builtin websockets require TLS)",
            {"tls": False, "tls_psk": False}, websockets="off"),
    Variant("no-tls-psk", "TLS-PSK disabled", {"tls_psk": False}),
    Variant("no-websockets", "websockets disabled", websockets="off"),
    Variant("websockets-lws", "websockets using libwebsockets instead of the builtin "
            "implementation, requires libwebsockets", websockets="lws"),
    Variant("no-threading", "threading disabled", {"threading": False}),
    Variant("no-memtrack", "memory tracking disabled", {"memtrack": False}),
    Variant("minimal", "bridge, persistence, $SYS tree, SOCKS and unix sockets disabled",
            {"bridge": False, "persistence": False, "sys_tree": False, "socks": False,
             "unix_sockets": False}),
]

BUILD_SYSTEMS = ["cmake", "make"]
MODES = ["plain", "asan", "valgrind"]

SANITIZE_FLAGS = "-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
# The defaults from config.mk, with less optimisation for more useful reports.
MAKE_ASAN_CFLAGS = f"-Wall -ggdb -O1 -Wconversion -Wextra -std=gnu99 -Werror=switch {SANITIZE_FLAGS}"
MAKE_ASAN_CXXFLAGS = f"-Wall -ggdb -O1 -Wconversion -Wextra {SANITIZE_FLAGS}"

# Valgrind logs are kept for still reachable memory too, mostly from OpenSSL,
# so only these count as errors.
VALGRIND_ERROR = re.compile(
    r"Invalid (read|write|free)|uninitialised|Mismatched free|Syscall param|"
    r"Source and destination overlap|(definitely|indirectly) lost: [1-9]")

ENV_TO_CLEAR = ["BUILD_ROOT", "MOSQ_USE_VALGRIND", "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"] + \
    sorted({opt for pair in FEATURES.values() for opt in pair} | {"WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"})


@dataclasses.dataclass
class Result:
    build_system: str
    variant: str
    mode: str
    status: str = "PASS"
    detail: str = ""
    log: Path = None
    seconds: float = 0.0


def probe_compile(source, flags, link=False):
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp, "probe.c")
        src.write_text(source)
        cmd = ["cc"] + flags + ([] if link else ["-c"]) + ["-o", str(Path(tmp, "probe")), str(src)]
        return subprocess.run(cmd, capture_output=True).returncode == 0


_probe_cache = {}


def probe(name):
    if name not in _probe_cache:
        if name == "engine":
            ok = probe_compile("#include <openssl/ssl.h>\n"
                               "#if defined(OPENSSL_NO_ENGINE) || OPENSSL_API_LEVEL >= 30000\n#error\n#endif\n"
                               "#include <openssl/engine.h>\n", [OPENSSL_LEGACY_API])
        elif name == "lws":
            ok = subprocess.run(["pkg-config", "--exists", "libwebsockets"]).returncode == 0
        elif name == "asan":
            ok = probe_compile("int main(void){return 0;}\n", SANITIZE_FLAGS.split(), link=True)
        else:
            ok = shutil.which(name) is not None
        _probe_cache[name] = ok
    return _probe_cache[name]


def unmet_requirement(build_system, variant, mode):
    if not probe(build_system):
        return f"{build_system} not found"
    if variant.engine and not probe("engine"):
        return "OpenSSL ENGINE headers not available"
    if variant.websockets == "lws" and not probe("lws"):
        return "libwebsockets not found"
    if mode == "valgrind" and not probe("valgrind"):
        return "valgrind not found"
    if mode == "asan" and not probe("asan"):
        return "compiler can't build with -fsanitize=address,undefined"
    return None


def cmake_configure_args(variant, asan):
    args = ["-DCMAKE_BUILD_TYPE=Debug", "-DWITH_DOCS=OFF"]
    for feature, enabled in variant.features.items():
        args.append(f"-D{FEATURES[feature][0]}={'ON' if enabled else 'OFF'}")
    args.append(f"-DWITH_WEBSOCKETS={'OFF' if variant.websockets == 'off' else 'ON'}")
    args.append(f"-DWITH_WEBSOCKETS_BUILTIN={'ON' if variant.websockets == 'builtin' else 'OFF'}")
    if variant.engine is False:
        args += ["-DCMAKE_C_FLAGS=-DOPENSSL_NO_ENGINE", "-DCMAKE_CXX_FLAGS=-DOPENSSL_NO_ENGINE"]
    if asan:
        args.append("-DWITH_ASAN=ON")
    return args


def make_options(variant):
    """The config.mk options of a variant."""
    options = {"WITH_DOCS": "no"}
    for feature, enabled in variant.features.items():
        options[FEATURES[feature][1]] = "yes" if enabled else "no"
    options["WITH_WEBSOCKETS"] = {"builtin": "yes", "lws": "lws", "off": "no"}[variant.websockets]
    return options


def set_make_options(config_mk, options):
    """Set options in config.mk. Passing them on the make command line
    instead would export them to the tests, as e.g. WITH_TLS=yes, which
    mosq_test.check_features() doesn't understand."""
    text = config_mk.read_text()
    for name, value in options.items():
        text, count = re.subn(rf"^{name}\s*:?=.*$", f"{name}:={value}", text, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"{name} not found in {config_mk}")
    config_mk.write_text(text)


def make_args(variant, asan):
    """The make command line arguments of a variant."""
    args = []
    if variant.engine is False:
        args.append("CPPFLAGS=-DOPENSSL_NO_ENGINE")
    elif variant.engine:
        args.append(f"CPPFLAGS={OPENSSL_LEGACY_API}")
    if asan:
        args += [f"CFLAGS={MAKE_ASAN_CFLAGS}", f"CXXFLAGS={MAKE_ASAN_CXXFLAGS}",
                 f"LDFLAGS={SANITIZE_FLAGS}"]
    return args


def make_test_feature_env(variant):
    """Feature flags for the tests of a make build. CMake passes these to the
    tests itself, while the tests assume that a feature that isn't set is
    enabled.

    For variables that config.mk also sets, make exports the value config.mk
    assigns to them, i.e. yes/no instead of ON/OFF, which the tests accept
    too."""
    env = {FEATURES[f][0]: "ON" if enabled else "OFF" for f, enabled in variant.features.items()}
    env["WITH_WEBSOCKETS"] = "OFF" if variant.websockets == "off" else "ON"
    env["WITH_WEBSOCKETS_BUILTIN"] = "ON" if variant.websockets == "builtin" else "OFF"
    return env


def snapshot_source(dest, ref=None, exclude=None):
    """Copy the source tree into dest: the tracked and untracked but not
    ignored files of the working tree except those in exclude, or the files
    of git ref."""
    if dest.exists():
        shutil.rmtree(dest)
    exclude = Path(exclude).resolve() if exclude else None
    is_git = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--git-dir"],
                            capture_output=True).returncode == 0 if shutil.which("git") else False
    if ref:
        dest.mkdir(parents=True)
        archive = subprocess.run(["git", "-C", str(REPO), "archive", ref],
                                 stdout=subprocess.PIPE, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)
    elif is_git:
        dest.mkdir(parents=True)
        files = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--cached", "--others",
                                "--exclude-standard"], stdout=subprocess.PIPE, check=True).stdout
        for name in files.decode().split("\0"):
            source = REPO / name
            if not name or not os.path.lexists(source):
                continue
            if exclude and source.is_relative_to(exclude):
                continue
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                os.symlink(os.readlink(source), target)
            elif source.is_file():
                shutil.copy2(source, target)
    else:
        shutil.copytree(REPO, dest, symlinks=True,
                        ignore=lambda d, names: [n for n in names if Path(d, n).resolve() == exclude])


class Runner:
    def __init__(self, args):
        self.args = args
        self.workdir = Path(args.workdir).resolve()
        self.results = []

    def log(self, msg):
        print(msg, flush=True)

    def run(self, cmd, log, cwd=None, env=None):
        if self.args.dry_run:
            self.log(f"    $ {'cd ' + str(cwd) + ' && ' if cwd else ''}{shlex.join(str(c) for c in cmd)}")
            return 0
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a") as f:
            f.write(f"$ {shlex.join(str(c) for c in cmd)}\n")
            f.flush()
            return subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT).returncode

    def base_env(self):
        env = os.environ.copy()
        for name in ENV_TO_CLEAR:
            env.pop(name, None)
        return env

    def snapshot(self):
        """Copy the source tree, so that it can be edited while the builds run
        and the make builds, which build in-tree, don't touch it."""
        dest = self.workdir / "src"
        if self.args.dry_run:
            self.log(f"Snapshot {self.args.ref or 'working tree'} of {REPO} into {dest}")
        else:
            snapshot_source(dest, self.args.ref, exclude=self.workdir)
        return dest

    def build(self, build_system, variant, asan, src, log):
        """Build a variant and return the directory containing the build, or
        None if it failed."""
        name = f"{build_system}-{variant.name}{'-asan' if asan else ''}"
        tree = self.workdir / name
        jobs = str(self.args.jobs)
        if not self.args.dry_run and tree.exists():
            shutil.rmtree(tree)
        if build_system == "cmake":
            generator = ["-G", "Ninja"] if shutil.which("ninja") else []
            steps = [["cmake", "-S", src, "-B", tree] + generator + cmake_configure_args(variant, asan),
                     ["cmake", "--build", tree, "--parallel", jobs]]
            cwd = None
        else:
            options = make_options(variant)
            if not self.args.dry_run:
                shutil.copytree(src, tree, symlinks=True)
                set_make_options(tree / "config.mk", options)
            else:
                self.log(f"    copy {src} to {tree} and set in config.mk: "
                         + " ".join(f"{k}={v}" for k, v in options.items()))
            margs = make_args(variant, asan)
            steps = [["make", "-j", jobs] + margs, ["make", "-j", jobs, "test-compile"] + margs]
            cwd = tree
        for cmd in steps:
            if self.run(cmd, log, cwd=cwd, env=self.base_env()) != 0:
                return None
        return tree

    def test(self, build_system, variant, mode, src, tree, result, logdir):
        env = self.base_env()
        sanitizer_dir = logdir / "sanitizer"
        valgrind_dir = logdir / "valgrind"
        test_tree = tree / "test"
        if mode == "asan":
            if not self.args.dry_run:
                shutil.rmtree(sanitizer_dir, ignore_errors=True)
                sanitizer_dir.mkdir(parents=True)
            # The tests discard the broker's output, so have the sanitizers
            # write their reports to files instead.
            env["ASAN_OPTIONS"] = f"log_path={sanitizer_dir}/asan:detect_leaks=1"
            if build_system == "make":
                # make links the static libmosquitto_common into the broker
                # and into each plugin, so ASan sees its global twice. CMake
                # builds it as a shared library with WITH_ASAN instead.
                env["ASAN_OPTIONS"] += ":detect_odr_violation=0"
            env["UBSAN_OPTIONS"] = f"log_path={sanitizer_dir}/ubsan:print_stacktrace=1:halt_on_error=1"
        elif mode == "valgrind":
            env["MOSQ_USE_VALGRIND"] = "1"
            if not self.args.dry_run:
                for vglog in test_tree.rglob("*.vglog"):
                    vglog.unlink()

        failures = []
        log = logdir / "test.log"
        jobs = self.args.test_jobs
        if mode == "valgrind":
            jobs = max(1, jobs // 2)
        if build_system == "cmake":
            cmd = ["ctest", "--test-dir", tree, "-j", str(jobs), "--output-on-failure",
                   "--resource-spec-file", src / "test" / "resource.json"]
            if self.args.repeat > 1:
                cmd += ["--repeat", f"until-pass:{self.args.repeat}"]
            if self.args.tests_regex:
                cmd += ["-R", self.args.tests_regex]
            if self.args.exclude_regex:
                cmd += ["-E", self.args.exclude_regex]
            rc = self.run(cmd, log, env=env)
            if rc != 0:
                failures.append("tests failed" + self.ctest_failures(log))
        else:
            env.update(make_test_feature_env(variant))
            # -k so that a failure in one group of tests doesn't stop the rest.
            rc = self.run(["make", "-k", self.args.make_target] + make_args(variant, mode == "asan"),
                          log, cwd=tree, env=env)
            if rc != 0:
                failures.append("tests failed")

        if self.args.stress_duration > 0 and variant.tls:
            script_tree = tree if build_system == "make" else src
            stress = [sys.executable, script_tree / "test" / "broker" / "08-ssl-hup-stress.py",
                      "--duration", str(self.args.stress_duration)]
            stress_env = env.copy()
            stress_env["BUILD_ROOT"] = str(tree)
            if self.run(stress, logdir / "stress.log", cwd=test_tree / "broker", env=stress_env) != 0:
                failures.append("stress test failed")

        if not self.args.dry_run:
            if mode == "asan":
                reports = sorted(p for p in sanitizer_dir.iterdir() if p.stat().st_size > 0)
                if reports:
                    failures.append(f"{len(reports)} sanitizer reports in {sanitizer_dir}")
            elif mode == "valgrind":
                bad = [p for p in test_tree.rglob("*.vglog") if VALGRIND_ERROR.search(p.read_text(errors="replace"))]
                if bad:
                    valgrind_dir.mkdir(parents=True, exist_ok=True)
                    for p in bad:
                        shutil.copy2(p, valgrind_dir / str(p.relative_to(test_tree)).replace(os.sep, "_"))
                    failures.append(f"{len(bad)} valgrind logs with errors in {valgrind_dir}")
        if failures:
            result.status = "FAIL"
            result.detail = "; ".join(failures)

    @staticmethod
    def ctest_failures(log):
        text = log.read_text(errors="replace")
        match = re.search(r"The following tests FAILED:\n((?:\s+\d+ - .*\n)+)", text)
        if not match:
            return ""
        names = re.findall(r"\d+ - (\S+)", match.group(1))
        shown = ", ".join(names[:5]) + (f", ... ({len(names)} total)" if len(names) > 5 else "")
        return f": {shown}"

    def run_all(self):
        variants = [v for v in VARIANTS if v.name in self.args.variant]
        src = self.snapshot()
        for build_system in self.args.build_system:
            for variant in variants:
                # plain and valgrind share an uninstrumented build.
                builds = []
                plain_modes = [m for m in self.args.mode if m in ("plain", "valgrind")]
                if plain_modes:
                    builds.append((False, plain_modes))
                if "asan" in self.args.mode:
                    builds.append((True, ["asan"]))
                for asan, modes in builds:
                    if not self.build_and_test(build_system, variant, asan, modes, src):
                        return

    def build_and_test(self, build_system, variant, asan, modes, src):
        """Returns False if the remaining runs should be abandoned."""
        runnable = []
        for mode in modes:
            reason = unmet_requirement(build_system, variant, mode)
            if reason:
                self.results.append(Result(build_system, variant.name, mode, "SKIP", reason))
                self.log(f"=== {build_system} {variant.name} {mode}: SKIP ({reason})")
            else:
                runnable.append(mode)
        if not runnable:
            return True

        name = f"{build_system}-{variant.name}{'-asan' if asan else ''}"
        logdir = self.workdir / "logs" / name
        if not self.args.dry_run:
            shutil.rmtree(logdir, ignore_errors=True)
        self.log(f"=== {build_system} {variant.name} ({variant.description}){' with sanitizers' if asan else ''}")
        start = time.monotonic()
        tree = self.build(build_system, variant, asan, src, logdir / "build.log")
        build_seconds = time.monotonic() - start
        if tree is None:
            for mode in runnable:
                self.results.append(Result(build_system, variant.name, mode, "FAIL", "build failed",
                                           logdir / "build.log", build_seconds))
            self.log(f"    build FAILED, see {logdir / 'build.log'}")
            return not self.args.fail_fast
        self.log(f"    built in {build_seconds:.0f}s")

        for mode in runnable:
            result = Result(build_system, variant.name, mode, log=logdir / mode)
            if not self.args.build_only:
                start = time.monotonic()
                self.log(f"    testing ({mode})")
                self.test(build_system, variant, mode, src, tree, result, logdir / mode)
                result.seconds = time.monotonic() - start
                self.log(f"    {mode}: {result.status} in {result.seconds:.0f}s"
                         f"{' - ' + result.detail if result.detail else ''}")
            else:
                result.detail = "built only"
            self.results.append(result)
            if result.status == "FAIL" and self.args.fail_fast:
                return False
        return True

    def summary(self):
        if not self.results:
            return ""
        rows = [("BUILD", "VARIANT", "MODE", "RESULT", "TIME", "DETAILS")]
        for r in self.results:
            detail = r.detail
            if r.status == "FAIL" and r.log:
                detail += f" (logs: {r.log})"
            rows.append((r.build_system, r.variant, r.mode, r.status,
                         f"{r.seconds / 60:.1f}m" if r.seconds else "-", detail))
        widths = [max(len(row[i]) for row in rows) for i in range(5)]
        lines = ["  ".join(c.ljust(w) for c, w in zip(row[:5], widths)) + "  " + row[5] for row in rows]
        counts = {s: sum(r.status == s for r in self.results) for s in ("PASS", "FAIL", "SKIP")}
        lines.append(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
        return "\n".join(lines)


def comma_list(choices):
    def parse(value):
        items = [v for v in value.split(",") if v]
        for item in items:
            if item not in choices:
                raise argparse.ArgumentTypeError(f"invalid choice {item!r}, choose from {', '.join(choices)}")
        return items
    return parse


def list_variants():
    print("Build systems: " + ", ".join(f"{b}{'' if probe(b) else ' (not found)'}" for b in BUILD_SYSTEMS))
    print("Modes: plain, asan" + ("" if probe("asan") else " (unavailable)") +
          ", valgrind" + ("" if probe("valgrind") else " (not found)"))
    print("Variants:")
    for v in VARIANTS:
        reason = unmet_requirement("cmake", v, "plain") if probe("cmake") else None
        print(f"  {v.name:16} {v.description}{f'  [SKIPPED: {reason}]' if reason else ''}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-b", "--build-system", type=comma_list(BUILD_SYSTEMS), default=BUILD_SYSTEMS,
                        help=f"comma separated build systems (default: {','.join(BUILD_SYSTEMS)})")
    parser.add_argument("-V", "--variant", type=comma_list([v.name for v in VARIANTS]),
                        default=[v.name for v in VARIANTS], help="comma separated variants (default: all, see --list)")
    parser.add_argument("-m", "--mode", type=comma_list(MODES), default=MODES,
                        help=f"comma separated test modes (default: {','.join(MODES)})")
    parser.add_argument("-R", "--tests-regex", help="only run the ctest tests matching this regex (cmake only)")
    parser.add_argument("-E", "--exclude-regex", help="don't run the ctest tests matching this regex (cmake only)")
    parser.add_argument("--make-target", default="test", choices=["test", "ptest"],
                        help="make target that runs the tests; ptest runs them in parallel (default: test)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="run failing ctest tests up to this many times, for timing related failures (default: 3)")
    parser.add_argument("--stress-duration", type=float, default=0,
                        help="also run test/broker/08-ssl-hup-stress.py for this many seconds for TLS builds")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count(), help="parallel build jobs (default: %(default)s)")
    parser.add_argument("--test-jobs", type=int, default=min(os.cpu_count(), 16),
                        help="parallel ctest jobs, halved under valgrind (default: %(default)s)")
    parser.add_argument("-w", "--workdir", default=str(REPO / "build-variants"),
                        help="directory for the source snapshot, builds and logs (default: %(default)s)")
    parser.add_argument("--ref", help="build this git ref instead of the working tree")
    parser.add_argument("--build-only", action="store_true", help="only build, don't run the tests")
    parser.add_argument("--fail-fast", action="store_true", help="stop at the first failure")
    parser.add_argument("-n", "--dry-run", action="store_true", help="print the commands instead of running them")
    parser.add_argument("--list", action="store_true", help="list the variants and whether they can be built here")
    args = parser.parse_args()

    if args.list:
        list_variants()
        return 0
    if (args.tests_regex or args.exclude_regex) and "make" in args.build_system:
        print("warning: -R/-E only apply to cmake builds, make builds run all their tests", file=sys.stderr)

    runner = Runner(args)
    try:
        runner.run_all()
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
    summary = runner.summary()
    if summary:
        print("\n" + summary)
        if not args.dry_run:
            (runner.workdir / "summary.txt").write_text(summary + "\n")
    return 1 if any(r.status == "FAIL" for r in runner.results) else 0


if __name__ == "__main__":
    sys.exit(main())
