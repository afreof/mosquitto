#!/usr/bin/env python3
"""Run the Linux CI workflows and the Docker build configurations in podman
containers, and report whether the tests that matter ran in each of them.

Three kinds of jobs are available, see --list:

  GitHub workflow jobs (linux, linux-asan, mosquitto-make, ...)
      The run steps of the job in .github/workflows are executed in a
      container that resembles the GitHub runner: the Ubuntu release behind
      ubuntu-latest, a few tools that the runner image provides
      (RUNNER_PACKAGES), and the packages the job installs with apt-get.
      Steps that use an action (checkout, cache, upload) are skipped.

  docker-* jobs
      Build the working tree with the base image, build dependencies and
      build options of a Dockerfile in docker/, then run the tests. The
      Dockerfiles only build, so the packages the tests need on top are
      added (TEST_PACKAGES) and listed in the summary.

  variants-* jobs
      Run test/build_variants.py in the dev containers of .devcontainer/, e.g.
      to test the OpenSSL ENGINE and libwebsockets variants that need packages
      the host lacks.

The source is a snapshot of the working tree (or --ref) and every job builds in
its own copy of it, so jobs neither touch the working tree nor each other.
Containers have their own network namespace, so jobs can run in parallel
(--parallel) without port clashes between their tests.

Examples:

  test/podman_ci.py --list
  test/podman_ci.py linux linux-asan mosquitto-make docker-local
  test/podman_ci.py variants-ubuntu --variants-args="-V engine,websockets-lws -m plain,valgrind"
  test/podman_ci.py --shell docker-local
  test/podman_ci.py --shell variants-ubuntu
"""

import argparse
import concurrent.futures
import dataclasses
import fnmatch
import hashlib
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_variants import snapshot_source  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
DOCKER = REPO / "docker"
DEVCONTAINER = REPO / ".devcontainer"

# Workflows that only build and test, without needing external services.
WORKFLOW_FILES = ["linux", "linux-asan", "mosquitto-make", "linux-build-variants", "coverage"]
DOCKER_DIRS = ["local", "2.1-alpine", "2.1-ubuntu"]
DEVCONTAINERS = ["ubuntu", "alpine"]

RUNS_ON = {"ubuntu-latest": "ubuntu:24.04", "ubuntu-24.04": "ubuntu:24.04", "ubuntu-22.04": "ubuntu:22.04"}

# Tools that the workflows use without installing them, because the GitHub
# runner image provides them.
RUNNER_PACKAGES = ["build-essential", "ca-certificates", "clang", "cmake", "git", "libsqlite3-dev",
                   "ninja-build", "openssl", "python3", "sudo"]

# What the tests need on top of the build dependencies of the Dockerfiles.
TEST_PACKAGES = {
    "alpine": ["bash", "cmake", "cunit-dev", "gtest-dev", "openssl", "pkgconf", "py3-paho-mqtt",
               "py3-psutil", "python3", "samurai", "uthash-dev"],
    "ubuntu": ["cmake", "libcunit1-dev", "libgmock-dev", "ninja-build", "openssl", "python3",
               "python3-paho-mqtt", "python3-psutil", "uthash-dev"],
}

SRC = "/work/src"

# The ctest invocation of the workflows.
CTEST = "ctest -j20 --resource-spec-file ../test/resource.json --output-on-failure --repeat until-pass:5"


@dataclasses.dataclass
class Step:
    name: str
    run: str
    env: dict = dataclasses.field(default_factory=dict)
    workdir: str = ""
    continue_on_error: bool = False
    # Why the step isn't run, if it isn't.
    skipped: str = ""


@dataclasses.dataclass
class Image:
    base: str
    packages: list
    # A Dockerfile to build, with the packages installed on top, instead of
    # installing the packages in the base image.
    dockerfile: Path | None = None

    @classmethod
    def from_dockerfile(cls, path):
        base = re.search(r"^FROM\s+(\S+)", path.read_text(), re.MULTILINE).group(1)
        return cls(base, [], path)

    @property
    def distro(self):
        return "alpine" if "alpine" in self.base else "ubuntu"

    def containerfile(self):
        packages = " ".join(sorted(set(self.packages)))
        if self.distro == "alpine":
            install = f"apk --no-cache add {packages}"
        else:
            install = (f"apt-get update && apt-get install -y {packages} && "
                       "rm -rf /var/lib/apt/lists/*")
        if self.dockerfile:
            text = self.dockerfile.read_text()
            if self.packages:
                text += f"USER root\nENV DEBIAN_FRONTEND=noninteractive\nRUN {install}\n"
            return text
        base = self.base if "/" in self.base else f"docker.io/library/{self.base}"
        return f"FROM {base}\nENV DEBIAN_FRONTEND=noninteractive\nRUN {install}\n"

    @property
    def context(self):
        """The build context, if the image needs one."""
        return self.dockerfile.parent if self.dockerfile else None

    @property
    def tag(self):
        digest = hashlib.sha256(self.containerfile().encode()).hexdigest()[:12]
        return f"localhost/mosquitto-test:{self.distro}-{digest}"


@dataclasses.dataclass
class Job:
    name: str
    description: str
    image: Image
    steps: list
    source: str
    # Packages added to what the job's source installs, to be able to test.
    added_packages: list = dataclasses.field(default_factory=list)
    unsupported: str = ""


# GitHub expressions

class UnsupportedExpression(Exception):
    pass


_TOKEN = re.compile(r"'(?:[^']|'')*'|[A-Za-z_][\w.\-]*|==|!=|&&|\|\||!|\(|\)|\S")


def eval_expression(expr, context):
    out = []
    for token in _TOKEN.findall(expr):
        if token.startswith("'"):
            out.append(repr(token[1:-1].replace("''", "'")))
        elif token in ("true", "false", "null"):
            out.append({"true": "True", "false": "False", "null": "None"}[token])
        elif token in ("==", "!=", "(", ")"):
            out.append(token)
        elif token in ("&&", "||", "!"):
            out.append({"&&": "and", "||": "or", "!": "not"}[token])
        elif re.match(r"[A-Za-z_]", token):
            if token.startswith("secrets."):
                out.append("''")
            elif token in context:
                out.append(repr(context[token]))
            else:
                raise UnsupportedExpression(token)
        else:
            raise UnsupportedExpression(expr)
    return eval(" ".join(out), {"__builtins__": {}})


def substitute(text, context):
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: str(eval_expression(m.group(1), context)), str(text))


def apt_packages(run):
    packages = []
    for match in re.finditer(r"apt-get install((?:\s+(?!&&)[^\s;&|]+)+)", run.replace("\\\n", " ")):
        packages += [p for p in match.group(1).split() if not p.startswith("-")]
    return packages


def workflow_jobs(event):
    jobs = []
    for wf in WORKFLOW_FILES:
        path = WORKFLOWS / f"{wf}.yml"
        data = yaml.safe_load(path.read_text())
        for job_id, job in data.get("jobs", {}).items():
            name = wf if len(data["jobs"]) == 1 else f"{wf}:{job_id}"
            context = {"github.workspace": SRC, "github.event_name": event, "runner.os": "Linux"}
            packages = list(RUNNER_PACKAGES)
            steps = []
            unsupported = ""
            runs_on = job.get("runs-on")
            base = RUNS_ON.get(runs_on)
            if base is None:
                unsupported = f"runs-on {runs_on}"
                base = "ubuntu:24.04"
            env = {**data.get("env", {}), **job.get("env", {})}
            default_wd = job.get("defaults", {}).get("run", {}).get("working-directory", "")
            try:
                for number, step in enumerate(job.get("steps", []), 1):
                    label = step.get("name") or step.get("uses") or step.get("run", "").splitlines()[0]
                    label = f"{number}: {label.rstrip(' \\')}"
                    if "if" in step:
                        cond = re.sub(r"^\$\{\{\s*(.*?)\s*\}\}$", r"\1", str(step["if"]).strip())
                        if not eval_expression(cond, context):
                            steps.append(Step(label, "", skipped=f"condition is false: {cond}"))
                            continue
                    if "uses" in step:
                        steps.append(Step(label, "", skipped=f"uses {step['uses']}"))
                        continue
                    if step.get("shell", "bash") != "bash":
                        raise UnsupportedExpression(f"shell {step['shell']}")
                    run = step["run"]
                    if "apt-get install" in run:
                        packages += apt_packages(run)
                        steps.append(Step(label, "", skipped="the packages are installed in the image"))
                        continue
                    steps.append(Step(label, substitute(run, context),
                                      {k: substitute(v, context) for k, v in {**env, **step.get("env", {})}.items()},
                                      substitute(step.get("working-directory", default_wd), context),
                                      bool(step.get("continue-on-error", False))))
            except UnsupportedExpression as e:
                unsupported = f"unsupported expression {e}"
            jobs.append(Job(name, data.get("name", wf), Image(base, packages), steps,
                            str(path.relative_to(REPO)), unsupported=unsupported))
    return jobs


def dockerfile_run(path):
    """The commands of the Dockerfile's RUN instruction, as one line."""
    text = path.read_text().replace("\\\n", " ")
    match = re.search(r"^RUN\s+(.*)$", text, re.MULTILINE)
    return match.group(1)


def docker_jobs():
    jobs = []
    for name in DOCKER_DIRS:
        path = DOCKER / name / "Dockerfile"
        base = re.search(r"^FROM\s+(\S+)", path.read_text(), re.MULTILINE).group(1)
        run = dockerfile_run(path)
        commands = [c.strip() for c in run.split("&&")]
        packages = []
        build = []
        for command in commands:
            words = shlex.split(command)
            if words[:3] == ["apk", "--no-cache", "add"] and "build-deps" in words and not packages:
                packages = [w for w in words[3:] if not w.startswith("-") and w != "build-deps"]
            elif words[:3] == ["apt-get", "install", "-y"] and not packages:
                packages = words[3:]
            elif words[:1] == ["make"] and "/build/mosq" in words:
                build = make_build_steps(words)
            elif words[:2] == ["cmake", "-G"]:
                build = cmake_build_steps(words)
        image = Image(base, packages + TEST_PACKAGES[Image(base, []).distro])
        added = sorted(set(TEST_PACKAGES[image.distro]) - set(packages))
        jobs.append(Job(f"docker-{name}", f"Dockerfile build options of docker/{name}, plus the tests",
                        image, build, str(path.relative_to(REPO)), added))
    return jobs


def make_build_steps(words):
    """make -C /build/mosq -j "$(nproc)" VAR=... binary

    The options that config.mk sets are set there instead of on the command
    line, see build_variants.set_make_options()."""
    config_mk = (REPO / "config.mk").read_text()
    variables = [w for w in words[1:] if "=" in w and not w.startswith("-")]
    options = {}
    for v in variables:
        name, value = v.split("=", 1)
        if re.search(rf"^{re.escape(name)}\s*:?=", config_mk, re.MULTILINE):
            options[name] = value
    args = shlex.join(v for v in variables if v.split("=", 1)[0] not in options)
    configure = "python3 -c " + shlex.quote(
        "import sys; sys.path.insert(0, 'test'); from pathlib import Path; "
        "from build_variants import set_make_options; "
        f"set_make_options(Path('config.mk'), {options!r})")
    return [
        Step("set the Dockerfile's options in config.mk: " + " ".join(f"{k}={v}" for k, v in options.items()),
             configure),
        Step("build (make binary, as in the Dockerfile)", f'make -j"$(nproc)" {args} binary'),
        Step("compile the tests", f'make -j"$(nproc)" {args} test-compile'),
        Step("make ptest", f"make {args} ptest"),
    ]


def cmake_build_steps(words):
    """cmake -G Ninja ... -S /build/mosq -B /build/mosq/build"""
    words = [w.replace("/build/mosq", SRC) for w in words]
    return [
        Step("configure (as in the Dockerfile)", shlex.join(words)),
        Step("build", 'cmake --build build --parallel "$(nproc)"'),
        Step("ctest", CTEST, workdir="build"),
    ]


def variant_jobs(variants_args):
    jobs = []
    for name in DEVCONTAINERS:
        dockerfile = DEVCONTAINER / name / "Dockerfile"
        run = f"python3 test/build_variants.py -w /work/variants {variants_args}"
        jobs.append(Job(f"variants-{name}",
                        f"test/build_variants.py {variants_args or '(all variants)'} in the dev container",
                        Image.from_dockerfile(dockerfile), [Step("build_variants.py", run)],
                        str(dockerfile.relative_to(REPO))))
    return jobs


def job_script(job, ccache):
    lines = [
        "#!/bin/bash",
        "set -e",
        f"export HOME=/work/home CI=true GITHUB_ACTIONS=true GITHUB_WORKSPACE={SRC} "
        "GITHUB_ENV=/work/github_env RUNNER_OS=Linux RUNNER_TEMP=/work/tmp",
        'rm -rf "$GITHUB_WORKSPACE" /work/tmp /work/home "$GITHUB_ENV"',
        'mkdir -p /work/tmp /work/home && : > "$GITHUB_ENV"',
        'cp -a /src "$GITHUB_WORKSPACE"',
    ]
    for step in job.steps:
        if step.skipped:
            lines.append(f"echo; echo {shlex.quote(f'::: step {step.name} (skipped, {step.skipped})')}")
            continue
        exports = "".join(f"export {k}={shlex.quote(str(v))}\n" for k, v in step.env.items())
        if ccache:
            # Keep the compiler cache across runs, whatever the job sets.
            exports += "export CCACHE_DIR=/ccache\n"
        workdir = f'"$GITHUB_WORKSPACE"/{shlex.quote(step.workdir)}' if step.workdir else '"$GITHUB_WORKSPACE"'
        failed = "true" if step.continue_on_error else "exit 1"
        lines += [
            f"echo; echo {shlex.quote('::: step ' + step.name)}",
            "(",
            'set -a; . "$GITHUB_ENV"; set +a',
            exports.rstrip("\n"),
            f"cd {workdir}",
            f"exec bash -e -c {shlex.quote(step.run)}",
            f") || {{ echo {shlex.quote('::: step failed: ' + step.name)}; {failed}; }}",
        ]
    lines.append("echo; echo '::: job succeeded'")
    return "\n".join(line for line in lines if line) + "\n"


def watched_tests(log_text, pattern):
    """How the tests matching pattern ended, from ctest or ptest output. A test
    that ran more than once, e.g. for several build variants, is reported as
    passed only if it passed every time, and as failed if it ever failed."""
    results = {}

    def rank(status):
        return 0 if status == "passed" else 2 if status == "failed" else 1

    def add(name, status):
        if rank(status) >= rank(results.get(name, "passed")):
            results[name] = status

    for m in re.finditer(r"Test\s+#\d+: (\S+) \.*\s*(?:\*\*\*)?([A-Za-z][A-Za-z ]*?)\s+[\d.]+ sec", log_text):
        if re.search(pattern, m.group(1)):
            add(m.group(1), m.group(2).lower())
    for m in re.finditer(r"^.*?([✓✗]).*?(\S+\.py)", log_text, re.MULTILINE):
        if re.search(pattern, m.group(2)):
            add(m.group(2), "passed" if m.group(1) == "✓" else "failed")
    # Serial make test prints the name of each test before running it, and
    # make's error after the test that failed.
    last = None
    for line in log_text.splitlines():
        if m := re.match(r"\./(\S+\.py)$", line):
            last = m.group(1)
            if re.search(pattern, last):
                add(last, "passed")
        elif last and (m := re.match(r"make\[\d+\]: \*\*\* .* Error (\d+)$", line)):
            if re.search(pattern, last):
                add(last, "skipped" if m.group(1) == "77" else "failed")
            last = None
    return results


def summarise_watched(results):
    if not results:
        return "none ran"
    by_status = {}
    for name, status in sorted(results.items()):
        by_status.setdefault(status, []).append(name)
    parts = []
    for status, names in sorted(by_status.items()):
        if status == "passed":
            parts.append(f"{len(names)} passed")
        else:
            parts.append(f"{len(names)} {status} ({', '.join(Path(n).stem for n in names)})")
    return ", ".join(parts)


class PodmanCI:
    def __init__(self, args):
        self.args = args
        self.workdir = Path(args.workdir).resolve()
        self.print_lock = threading.Lock()
        self.image_locks = {}

    def log(self, msg):
        with self.print_lock:
            print(msg, flush=True)

    def ensure_image(self, image):
        lock = self.image_locks.setdefault(image.tag, threading.Lock())
        with lock:
            exists = subprocess.run(["podman", "image", "exists", image.tag]).returncode == 0
            if exists and not self.args.pull:
                return True
            imagedir = self.workdir / "images" / image.tag.rsplit(":", 1)[1]
            imagedir.mkdir(parents=True, exist_ok=True)
            containerfile = imagedir / "Containerfile"
            containerfile.write_text(image.containerfile())
            log = imagedir / "build.log"
            self.log(f"--- building image {image.tag} (log: {log})")
            cmd = (["podman", "build", "-t", image.tag, "-f", str(containerfile)]
                   + (["--pull=always"] if self.args.pull else []) + [str(image.context or imagedir)])
            with open(log, "w") as f:
                ok = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode == 0
            if not ok:
                self.log(f"--- building image {image.tag} FAILED, see {log}")
            return ok

    def podman_run(self, job, command, interactive=False):
        jobdir = self.workdir / "jobs" / job.name.replace(":", "-")
        jobdir.mkdir(parents=True, exist_ok=True)
        cmd = ["podman", "run", "--rm", "--init", "--userns=keep-id", "--security-opt", "label=disable",
               # The GitHub runner's /etc/hosts has these, and the socks tests use them.
               "--add-host", "ip6-localhost:::1", "--add-host", "ip6-loopback:::1",
               "--hostname", "runner", "-v", f"{self.workdir / 'src'}:/src:ro", "-v", f"{jobdir}:/work",
               "-w", "/work"]
        if not self.args.no_ccache:
            ccache = self.workdir / "ccache" / job.image.distro
            ccache.mkdir(parents=True, exist_ok=True)
            cmd += ["-v", f"{ccache}:/ccache"]
        if interactive:
            cmd += ["-it"]
        return jobdir, cmd + [job.image.tag] + command

    def run_job(self, job):
        start = time.monotonic()
        if job.unsupported:
            return job, "SKIP", job.unsupported, None, 0
        if not self.ensure_image(job.image):
            return job, "FAIL", "image build failed", None, 0
        jobdir, cmd = self.podman_run(job, ["bash", "/work/run.sh"])
        shutil.rmtree(jobdir / "variants" / "logs", ignore_errors=True)
        (jobdir / "run.sh").write_text(job_script(job, not self.args.no_ccache))
        log = jobdir / "job.log"
        self.log(f"--- {job.name}: started (log: {log})")
        with open(log, "w") as f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    errors="replace")
            for line in proc.stdout:
                f.write(line)
                if self.args.verbose:
                    self.log(f"[{job.name}] {line.rstrip()}")
                elif line.startswith("::: step"):
                    self.log(f"[{job.name}] {line.strip()[4:]}")
            rc = proc.wait()
        seconds = time.monotonic() - start
        text = log.read_text(errors="replace")
        failed_step = re.findall(r"^::: step failed: (.*)$", text, re.MULTILINE)
        # The test output of build_variants.py is in its logs.
        for test_log in sorted((jobdir / "variants" / "logs").glob("**/test.log")):
            text += test_log.read_text(errors="replace")
        status = "PASS" if rc == 0 else "FAIL"
        detail = f"step {failed_step[-1]} failed" if failed_step else ("" if rc == 0 else f"exit code {rc}")
        self.log(f"--- {job.name}: {status} in {seconds / 60:.1f}m{' - ' + detail if detail else ''}")
        return job, status, detail, text, seconds

    def snapshot(self):
        snapshot_source(self.workdir / "src", self.args.ref, exclude=self.workdir)


def all_jobs(args):
    jobs = workflow_jobs(args.event) + docker_jobs() + variant_jobs(args.variants_args)
    extra = [p for p in args.add_packages.split(",") if p]
    if extra:
        for job in jobs:
            job.image = dataclasses.replace(job.image, packages=job.image.packages + extra)
            job.added_packages = job.added_packages + extra
    return jobs


def select_jobs(jobs, patterns):
    if not patterns:
        return [j for j in jobs if not j.name.startswith("variants-")]
    selected = []
    for pattern in patterns:
        matches = [j for j in jobs if fnmatch.fnmatch(j.name, pattern)]
        if not matches:
            sys.exit(f"no job matches {pattern!r}, see --list")
        selected += [j for j in matches if j not in selected]
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("jobs", nargs="*", help="jobs to run, shell patterns allowed (default: all but variants-*)")
    parser.add_argument("--list", action="store_true", help="list the jobs")
    parser.add_argument("--show", action="store_true", help="print the Containerfile and script of the jobs")
    parser.add_argument("--shell", action="store_true",
                        help="open a shell in the container of the (single) job, with the source in /src")
    parser.add_argument("--event", default="push", choices=["push", "pull_request", "schedule", "workflow_dispatch"],
                        help="github.event_name for the workflows' if conditions (default: push)")
    parser.add_argument("--ref", help="test this git ref instead of the working tree")
    parser.add_argument("--variants-args", default="", help="arguments for build_variants.py in the variants-* jobs")
    parser.add_argument("--add-packages", default="",
                        help="comma separated packages to add to the images, e.g. to try out a fix")
    parser.add_argument("--watch", default="hup",
                        help="regex of tests to report on per job, to see whether they ran (default: %(default)s)")
    parser.add_argument("-p", "--parallel", type=int, default=1, help="jobs to run at the same time (default: 1)")
    parser.add_argument("-w", "--workdir", default=str(REPO / "build-podman"),
                        help="directory for images, the source snapshot and the job directories (default: %(default)s)")
    parser.add_argument("--pull", action="store_true", help="update the base images and rebuild the job images")
    parser.add_argument("--no-ccache", action="store_true", help="don't keep a compiler cache in the workdir")
    parser.add_argument("-v", "--verbose", action="store_true", help="print the output of the jobs")
    args = parser.parse_args()

    jobs = all_jobs(args)
    if args.list:
        for job in jobs:
            note = f"  [SKIPPED: {job.unsupported}]" if job.unsupported else ""
            print(f"{job.name:22} {job.description} ({job.source}){note}")
        return 0
    jobs = select_jobs(jobs, args.jobs)
    if args.show:
        for job in jobs:
            print(f"##### {job.name}\n### {job.image.tag}\n{job.image.containerfile()}### run.sh")
            print(job_script(job, not args.no_ccache))
        return 0
    if shutil.which("podman") is None:
        sys.exit("podman not found")

    ci = PodmanCI(args)
    ci.snapshot()
    if args.shell:
        if len(jobs) != 1:
            sys.exit("--shell needs exactly one job")
        if not ci.ensure_image(jobs[0].image):
            return 1
        _, cmd = ci.podman_run(jobs[0], ["bash"], interactive=True)
        return subprocess.run(cmd).returncode

    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            for result in pool.map(ci.run_job, jobs):
                results.append(result)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)

    rows = [("JOB", "RESULT", "TIME", f"TESTS /{args.watch}/", "DETAILS")]
    for job, status, detail, text, seconds in results:
        watched = summarise_watched(watched_tests(text, args.watch)) if text is not None else "-"
        if job.added_packages:
            detail = (detail + "; " if detail else "") + "added for testing: " + " ".join(job.added_packages)
        rows.append((job.name, status, f"{seconds / 60:.1f}m" if seconds else "-", watched, detail))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    summary = "\n".join("  ".join(c.ljust(w) for c, w in zip(r[:4], widths)) + "  " + r[4] for r in rows)
    print("\n" + summary)
    (ci.workdir / "summary.txt").write_text(summary + "\n")
    return 1 if any(r[1] == "FAIL" for r in results) or len(results) < len(jobs) else 0


if __name__ == "__main__":
    sys.exit(main())
