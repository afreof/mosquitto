# Tests

## Running

The Mosquitto test suite can be invoked using either of

```
make test
make check
```

The tests run in series and due to the nature of some of the tests being made
can take a while.

Tests that need a feature the build doesn't have are skipped. They find out
from `WITH_*` environment variables, which CMake sets for ctest, and which
make sets for the options given on its command line, e.g.
`make WITH_TLS=no test`, but not for those only changed in `config.mk`. make
has no notion of skipped tests, so `make test` only prints
`Skipping test: ...` for them, while `make ptest` and ctest report them as
skipped.

## Parallel Tests

To run the tests with some parallelism, use

```
make ptest
```

This runs up to 20 tests in parallel at once, yielding much faster overall run
time at the expense of having up to 20 instances of Python running at once.
This is not a particularly CPU intensive option, but does require more memory
and may be unsuitable on e.g. a Raspberry Pi.

## Memory checking

### Valgrind

Setting `MOSQ_USE_VALGRIND=1` makes the tests run every broker they start under
valgrind memcheck, with full leak checking:

```
cd build
MOSQ_USE_VALGRIND=1 ctest -R '^broker-'
```

Valgrind doesn't change the result of a test. Instead it writes a
`<config>.<n>.vglog` file in the test's working directory
(`build/test/broker` for CMake builds, `test/broker` for make builds) for each
broker it ran. Empty logs are removed when the test exits, so any `.vglog`
files left behind need inspecting. They include memory that is still reachable
at exit, mostly from OpenSSL. Look for `definitely lost`, `Invalid read`,
`Invalid write` and `uninitialised` instead. Logs from different tests can share
a name and overwrite each other, so rerun a test on its own when investigating.

Brokers are much slower under valgrind, so a few tests that depend on timing
can fail without there being a memory error.

### Sanitizers

The CMake build can instrument the broker, libraries, plugins and test
helpers with AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer:

```
cmake -B build-asan -DWITH_ASAN=ON
cmake --build build-asan
cd build-asan
ctest
```

This needs the sanitizer runtime libraries, e.g. the `libasan` and `libubsan`
packages on Fedora. `WITH_ASAN` builds `libmosquitto_common` as a shared
library by default, because a static copy in the broker and in each plugin
makes AddressSanitizer report an ODR violation when a plugin is loaded. The
make build has a similar `WITH_ASAN=yes` option in `config.mk`, which uses
clang and only enables AddressSanitizer; it always links the static
`libmosquitto_common`, so run it with `ASAN_OPTIONS=detect_odr_violation=0`.

When a sanitizer finds a problem, the broker prints a report to its log and
exits with a non-zero status. Tests that use `MosquittoBroker` fail when that
happens. Older tests that start the broker with `mosq_test.start_broker()`
don't check its exit status, so check their output for `ERROR:
AddressSanitizer`, `ERROR: LeakSanitizer` and `runtime error:` as well.

## Stress testing TLS reloading

`test/broker/08-ssl-hup-stress.py` repeatedly rotates the server certificate,
CA file and CRL of a TLS listener, sometimes to broken or missing files, and
sends SIGHUP to the broker, while clients keep connecting, publishing and
receiving messages. The normal test run only runs it for 5 seconds. For longer
runs, run it from `test/broker` with a sanitizer build, or under valgrind:

```
cd test/broker
BUILD_ROOT=../../build-asan ./08-ssl-hup-stress.py --duration 300
BUILD_ROOT=../../build MOSQ_USE_VALGRIND=1 ./08-ssl-hup-stress.py --duration 120
```

`--workers`, `--long-clients` and `--seed` change the workload, see `--help`.

It fails if the broker crashes or doesn't exit cleanly, a sanitizer or
valgrind error is reported, a long-lived client loses its connection, or new
clients are refused once a valid configuration has been restored.
Unexpected worker-thread failures and threads that fail to stop also fail the
test. Unlike the other tests, it checks its `.vglog` file for memory errors
and definitely or indirectly lost allocations; still-reachable allocations do
not fail the test. If it fails, the broker log is kept in
`08-ssl-hup-stress.log`.

## Development containers

`.devcontainer/ubuntu` and `.devcontainer/alpine` define development
containers with everything needed to build mosquitto with make and CMake and
to run all tests, including under valgrind and with libwebsockets, and with
the sanitizers and OpenSSL ENGINE support on Ubuntu or musl libc on Alpine.
Open the repository in VS Code and choose "Dev Containers: Reopen in
Container", or use the dev container CLI:

```
devcontainer up --workspace-folder . --config .devcontainer/ubuntu/devcontainer.json
devcontainer exec --workspace-folder . --config .devcontainer/ubuntu/devcontainer.json bash
```

They work with Docker and with rootless podman. For podman, set
`dev.containers.dockerPath` to `podman` in VS Code, or pass
`--docker-path podman` to the CLI.

## Testing build variants

`test/build_variants.py` builds the broker with make and CMake in several
configurations (with and without TLS, TLS-PSK, OpenSSL ENGINE support,
builtin websockets or libwebsockets, threading, ...) and runs the tests for
each in three modes: plain, with AddressSanitizer and
UndefinedBehaviorSanitizer, and with every broker run under valgrind. A
sanitizer report or a valgrind error fails the run even when the tests pass.
It builds from a snapshot of the working tree in `build-variants/`, and skips
the variants whose dependencies are missing:

```
test/build_variants.py --list
test/build_variants.py -b cmake,make -V default,no-tls -m plain,asan
test/build_variants.py -m asan,valgrind -R '08-ssl-hup' --stress-duration 60
```

`-R` and `-E` only filter the CMake builds; the make builds always run their
complete `make test`, which takes about 30 minutes under valgrind.

The development containers have everything that all variants need:

```
devcontainer exec --workspace-folder . --config .devcontainer/ubuntu/devcontainer.json \
    test/build_variants.py -V engine,websockets-lws -m plain,asan,valgrind
```

## Testing in the CI and Docker environments

`test/podman_ci.py` runs the Linux GitHub workflows in podman containers, by
executing the `run` steps of their jobs in an image with the packages the jobs
install. It also builds the source with the build dependencies and options of
the Dockerfiles in `docker/`, which don't run the tests themselves, and then
runs the tests, and it can run `test/build_variants.py` in the development
containers, e.g. to cover the libwebsockets and OpenSSL ENGINE variants:

```
test/podman_ci.py --list
test/podman_ci.py linux linux-asan mosquitto-make docker-local
test/podman_ci.py variants-ubuntu --variants-args="-V engine,websockets-lws"
test/podman_ci.py --shell variants-alpine
```

The summary shows how the tests matching `--watch` (by default the SIGHUP
reload tests) ended in each job, to spot tests that are skipped or not run
in an environment, and which packages were added to a Dockerfile's to be able
to run the tests.

## Dependencies

The tests require Python 3 and CUnit to be installed.
