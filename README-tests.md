# Tests

## Running

The Mosquitto test suite can be invoked using either of

```
make test
make check
```

The tests run in series and due to the nature of some of the tests being made
can take a while.

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

## Dependencies

The tests require Python 3 and CUnit to be installed.
