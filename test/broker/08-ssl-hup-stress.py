#!/usr/bin/env python3

# Stress test reloading TLS listeners with SIGHUP.
#
# While a reloader thread repeatedly rotates the server certificate, the CA
# file and the CRL (sometimes to broken or missing files) and sends SIGHUP to
# the broker, worker threads keep making short-lived TLS connections, and
# long-lived TLS clients receive a continuous stream of messages from a
# publisher on a plain listener.
#
# The defaults are a short run for the normal test run. For longer runs, use
# a sanitizer build (cmake -DWITH_ASAN=ON) or valgrind (MOSQ_USE_VALGRIND=1),
# see README-tests.md. The test fails if the broker crashes or doesn't exit
# cleanly, reports a sanitizer or valgrind error, a long-lived client loses
# its connection, the broker doesn't accept clients once a valid
# configuration is restored, or a workload thread fails unexpectedly or
# doesn't stop.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
from tls_helper import replace_file, tls_connect

import argparse
import collections
import random
import threading

mosq_test.require_features(["WITH_TLS"])

parser = argparse.ArgumentParser(description="Stress test reloading TLS listeners with SIGHUP.")
parser.add_argument("--duration", type=float, default=5, help="seconds to run for (default: 5)")
parser.add_argument("--workers", type=int, default=4, help="threads making short-lived connections (default: 4)")
parser.add_argument("--long-clients", type=int, default=2, help="long-lived TLS clients (default: 2)")
parser.add_argument("--seed", type=int, default=1, help="random seed (default: 1)")
parser.add_argument("ports", type=int, nargs="*", help="ports for the TLS and the plain listener, as passed by the test runner")
args = parser.parse_args()
if len(args.ports) not in (0, 2):
    parser.error("expected two ports")
# Leave only the ports for mosq_test.get_port().
sys.argv[1:] = [str(p) for p in args.ports]
tls_port, plain_port = mosq_test.get_port(2)

# The server certificates don't include their signing CA, and the broker can't
# send it while cafile is rotated to an unrelated CA, so the clients trust both.
CLIENT_CAFILE = "all-ca.crt"
# Logged by valgrind for memory errors and for definitely or indirectly lost
# allocations, but not for still reachable ones.
VALGRIND_ERRORS = ["are definitely lost", "are indirectly lost", "Invalid read", "Invalid write",
                   "Invalid free", "Mismatched free", "uninitialised", "Syscall param",
                   "Source and destination overlap"]
SANITIZER_ERRORS = ["ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:"]


class Stats:
    def __init__(self):
        self._c = collections.Counter()
        self._lock = threading.Lock()

    def inc(self, key, n=1):
        with self._lock:
            self._c[key] += n

    def snapshot(self):
        with self._lock:
            return dict(self._c)


stats = Stats()
errors = []
errors_lock = threading.Lock()
# Set once the broker is being stopped, after which thread failures are an
# expected consequence of that, rather than errors in their own right.
teardown = threading.Event()


def error(msg):
    with errors_lock:
        errors.append(msg)


def thread_error(msg):
    if not teardown.is_set():
        error(msg)


def run_worker(target, *worker_args):
    try:
        target(*worker_args)
    except Exception as e:
        thread_error(f"{threading.current_thread().name} failed: {type(e).__name__}: {e}")


def join_thread(thread, timeout):
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"thread {thread.name} did not stop within {timeout}s")


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        data = sock.recv(n - len(buf))
        if not data:
            raise ConnectionError("connection closed")
        buf += data
    return buf


def read_packet(sock):
    cmd = recv_exact(sock, 1)[0]
    mult, length = 1, 0
    while True:
        b = recv_exact(sock, 1)[0]
        length += (b & 127) * mult
        mult *= 128
        if not b & 128:
            break
    return cmd, recv_exact(sock, length) if length else b""


# --- workload --------------------------------------------------------------

def short_worker(idx, port, stop):
    rnd = random.Random(args.seed * 1000 + idx)
    n = 0
    while not stop.is_set():
        n += 1
        r = rnd.random()
        try:
            if r < 0.1:
                # Broken handshake: a truncated ClientHello, then disconnect.
                raw = socket.create_connection(("localhost", port), timeout=10)
                raw.sendall(b"\x16\x03\x01\x02\x00" + rnd.randbytes(rnd.randint(0, 40)))
                time.sleep(rnd.uniform(0, 0.05))
                raw.close()
                stats.inc("short_aborted")
                continue
            cert = "client-revoked" if r < 0.25 else "client"
            # The broker has accepted the TCP connection, and created its SSL
            # object, before the handshake starts, possibly after a reload.
            delay = rnd.uniform(0, 0.2) if r > 0.7 else 0.0
            s = tls_connect(port, f"short-{idx}-{n}", cert=cert, keepalive=60,
                            cafile=CLIENT_CAFILE, delay=delay, timeout=10)
            mid = rnd.randint(1, 65535)
            s.sendall(mqtt_packets.gen_publish("stress/short", qos=1, mid=mid, payload=b"x"))
            cmd, body = read_packet(s)
            if cmd != 0x40:
                raise ConnectionError(f"expected PUBACK, got {cmd:#x}")
            s.sendall(mqtt_packets.gen_disconnect())
            s.close()
            stats.inc(f"short_ok_{cert}")
        except OSError:
            # Includes ssl.SSLError and ConnectionError.
            stats.inc("short_refused")


class LongClient(threading.Thread):
    def __init__(self, idx, port, stop):
        super().__init__(name=f"long-client-{idx}", daemon=True)
        self.idx = idx
        self.stop = stop
        self.sock = tls_connect(port, f"long-{idx}", keepalive=600, cafile=CLIENT_CAFILE)
        self.sock.sendall(mqtt_packets.gen_subscribe(1, "stress/long", 0))
        cmd, _ = read_packet(self.sock)
        if cmd != 0x90:
            raise ConnectionError("expected SUBACK")
        self.received = 0
        self.pings = 0
        self.pongs = 0
        self.max_gap = 0.0
        self.ok = False

    def run(self):
        last = time.monotonic()
        try:
            self.sock.settimeout(30)
            while not self.stop.is_set():
                cmd, _ = read_packet(self.sock)
                now = time.monotonic()
                if cmd & 0xF0 == 0x30:
                    self.received += 1
                    self.max_gap = max(self.max_gap, now - last)
                    last = now
                    if self.received % 50 == 0:
                        self.sock.sendall(mqtt_packets.gen_pingreq())
                        self.pings += 1
                elif cmd == 0xD0:
                    self.pongs += 1
            # Final liveness check.
            self.sock.sendall(mqtt_packets.gen_pingreq())
            self.pings += 1
            while True:
                cmd, _ = read_packet(self.sock)
                if cmd == 0xD0:
                    self.pongs += 1
                    break
            self.ok = True
        except Exception as e:
            thread_error(f"long client {self.idx} failed after {self.received} messages: {type(e).__name__}: {e}")
        finally:
            self.sock.close()


def publisher(port, stop):
    s = socket.create_connection(("localhost", port), timeout=20)
    s.sendall(mqtt_packets.gen_connect("stress-pub", keepalive=600))
    read_packet(s)
    n = 0
    while not stop.is_set():
        n += 1
        s.sendall(mqtt_packets.gen_publish("stress/long", qos=0, payload=str(n)))
        stats.inc("published")
        time.sleep(0.01)
    s.close()


# --- broker and files ------------------------------------------------------

basename = os.path.basename(__file__).replace(".py", "")
conf_file = basename + ".conf"
certfile, keyfile = basename + ".server.crt", basename + ".server.key"
cafile, crlfile = basename + ".ca.crt", basename + ".crl.pem"


def set_valid_state(crl="crl"):
    replace_file(ssl_dir / "server.crt", certfile)
    replace_file(ssl_dir / "server.key", keyfile)
    replace_file(ssl_dir / "all-ca.crt", cafile)
    replace_file(ssl_dir / f"{crl}.pem", crlfile)


def reloader(stop):
    rnd = random.Random(args.seed)
    while not stop.is_set():
        choice = rnd.choice(["cert", "ca", "crl", "broken_cert", "missing_ca", "none"])
        cert = rnd.choice(["server", "server-san"])
        replace_file(ssl_dir / f"{cert}.crt", certfile)
        replace_file(ssl_dir / f"{cert}.key", keyfile)
        replace_file(ssl_dir / rnd.choice(["all-ca.crt", "all-ca.crt", "test-fake-root-ca.crt"]), cafile)
        replace_file(ssl_dir / rnd.choice(["crl.pem", "crl-empty.pem"]), crlfile)
        if choice == "broken_cert":
            open(certfile, "w").close()
        elif choice == "missing_ca":
            os.remove(cafile)
        stats.inc(f"reload_{choice}")
        broker.reload()
        time.sleep(rnd.uniform(0.02, 0.15))


set_valid_state()
broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(
            port=tls_port,
            certfile=certfile,
            keyfile=keyfile,
            cafile=cafile,
            crlfile=crlfile,
            require_certificate=True,
        ),
        ListenerConfig(port=plain_port),
    ],
    allow_anonymous=True,
)
env = {
    "ASAN_OPTIONS": os.environ.get("ASAN_OPTIONS", "detect_leaks=1:halt_on_error=1"),
    "UBSAN_OPTIONS": os.environ.get("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1"),
}
# A broker under valgrind can take a while to close all of its connections.
broker = MosquittoBroker(config=broker_config, config_file_name=conf_file, env=env, termination_timeout=120)
for f in [certfile, keyfile, cafile, crlfile]:
    broker.add_extra_file(f)

vglog = None
long_clients = []
threads = []
stop_short, stop_long, stop_pub = threading.Event(), threading.Event(), threading.Event()
try:
    broker.start()
    if os.environ.get("MOSQ_USE_VALGRIND") not in (None, "callgrind", "massif", "failgrind"):
        vglog = mosq_test.vg_logfiles[-1]
    broker.wait_until_running(timeout=60)

    long_clients.extend(LongClient(i, tls_port, stop_long) for i in range(args.long_clients))
    pub = threading.Thread(target=run_worker, args=(publisher, plain_port, stop_pub),
                           name="publisher", daemon=True)
    pub.start()
    threads.append(pub)
    for c in long_clients:
        c.start()
        threads.append(c)
    workers = [threading.Thread(target=run_worker, args=(short_worker, i, tls_port, stop_short),
                                name=f"short-worker-{i}", daemon=True)
               for i in range(args.workers)]
    for w in workers:
        w.start()
        threads.append(w)
    rl = threading.Thread(target=run_worker, args=(reloader, stop_short), name="reloader", daemon=True)
    rl.start()
    threads.append(rl)

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        if not broker.is_running():
            raise RuntimeError(f"broker exited with {broker.process.returncode} during the run")
        with errors_lock:
            if errors:
                break
        time.sleep(0.5)

    stop_short.set()
    join_thread(rl, 60)
    for w in workers:
        join_thread(w, 60)

    # Restore a valid configuration and check new clients are accepted.
    set_valid_state(crl="crl-empty")
    broker.reload_and_wait(timeout=60)
    for cert in ["client", "client-revoked"]:
        tls_connect(tls_port, f"final-{cert}", cert=cert, cafile=CLIENT_CAFILE).close()

    stop_long.set()
    for c in long_clients:
        join_thread(c, 60)
    stop_pub.set()
    join_thread(pub, 30)
    for c in long_clients:
        if not c.ok:
            error(f"long client {c.idx} did not finish cleanly")
        if c.received == 0:
            error(f"long client {c.idx} received nothing")
except Exception as e:
    error(f"{type(e).__name__}: {e}")
finally:
    stop_short.set()
    stop_long.set()
    stop_pub.set()
    teardown.set()
    try:
        # Raises if the broker doesn't exit, or exits with an error, e.g.
        # because a sanitizer found a problem.
        broker.stop()
    except Exception as e:
        error(f"{type(e).__name__}: {e}")
    for thread in threads:
        thread.join(5)
        if thread.is_alive():
            error(f"thread {thread.name} did not stop during cleanup")

text = broker.get_log() or ""
for marker in SANITIZER_ERRORS:
    if marker in text:
        error(f"broker log contains {marker!r}")
if vglog is not None and os.path.exists(vglog):
    with open(vglog, errors="replace") as f:
        vgtext = f.read()
    for marker in VALGRIND_ERRORS:
        if marker in vgtext:
            error(f"valgrind log {vglog} contains {marker!r}")
s = stats.snapshot()
print(f"duration {args.duration}s, workers {args.workers}, long clients {args.long_clients}")
print(f"SIGHUPs sent: {sum(v for k, v in s.items() if k.startswith('reload_'))}, "
      f"reloads logged: {text.count('Reloading config.')}, "
      f"failed reloads kept previous config: {text.count('keeping the previous TLS configuration')}")
for k in sorted(s):
    print(f"  {k}: {s[k]}")
for c in long_clients:
    print(f"  long client {c.idx}: received {c.received}, pings {c.pings}/{c.pongs}, max gap {c.max_gap:.2f}s")
if s.get("short_ok_client", 0) == 0 or s.get("short_refused", 0) == 0:
    error("expected both accepted and refused short-lived clients")

if errors:
    logfile = basename + ".log"
    with open(logfile, "w") as f:
        f.write(text)
    print("FAILED:")
    for e in errors:
        print("  " + e)
    print(f"broker log kept in {os.path.abspath(logfile)}")
    sys.exit(1)
print("PASSED")
