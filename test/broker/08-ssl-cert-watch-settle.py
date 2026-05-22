#!/usr/bin/env python3

# Test tls_cert_watch_settle: reload must be deferred until the settle window
# has elapsed with no further file changes.
#
# Timeline (POLL_INTERVAL=1s, SETTLE=3s):
#
#   t=0          Broker starts; presents cert A.
#   t~1 (poll)   Files unchanged — no action.
#   t~2 (poll)   Files unchanged — no action.
#   t=2.5        Rotate files to cert B; bump mtimes.
#   t~3.5 (poll) Change detected — settle timer set to expire at t~6.5.
#                Broker must NOT reload yet; still presents cert A.
#   t~4.5 (poll) Files stable — settle window not yet elapsed; no reload.
#   t~5.5 (poll) Files stable — settle window not yet elapsed; no reload.
#   t~6.5 (poll) Settle window elapsed — broker reloads and presents cert B.
#
# This test uses a settle of 3 s and a poll interval of 1 s so the "no reload
# yet" window covers multiple poll ticks and the deferred reload is visible.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
import hashlib
import re
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

mosq_test.require_features(["WITH_TLS"])

POLL_INTERVAL = 1   # seconds
SETTLE = 3          # seconds — must be > POLL_INTERVAL


def pem_to_fingerprint(pem_path):
    text = open(pem_path).read()
    match = re.search(
        r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
        text, re.DOTALL)
    if not match:
        raise ValueError(f"No PEM certificate block found in {pem_path}")
    der = ssl.PEM_cert_to_DER_cert(match.group(0))
    return hashlib.sha256(der).hexdigest()


def make_client_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                        keyfile=str(ssl_dir / "client.key"))
    return ctx


def connect_and_get_fingerprint(port):
    connect_packet = mqtt_packets.gen_connect("cert-watch-settle-fp")
    connack_packet = mqtt_packets.gen_connack(rc=0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock = make_client_context().wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    der = ssock.getpeercert(binary_form=True)
    ssock.close()
    return hashlib.sha256(der).hexdigest()


fp_cert_a = pem_to_fingerprint(str(ssl_dir / "server.crt"))
fp_cert_b = pem_to_fingerprint(str(ssl_dir / "server-san.crt"))

port = mosq_test.get_port()

cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_settle_")
try:
    for fname in ("all-ca.crt", "server.crt", "server.key"):
        shutil.copy(str(ssl_dir / fname), cert_dir)

    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port,
                cafile=Path(cert_dir) / "all-ca.crt",
                certfile=Path(cert_dir) / "server.crt",
                keyfile=Path(cert_dir) / "server.key",
                require_certificate=True,
                tls_cert_watch="polling",
                tls_cert_watch_interval=POLL_INTERVAL,
                tls_cert_watch_settle=SETTLE,
            ),
        ],
        allow_anonymous=True,
    )

    with MosquittoBroker(config=broker_config) as broker:
        # 1. Baseline: broker must present cert A.
        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_a:
            raise mosq_test.TestError(
                f"Baseline fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_a}")

        # 2. Rotate files (cert B) and bump their mtimes so the poller detects the
        #    change even if the copy completes within the same wall-clock second.
        shutil.copy(str(ssl_dir / "server-san.crt"), os.path.join(cert_dir, "server.crt"))
        shutil.copy(str(ssl_dir / "server-san.key"), os.path.join(cert_dir, "server.key"))
        os.utime(os.path.join(cert_dir, "server.crt"), None)
        os.utime(os.path.join(cert_dir, "server.key"), None)

        # 3. Wait for one poll interval + a small margin. The poller should now
        #    have detected the change and started the settle timer, but MUST NOT
        #    have reloaded yet.
        time.sleep(POLL_INTERVAL + 0.5)

        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_a:
            raise mosq_test.TestError(
                f"Broker reloaded too early (before settle window elapsed)\n"
                f"  got:      {fp}\n  expected cert A: {fp_cert_a}")

        # 4. Now wait for the full settle window to expire (plus a poll interval
        #    and a margin to be sure the broker has acted on it).
        time.sleep(SETTLE + POLL_INTERVAL + 1)

        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_b:
            raise mosq_test.TestError(
                f"Broker did not reload after settle window elapsed\n"
                f"  got:      {fp}\n  expected cert B: {fp_cert_b}")

finally:
    shutil.rmtree(cert_dir, ignore_errors=True)
