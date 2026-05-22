#!/usr/bin/env python3

# Test certificate watch failure/retry robustness.
#
# When a changed certfile cannot be loaded (e.g. the file is corrupt or
# only half-written), the broker must:
#   1. Keep the existing SSL_CTX so that in-flight connections are not
#      disrupted and new connections still succeed.
#   2. NOT update the mtime snapshot, so that the next poll retries the load.
#   3. After a valid certificate is written, successfully rotate to it.
#
# Scenario:
#   a. Baseline: broker presents cert A (server.crt).
#   b. Write a corrupt certfile (truncated PEM) and bump its mtime.
#   c. Wait for a poll — broker must log an error but keep serving cert A.
#   d. Write the valid cert B (server-san.crt) and bump its mtime.
#   e. Wait for a poll — broker must now serve cert B.

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

POLL_INTERVAL = 1  # seconds — keep the test fast


def pem_to_fingerprint(pem_path):
    """Return the SHA-256 fingerprint (hex) of the first cert in a PEM file."""
    text = open(pem_path).read()
    match = re.search(
        r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
        text, re.DOTALL)
    if not match:
        raise ValueError(f"No PEM certificate block found in {pem_path}")
    der = ssl.PEM_cert_to_DER_cert(match.group(0))
    return hashlib.sha256(der).hexdigest()


def make_client_context():
    """Create an SSL context for a valid client."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                        keyfile=str(ssl_dir / "client.key"))
    return ctx


def connect_and_get_fingerprint(port):
    """Connect with a valid client cert and return the server leaf fingerprint."""
    connect_packet = mqtt_packets.gen_connect("cert-watch-failure-fp")
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

cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_fail_")
try:
    for fname in ("all-ca.crt", "server.crt", "server.key", "crl.pem"):
        shutil.copy(str(ssl_dir / fname), cert_dir)

    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port,
                cafile=Path(cert_dir) / "all-ca.crt",
                certfile=Path(cert_dir) / "server.crt",
                keyfile=Path(cert_dir) / "server.key",
                require_certificate=True,
                crlfile=Path(cert_dir) / "crl.pem",
                tls_cert_watch="polling",
                tls_cert_watch_interval=POLL_INTERVAL,
            ),
        ],
        allow_anonymous=True,
    )

    with MosquittoBroker(config=broker_config) as broker:
        # a. Baseline: broker presents cert A.
        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_a:
            raise mosq_test.TestError(
                f"Baseline fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_a}")

        # b. Write a corrupt (truncated) certfile and bump its mtime.
        corrupt_path = os.path.join(cert_dir, "server.crt")
        with open(corrupt_path, 'w') as f:
            f.write("-----BEGIN CERTIFICATE-----\nTHIS IS NOT VALID BASE64\n-----END CERTIFICATE-----\n")
        os.utime(corrupt_path, None)

        # c. Wait for the poll — broker must reject the corrupt cert and keep cert A.
        time.sleep(POLL_INTERVAL + 1)

        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_a:
            raise mosq_test.TestError(
                f"After corrupt cert: fingerprint changed — broker should have kept cert A\n"
                f"  got:      {fp}\n  expected: {fp_cert_a}")

        # d. Write valid cert B and bump its mtime.
        shutil.copy(str(ssl_dir / "server-san.crt"), os.path.join(cert_dir, "server.crt"))
        shutil.copy(str(ssl_dir / "server-san.key"), os.path.join(cert_dir, "server.key"))
        os.utime(os.path.join(cert_dir, "server.crt"), None)
        os.utime(os.path.join(cert_dir, "server.key"), None)

        # e. Wait for the poll — broker must now serve cert B.
        time.sleep(POLL_INTERVAL + 1)

        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_b:
            raise mosq_test.TestError(
                f"After valid cert B: fingerprint mismatch\n"
                f"  got:      {fp}\n  expected: {fp_cert_b}")

finally:
    shutil.rmtree(cert_dir, ignore_errors=True)
