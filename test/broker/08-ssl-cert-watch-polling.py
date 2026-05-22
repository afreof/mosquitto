#!/usr/bin/env python3

# Test certificate watch in polling mode.
#
# The broker is started with tls_cert_watch polling and a 1-second interval.
# The test exercises a full certificate rotation by replacing the server cert
# and key with a different certificate signed by the same CA.  After each
# reload the TLS fingerprint presented by the broker is verified to confirm
# the new certificate is actually in use:
#
#   1. Baseline: broker presents server.crt  — fingerprint matches cert A.
#   2. Rotate:   server.crt/key replaced with server-san.crt/key (cert B).
#   3. After poll interval: broker presents cert B — fingerprint matches.
#   4. CRL must still be active after the auto-reload.

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
    """Return the SHA-256 fingerprint (hex) of the first cert in a PEM file.

    The file may be in OpenSSL text+PEM combined format (as produced by
    'openssl x509 -text') — only the PEM block is parsed.
    """
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
    """Connect with a valid client cert, complete MQTT handshake, and return
    the SHA-256 fingerprint (hex) of the server's leaf certificate."""
    connect_packet = mqtt_packets.gen_connect("cert-watch-fp")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock = make_client_context().wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    der = ssock.getpeercert(binary_form=True)
    ssock.close()
    return hashlib.sha256(der).hexdigest()


def connect_revoked_expect_rejection(port):
    """Connect with a revoked certificate; expect rejection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client-revoked.crt"),
                        keyfile=str(ssl_dir / "client-revoked.key"))
    ssock = ctx.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port))
        try:
            ssock.read(1)
        except (ssl.SSLEOFError, ssl.SSLError):
            return  # expected
        raise mosq_test.TestError("Revoked certificate was accepted after cert-watch reload")
    except ssl.SSLError as err:
        if "revoked" in err.strerror or "EOF" in err.strerror or err.errno == 8:
            return  # expected rejection
        raise


# Pre-compute expected fingerprints from the source PEM files.
fp_cert_a = pem_to_fingerprint(str(ssl_dir / "server.crt"))
fp_cert_b = pem_to_fingerprint(str(ssl_dir / "server-san.crt"))

port = mosq_test.get_port()

# Copy the TLS files to a temporary directory so we can replace them safely
# without affecting other tests that use the shared ssl/ directory.
cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_")
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
        # 1. Baseline: broker must present cert A (server.crt).
        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_a:
            raise mosq_test.TestError(
                f"Baseline fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_a}")

        # 2. Rotate to cert B by replacing server.crt and server.key in the
        #    temp dir with server-san.crt / server-san.key.
        shutil.copy(str(ssl_dir / "server-san.crt"), os.path.join(cert_dir, "server.crt"))
        shutil.copy(str(ssl_dir / "server-san.key"), os.path.join(cert_dir, "server.key"))
        # Explicitly bump the mtime so the poller detects the change even if the
        # copy happened within the same wall-clock second as the initial snapshot.
        os.utime(os.path.join(cert_dir, "server.crt"), None)
        os.utime(os.path.join(cert_dir, "server.key"), None)

        # Wait for the poll interval to elapse (add 1 s margin).
        time.sleep(POLL_INTERVAL + 1)

        # 3. After polling reload: broker must now present cert B.
        fp = connect_and_get_fingerprint(port)
        if fp != fp_cert_b:
            raise mosq_test.TestError(
                f"Post-rotation fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_b}")

        # 4. CRL must still be active after the auto-reload.
        connect_revoked_expect_rejection(port)

finally:
    shutil.rmtree(cert_dir, ignore_errors=True)

