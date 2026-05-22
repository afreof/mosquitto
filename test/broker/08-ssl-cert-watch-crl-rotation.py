#!/usr/bin/env python3

# Test that cert_watch polling reloads crlfile when it changes.
#
# The broker is started with an empty CRL (crl-empty.pem) so that
# client-revoked.crt is initially accepted.  The CRL file is then replaced
# with crl.pem (which revokes client-revoked.crt) and the mtime is bumped.
# After the next poll interval the broker must reject the revoked certificate.
#
# This proves that crlfile rotation takes effect via the polling watcher
# without requiring a SIGHUP or broker restart.

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

mosq_test.require_features(["WITH_TLS"])

POLL_INTERVAL = 1  # seconds — keep the test fast


def connect_expect_accept(port):
    """Connect with client-revoked.crt and expect CONNACK rc=0 (CRL is empty)."""
    connect_packet = mqtt_packets.gen_connect("crl-rotation-pre")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client-revoked.crt"),
                        keyfile=str(ssl_dir / "client-revoked.key"))
    ssock = ctx.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    ssock.close()


def connect_expect_rejection(port):
    """Connect with client-revoked.crt; expect rejection after CRL rotation."""
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
        raise mosq_test.TestError(
            "Revoked certificate was accepted after CRL rotation via cert_watch")
    except ssl.SSLError as err:
        if "revoked" in err.strerror or "EOF" in err.strerror or err.errno == 8:
            return  # expected rejection
        raise


port = mosq_test.get_port()

cert_dir = tempfile.mkdtemp(prefix="mosq_crl_rotation_")
try:
    for fname in ("all-ca.crt", "server.crt", "server.key"):
        shutil.copy(str(ssl_dir / fname), cert_dir)
    # Start with an empty CRL so that client-revoked.crt is initially accepted.
    shutil.copy(str(ssl_dir / "crl-empty.pem"), os.path.join(cert_dir, "crl.pem"))

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
                tls_cert_watch_settle=0,
            ),
        ],
        allow_anonymous=True,
    )

    with MosquittoBroker(config=broker_config) as broker:
        # Baseline: empty CRL — client-revoked.crt must be accepted.
        connect_expect_accept(port)

        # Rotate the CRL to one that revokes client-revoked.crt.
        shutil.copy(str(ssl_dir / "crl.pem"), os.path.join(cert_dir, "crl.pem"))
        os.utime(os.path.join(cert_dir, "crl.pem"), None)

        # Wait for the poll interval to elapse.
        time.sleep(POLL_INTERVAL + 1)

        # After CRL rotation: client-revoked.crt must now be rejected.
        connect_expect_rejection(port)

finally:
    shutil.rmtree(cert_dir, ignore_errors=True)
