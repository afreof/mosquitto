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
import hashlib
import re
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

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


def write_config(filename, cert_dir, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % port2)
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("listener %d\n" % port1)
        f.write("allow_anonymous true\n")
        f.write(f"cafile {cert_dir}/all-ca.crt\n")
        f.write(f"certfile {cert_dir}/server.crt\n")
        f.write(f"keyfile {cert_dir}/server.key\n")
        f.write("require_certificate true\n")
        f.write(f"crlfile {cert_dir}/crl.pem\n")
        f.write("tls_cert_watch polling\n")
        f.write(f"tls_cert_watch_interval {POLL_INTERVAL}\n")


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
    connect_packet = mosq_test.gen_connect("cert-watch-fp")
    connack_packet = mosq_test.gen_connack(rc=0)

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

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')

# Copy the TLS files to a temporary directory so we can replace them safely
# without affecting other tests that use the shared ssl/ directory.
cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_")
for fname in ("all-ca.crt", "server.crt", "server.key", "crl.pem"):
    shutil.copy(str(ssl_dir / fname), cert_dir)

write_config(conf_file, cert_dir, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # 1. Baseline: broker must present cert A (server.crt).
    fp = connect_and_get_fingerprint(port1)
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
    fp = connect_and_get_fingerprint(port1)
    if fp != fp_cert_b:
        raise mosq_test.TestError(
            f"Post-rotation fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_b}")

    # 4. CRL must still be active after the auto-reload.
    connect_revoked_expect_rejection(port1)

    rc = 0
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    shutil.rmtree(cert_dir, ignore_errors=True)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0:
            rc = 1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)
