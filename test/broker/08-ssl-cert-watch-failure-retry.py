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
import hashlib
import re
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

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
        f.write("tls_cert_watch_settle 0\n")


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
    connect_packet = mosq_test.gen_connect("cert-watch-failure-fp")
    connack_packet = mosq_test.gen_connack(rc=0)

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

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')

cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_fail_")
for fname in ("all-ca.crt", "server.crt", "server.key", "crl.pem"):
    shutil.copy(str(ssl_dir / fname), cert_dir)

write_config(conf_file, cert_dir, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # a. Baseline: broker presents cert A.
    fp = connect_and_get_fingerprint(port1)
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

    fp = connect_and_get_fingerprint(port1)
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

    fp = connect_and_get_fingerprint(port1)
    if fp != fp_cert_b:
        raise mosq_test.TestError(
            f"After valid cert B: fingerprint mismatch\n"
            f"  got:      {fp}\n  expected: {fp_cert_b}")

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
