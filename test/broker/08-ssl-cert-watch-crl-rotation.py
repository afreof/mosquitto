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
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

POLL_INTERVAL = 1  # seconds — keep the test fast


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


def connect_expect_accept(port):
    """Connect with client-revoked.crt and expect CONNACK rc=0 (CRL is empty)."""
    connect_packet = mosq_test.gen_connect("crl-rotation-pre")
    connack_packet = mosq_test.gen_connack(rc=0)

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


(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')

cert_dir = tempfile.mkdtemp(prefix="mosq_crl_rotation_")
for fname in ("all-ca.crt", "server.crt", "server.key"):
    shutil.copy(str(ssl_dir / fname), cert_dir)
# Start with an empty CRL so that client-revoked.crt is initially accepted.
shutil.copy(str(ssl_dir / "crl-empty.pem"), os.path.join(cert_dir, "crl.pem"))

write_config(conf_file, cert_dir, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # Baseline: empty CRL — client-revoked.crt must be accepted.
    connect_expect_accept(port1)

    # Rotate the CRL to one that revokes client-revoked.crt.
    shutil.copy(str(ssl_dir / "crl.pem"), os.path.join(cert_dir, "crl.pem"))
    os.utime(os.path.join(cert_dir, "crl.pem"), None)

    # Wait for the poll interval to elapse.
    time.sleep(POLL_INTERVAL + 1)

    # After CRL rotation: client-revoked.crt must now be rejected.
    connect_expect_rejection(port1)

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
