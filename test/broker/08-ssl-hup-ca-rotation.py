#!/usr/bin/env python3

# Test that SIGHUP reloads cafile so that CA cert rotations take effect.
#
# The broker is started with cafile pointing to all-ca.crt (which includes
# the signing CA).  A symlink is used as the cafile so we can atomically
# switch it to a completely different CA (test-fake-root-ca.crt) while the
# broker is running, then send SIGHUP.
#
# After the reload:
#   - client.crt (signed by the original CA chain) must now be rejected
#     because the new cafile no longer trusts its issuer.
#   - Before the fix (net__load_certificates only, no net__tls_load_verify),
#     the stale CA store is kept and client.crt would still be accepted.

from mosq_test_helper import *
import shutil
import signal
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)


def write_config(filename, cafile_symlink, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % port2)
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("listener %d\n" % port1)
        f.write("allow_anonymous true\n")
        f.write(f"cafile {cafile_symlink}\n")
        f.write(f"certfile {ssl_dir}/server.crt\n")
        f.write(f"keyfile {ssl_dir}/server.key\n")
        f.write("require_certificate true\n")


def connect_expect_success(port):
    """Connect with client.crt; expect CONNACK rc=0."""
    connect_packet = mosq_test.gen_connect("ca-reload-ok")
    connack_packet = mosq_test.gen_connack(rc=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                        keyfile=str(ssl_dir / "client.key"))
    ssock = ctx.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    ssock.close()


def connect_expect_rejection(port):
    """Connect with client.crt; expect rejection after CA rotation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                        keyfile=str(ssl_dir / "client.key"))
    ssock = ctx.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port))
        try:
            ssock.read(1)
        except (ssl.SSLEOFError, ssl.SSLError):
            return  # expected
        raise mosq_test.TestError(
            "client.crt was accepted after CA rotation to an unrelated CA")
    except ssl.SSLError as err:
        if "certificate" in err.strerror.lower() or "EOF" in err.strerror or err.errno == 8:
            return  # expected rejection
        raise
    except TimeoutError:
        raise mosq_test.TestError(
            "client.crt connection timed out instead of being rejected after CA rotation")


(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')

# Use a temp dir for the cafile symlink so we can retarget it atomically.
tmpdir = tempfile.mkdtemp(prefix="mosq_ca_reload_")
cafile_symlink = os.path.join(tmpdir, "ca.crt")
os.symlink(str(ssl_dir / "all-ca.crt"), cafile_symlink)

write_config(conf_file, cafile_symlink, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # Baseline: client.crt accepted with original CA.
    connect_expect_success(port1)

    # Rotate cafile symlink to a completely unrelated CA and reload.
    new_link = cafile_symlink + ".new"
    os.symlink(str(ssl_dir / "test-fake-root-ca.crt"), new_link)
    os.replace(new_link, cafile_symlink)  # atomic swap

    broker.send_signal(signal.SIGHUP)
    time.sleep(0.5)

    # After reload with the unrelated CA: client.crt must now be rejected.
    connect_expect_rejection(port1)

    rc = 0
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    shutil.rmtree(tmpdir, ignore_errors=True)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0:
            rc = 1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)
