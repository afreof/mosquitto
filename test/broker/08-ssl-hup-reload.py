#!/usr/bin/env python3

# Test that after a SIGHUP:
#   1. New TLS connections with a valid certificate are still accepted.
#      (Verifies that SSL_CTX recreation does not break valid handshakes.)
#   2. Revoked certificates are still rejected.
#      (Verifies that the CRL is correctly loaded into the recreated SSL_CTX;
#       a missing CRL would allow revoked certs to connect.)
#   3. Repeated SIGHUPs do not degrade behaviour.
#      (Ensures each SSL_CTX recreation cycle leaves a fully functional context.)

from mosq_test_helper import *
import signal

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

SIGHUP_COUNT = 3  # exercise multiple reloads


def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % port2)
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("listener %d\n" % port1)
        f.write("allow_anonymous true\n")
        f.write(f"cafile {ssl_dir / 'all-ca.crt'}\n")
        f.write(f"certfile {ssl_dir / 'server.crt'}\n")
        f.write(f"keyfile {ssl_dir / 'server.key'}\n")
        f.write("require_certificate true\n")
        f.write(f"crlfile {ssl_dir / 'crl.pem'}\n")


def connect_valid(port):
    """Connect with a valid client certificate; expect CONNACK rc=0."""
    connect_packet = mosq_test.gen_connect("hup-reload-valid")
    connack_packet = mosq_test.gen_connack(rc=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=str(ssl_dir / "test-root-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                            keyfile=str(ssl_dir / "client.key"))
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    ssock.connect(("localhost", port))
    mosq_test.do_send_receive(ssock, connect_packet, connack_packet, "connack")
    ssock.close()


def connect_revoked_expect_rejection(port):
    """Connect with a revoked certificate; expect the TLS handshake or
    the subsequent read to fail with a certificate-revoked error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=str(ssl_dir / "test-root-ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(ssl_dir / "client-revoked.crt"),
                            keyfile=str(ssl_dir / "client-revoked.key"))
    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", port))
        # The broker may close the connection after the handshake
        try:
            ssock.read(1)
        except (ssl.SSLEOFError, ssl.SSLError):
            return  # expected
        raise mosq_test.TestError("Revoked certificate was accepted after SIGHUP")
    except ssl.SSLError as err:
        if "revoked" in err.strerror or "EOF" in err.strerror or err.errno == 8:
            return  # expected rejection
        raise


(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # Baseline: verify TLS works before any reload
    connect_valid(port1)

    for i in range(SIGHUP_COUNT):
        broker.send_signal(signal.SIGHUP)
        time.sleep(0.5)  # give broker time to reload

        # After each SIGHUP a new handshake must succeed
        connect_valid(port1)

        # CRL must still be active: revoked cert must be rejected
        connect_revoked_expect_rejection(port1)

    rc = 0
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0:
            rc = 1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)
