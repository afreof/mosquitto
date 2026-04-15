#!/usr/bin/env python3

# Test that the TLS certificate chain is stable and correct across SIGHUP reloads.
#
# A certfile containing both the leaf certificate and an intermediate signing
# CA is configured. After each SIGHUP the test connects via openssl s_client
# and extracts the SHA-256 fingerprint of every certificate in the server's
# chain, verifying that:
#   1. Exactly 2 certificates are presented (leaf + intermediate).
#   2. The leaf is always server.crt (correct identity after SSL_CTX recreation).
#   3. The intermediate is always test-signing-ca.crt (chain is complete and
#      correct; SSL_CTX_use_certificate_chain_file() replaces the chain on
#      every reload so no stale or duplicate entries appear).

from mosq_test_helper import *
import hashlib
import re
import signal
import shutil
import subprocess
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

SIGHUP_COUNT = 3


def write_config(filename, cert_dir, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % port2)
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("listener %d\n" % port1)
        f.write("allow_anonymous true\n")
        f.write(f"cafile {cert_dir}/all-ca.crt\n")
        f.write(f"certfile {cert_dir}/server-chain.crt\n")
        f.write(f"keyfile {cert_dir}/server.key\n")
        f.write("require_certificate true\n")
        f.write(f"crlfile {cert_dir}/crl.pem\n")


def pem_to_fingerprint(pem_path):
    """Return the SHA-256 fingerprint (hex) of the first certificate in a PEM file.
    Handles both plain PEM and OpenSSL text+PEM combined format."""
    text = open(pem_path).read()
    match = re.search(
        r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
        text, re.DOTALL)
    if not match:
        raise ValueError(f"No PEM certificate block found in {pem_path}")
    der = ssl.PEM_cert_to_DER_cert(match.group(0))
    return hashlib.sha256(der).hexdigest()


def get_chain_fingerprints(port, ca_file, client_cert, client_key):
    """Connect via openssl s_client with -showcerts and return the SHA-256
    fingerprint of every certificate in the server's chain (leaf first),
    or None on failure."""
    try:
        result = subprocess.run(
            ['openssl', 's_client',
             '-connect', f'localhost:{port}',
             '-CAfile', str(ca_file),
             '-cert', str(client_cert),
             '-key', str(client_key),
             '-servername', 'localhost',
             '-showcerts'],
            input=b'',
            capture_output=True,
            timeout=5,
        )
        output = result.stdout.decode()
        pem_blocks = re.findall(
            r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
            output, re.DOTALL)
        return [hashlib.sha256(ssl.PEM_cert_to_DER_cert(p)).hexdigest()
                for p in pem_blocks]
    except Exception as e:
        print(f"get_chain_fingerprints error: {e}")
        return None


def connect_valid(port):
    """Connect with a valid client certificate; expect CONNACK rc=0."""
    connect_packet = mosq_test.gen_connect("chain-hup-valid")
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


# Pre-compute expected fingerprints from the source PEM files.
fp_leaf         = pem_to_fingerprint(str(ssl_dir / "server.crt"))
fp_intermediate = pem_to_fingerprint(str(ssl_dir / "test-signing-ca.crt"))
expected_chain  = [fp_leaf, fp_intermediate]

(port1, port2) = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')

# Build a chain certfile (leaf + intermediate signing CA) in a temp dir so
# we don't modify the shared ssl/ fixtures.
cert_dir = tempfile.mkdtemp(prefix="mosq_chain_hup_")
for fname in ("all-ca.crt", "server.key", "crl.pem"):
    shutil.copy(str(ssl_dir / fname), cert_dir)
with open(os.path.join(cert_dir, "server-chain.crt"), 'w') as out:
    out.write(open(str(ssl_dir / "server.crt")).read())
    out.write(open(str(ssl_dir / "test-signing-ca.crt")).read())

write_config(conf_file, cert_dir, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # Baseline check before any reload.
    chain = get_chain_fingerprints(port1,
                                   str(ssl_dir / "test-root-ca.crt"),
                                   str(ssl_dir / "client.crt"),
                                   str(ssl_dir / "client.key"))
    if chain != expected_chain:
        raise mosq_test.TestError(
            f"Baseline chain fingerprints mismatch\n"
            f"  got:      {chain}\n"
            f"  expected: {expected_chain}")

    for i in range(SIGHUP_COUNT):
        broker.send_signal(signal.SIGHUP)
        time.sleep(0.5)

        connect_valid(port1)

        chain = get_chain_fingerprints(port1,
                                       str(ssl_dir / "test-root-ca.crt"),
                                       str(ssl_dir / "client.crt"),
                                       str(ssl_dir / "client.key"))
        if chain != expected_chain:
            raise mosq_test.TestError(
                f"After SIGHUP #{i+1}: chain fingerprints mismatch\n"
                f"  got:      {chain}\n"
                f"  expected: {expected_chain}")

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
