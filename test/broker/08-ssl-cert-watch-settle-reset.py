#!/usr/bin/env python3

# Test tls_cert_watch_settle timer reset (debounce property).
#
# When multiple certificate files are updated in sequence (e.g. certfile
# first, then keyfile a second later), each new change detected within the
# settle window must reset the timer.  This prevents the broker from
# attempting to reload with a partially-written, inconsistent set.
#
# A key correctness property that this test guards against is the
# "perpetual-reset" bug: if the mtime comparison (changed vs. the
# original pre-rotation snapshot) is used for within-window resets,
# changed == true on every poll and the timer is reset indefinitely,
# meaning cert B is never loaded.  The settle snapshot must be updated
# to the post-change mtimes so subsequent polls see no new change.
#
# Scenario (POLL_INTERVAL=1s, SETTLE=2s):
#
#   1. Baseline: broker presents cert A.
#   2. Write only the certfile as cert B (keyfile still cert A's — mismatched).
#   3. Wait poll+margin: poller detects certfile change; settle timer starts.
#      Broker MUST NOT reload (key mismatch would be caught by OpenSSL anyway,
#      but we verify it does not try via the settle mechanism).
#   4. Write keyfile as cert B (now both files are cert B — consistent).
#      settle timer resets to now+SETTLE (new deadline).
#   5. Wait settle + poll + margin from step 4: settle window elapses.
#      Broker must reload and present cert B.
#
# The test verifies point 5: if the timer were perpetually reset (bug),
# cert B would never be loaded and the test would time out with a failure.

from mosq_test_helper import *
import hashlib
import re
import shutil
import tempfile

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

POLL_INTERVAL = 1   # seconds
SETTLE = 2          # seconds — keep small for a fast test


def pem_to_fingerprint(pem_path):
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
        f.write("tls_cert_watch polling\n")
        f.write(f"tls_cert_watch_interval {POLL_INTERVAL}\n")
        f.write(f"tls_cert_watch_settle {SETTLE}\n")


def make_client_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=str(ssl_dir / "test-root-ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(ssl_dir / "client.crt"),
                        keyfile=str(ssl_dir / "client.key"))
    return ctx


def connect_and_get_fingerprint(port):
    connect_packet = mosq_test.gen_connect("cert-watch-settle-reset-fp")
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

cert_dir = tempfile.mkdtemp(prefix="mosq_cert_watch_settle_reset_")
for fname in ("all-ca.crt", "server.crt", "server.key"):
    shutil.copy(str(ssl_dir / fname), cert_dir)

write_config(conf_file, cert_dir, port1, port2)

rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port2, use_conf=True)

try:
    # 1. Baseline: broker presents cert A.
    fp = connect_and_get_fingerprint(port1)
    if fp != fp_cert_a:
        raise mosq_test.TestError(
            f"Baseline fingerprint mismatch\n  got:      {fp}\n  expected: {fp_cert_a}")

    # 2. Write ONLY the certfile as cert B (keyfile still cert A's — mismatched).
    #    Bump the mtime so the poller detects the change.
    shutil.copy(str(ssl_dir / "server-san.crt"), os.path.join(cert_dir, "server.crt"))
    os.utime(os.path.join(cert_dir, "server.crt"), None)

    # 3. Wait for the poll to detect the certfile change and start the settle
    #    timer.  The broker must NOT reload (only certfile changed, key mismatch).
    time.sleep(POLL_INTERVAL + 0.5)

    fp = connect_and_get_fingerprint(port1)
    if fp != fp_cert_a:
        raise mosq_test.TestError(
            f"Broker reloaded with only certfile changed (before keyfile update)\n"
            f"  got:      {fp}\n  expected cert A: {fp_cert_a}")

    # 4. Now write the keyfile as cert B too — second change within the settle
    #    window.  The settle snapshot must be updated so the timer resets to
    #    now+SETTLE rather than perpetually re-detecting this change.
    shutil.copy(str(ssl_dir / "server-san.key"), os.path.join(cert_dir, "server.key"))
    os.utime(os.path.join(cert_dir, "server.key"), None)

    # 5. Wait for the (reset) settle window to expire and the poller to act.
    #    If the timer is perpetually reset (bug), cert B is never loaded and
    #    this assertion fails.
    time.sleep(SETTLE + POLL_INTERVAL + 1)

    fp = connect_and_get_fingerprint(port1)
    if fp != fp_cert_b:
        raise mosq_test.TestError(
            f"Broker did not reload after two-step rotation settle window\n"
            f"  got:      {fp}\n  expected cert B: {fp_cert_b}")

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
