#!/usr/bin/env python3

# Test that a socket that hasn't sent a CONNECT isn't counted in the
# $SYS/broker/clients/ topics. It used to be counted as a connected client
# and made the number of disconnected clients negative.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
import socket

mosq_test.require_features(["WITH_SYS_TREE"])


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise mosq_test.TestError("connection closed by broker")
        data += chunk
    return data


def read_publish(sock):
    cmd = recv_exact(sock, 1)[0]
    if cmd & 0xF0 != 0x30:
        raise mosq_test.TestError(f"expected PUBLISH, got {cmd:#x}")
    rl, _ = mosq_test.read_varint(sock, 0)
    data = recv_exact(sock, rl)
    topic_len, = struct.unpack("!H", data[:2])
    return data[2:2+topic_len].decode(), data[2+topic_len:].decode()


def do_test():
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[ ListenerConfig(port=port) ],
        allow_anonymous=True,
        sys_interval=1,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        no_connect = socket.create_connection(("localhost", port))

        connect_packet = mqtt_packets.gen_connect("sys-clients-count")
        connack_packet = mqtt_packets.gen_connack(rc=0)
        subscribe_packet = mqtt_packets.gen_subscribe(1, "$SYS/broker/#", 0)
        suback_packet = mqtt_packets.gen_suback(1, 0)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        # The retained uptime is from an earlier update, so the third one is
        # from at least the second update after both connections were made.
        # The client counts are only published when they change.
        values = {}
        uptimes = 0
        while uptimes < 3:
            topic, payload = read_publish(sock)
            if topic == "$SYS/broker/uptime":
                uptimes += 1
            values[topic] = payload

        expected = {
            "$SYS/broker/clients/total": "1",
            "$SYS/broker/clients/connected": "1",
            "$SYS/broker/clients/disconnected": "0",
        }
        for topic, payload in expected.items():
            if values.get(topic) != payload:
                raise mosq_test.TestError(f"{topic} is {values.get(topic)}, expected {payload}\n{values}")

        no_connect.close()
        sock.close()


do_test()
