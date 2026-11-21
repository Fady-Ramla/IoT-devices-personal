#!/usr/bin/env python3
import os
import socket
import struct

SERVER_IP = os.getenv("DNS_SERVER_IP", "10.10.30.2")
DNS_PORT = int(os.getenv("DNS_PORT", "53"))
INTERNAL_NAME = os.getenv("DNS_INTERNAL_NAME", "https.lab").rstrip(".").lower()
INTERNAL_IP = os.getenv("DNS_INTERNAL_IP", "10.10.20.100")
UPSTREAMS = tuple(
    item.strip() for item in os.getenv("DNS_UPSTREAMS", "1.1.1.1,8.8.8.8").split(",")
    if item.strip()
)


def question_info(data):
    if len(data) < 12:
        raise ValueError("DNS packet is too short")
    offset = 12
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("invalid DNS question")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(data):
            raise ValueError("compressed or invalid question name")
        labels.append(data[offset:offset + length].decode("ascii", "strict"))
        offset += length
    if offset + 4 > len(data):
        raise ValueError("DNS question has no type/class")
    return ".".join(labels).lower(), data[12:offset + 4], data[offset:offset + 4]


def local_response(data, question, qtype, qclass):
    transaction_id = data[:2]
    if qtype != b"\x00\x01" or qclass != b"\x00\x01":
        return transaction_id + b"\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
    ip_address = socket.inet_aton(INTERNAL_IP)
    header = transaction_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip_address
    return header + question + answer


def forward_upstream(data):
    for upstream in UPSTREAMS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(float(os.getenv("DNS_UPSTREAM_TIMEOUT", "1.5")))
        try:
            sock.sendto(data, (upstream, 53))
            response, _ = sock.recvfrom(65535)
            if response and response[:2] == data[:2]:
                return response
        except OSError:
            pass
        finally:
            sock.close()
    return None


def servfail(data, question):
    return data[:2] + b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00" + question


def build_dns_response(data):
    name, question, qtype_class = question_info(data)
    qtype, qclass = qtype_class[:2], qtype_class[2:]
    if name == INTERNAL_NAME:
        return local_response(data, question, qtype, qclass)
    return forward_upstream(data) or servfail(data, question)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, DNS_PORT))
    print(
        f"DNS server listening on {SERVER_IP}:{DNS_PORT}; "
        f"internal={INTERNAL_NAME}->{INTERNAL_IP}; upstreams={UPSTREAMS}",
        flush=True,
    )
    while True:
        data, client = sock.recvfrom(4096)
        try:
            response = build_dns_response(data)
            sock.sendto(response, client)
            print(f"DNS response sent to {client}", flush=True)
        except Exception as exc:
            print(f"DNS error from {client}: {exc}", flush=True)


if __name__ == "__main__":
    main()
