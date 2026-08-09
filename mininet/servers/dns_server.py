#!/usr/bin/env python3

import socket
import struct

SERVER_IP = "10.0.0.1"
DNS_PORT = 53


def build_dns_response(data):
    # Transaction ID
    transaction_id = data[:2]

    # Flags: Response + Authoritative Answer + NoError
    flags = b"\x81\x80"

    # Questions = 1
    qdcount = b"\x00\x01"

    # Answer = 1
    ancount = b"\x00\x01"

    # Authority = 0
    nscount = b"\x00\x00"

    # Additional = 0
    arcount = b"\x00\x00"

    header = (
        transaction_id +
        flags +
        qdcount +
        ancount +
        nscount +
        arcount
    )

    # Copy question section (name + type + class)
    question = data[12:]

    # DNS answer:
    # Name pointer to question name
    name = b"\xc0\x0c"

    # Type A
    qtype = b"\x00\x01"

    # Class IN
    qclass = b"\x00\x01"

    # TTL = 60 seconds
    ttl = b"\x00\x00\x00\x3c"

    # IPv4 address length = 4
    data_length = b"\x00\x04"

    # Returned IP
    ip_address = socket.inet_aton("10.0.0.2")

    answer = (
        name +
        qtype +
        qclass +
        ttl +
        data_length +
        ip_address
    )

    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, DNS_PORT))

    print(f"DNS server listening on {SERVER_IP}:{DNS_PORT}")

    while True:
        data, client = sock.recvfrom(512)

        try:
            print(f"DNS request from {client} - {len(data)} bytes")
            response = build_dns_response(data)
            sock.sendto(response, client)
            print(f"DNS response sent to {client}")
        except Exception as e:
            print(f"DNS error: {e}")


if __name__ == "__main__":
    main()
