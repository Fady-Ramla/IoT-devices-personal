#!/usr/bin/env python3
import os
import socket

SERVER_IP = os.getenv("DNS_SERVER_IP", "10.10.30.2")
DNS_PORT = int(os.getenv("DNS_PORT", "53"))


def build_dns_response(data):
    if len(data) < 12:
        raise ValueError("DNS packet is too short")
    transaction_id = data[:2]
    question_end = data.find(b"\x00", 12)
    if question_end < 0 or question_end + 5 > len(data):
        raise ValueError("invalid DNS question")
    question = data[12:question_end + 5]
    qtype = question[-4:-2]
    qclass = question[-2:]
    if qtype != b"\x00\x01" or qclass != b"\x00\x01":
        return transaction_id + b"\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
    header = transaction_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    ip_address = socket.inet_aton(os.getenv("DNS_ANSWER_IP", "10.10.20.2"))
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip_address
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, DNS_PORT))
    print(f"DNS server listening on {SERVER_IP}:{DNS_PORT}", flush=True)
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

