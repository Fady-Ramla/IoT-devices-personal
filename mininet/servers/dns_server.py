#!/usr/bin/env python3
"""Minimal lab DNS A responder over UDP and TCP for SecureIoT service pairs."""
import os
import socket
import threading

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


def udp_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, DNS_PORT))
    print("DNS UDP listening on %s:%d" % (SERVER_IP, DNS_PORT), flush=True)
    while True:
        data, client = sock.recvfrom(4096)
        try:
            sock.sendto(build_dns_response(data), client)
        except Exception as exc:
            print("DNS UDP error from %s: %s" % (client, exc), flush=True)


def _recv_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _tcp_client(conn, address):
    try:
        conn.settimeout(3)
        header = _recv_exact(conn, 2)
        if header is None:
            return
        length = int.from_bytes(header, "big")
        if not 12 <= length <= 4096:
            return
        data = _recv_exact(conn, length)
        if data is None:
            return
        response = build_dns_response(bytes(data))
        conn.sendall(len(response).to_bytes(2, "big") + response)
    except Exception as exc:
        print("DNS TCP error from %s: %s" % (address, exc), flush=True)
    finally:
        conn.close()


def tcp_loop():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_IP, DNS_PORT))
    server.listen(64)
    print("DNS TCP listening on %s:%d" % (SERVER_IP, DNS_PORT), flush=True)
    while True:
        conn, address = server.accept()
        threading.Thread(target=_tcp_client, args=(conn, address), daemon=True).start()


def main():
    threading.Thread(target=udp_loop, daemon=True).start()
    tcp_loop()


if __name__ == "__main__":
    main()
