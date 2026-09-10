#!/bin/bash

# ============================================================
# Attack Collection Script
# ============================================================
# Usage:
#   ./run_attacks_collection.sh <attack_type> <attacker> [endpoint]
#
# Examples:
#   ./run_attacks_collection.sh port_scan h6
#   ./run_attacks_collection.sh syn_flood h5
#   ./run_attacks_collection.sh malicious_post h7 /admin
# ============================================================

ATTACK_TYPE="$1"
ATTACKER="$2"
ENDPOINT="$3"

# ------------------------------------------------------------
# Validate input
# ------------------------------------------------------------

if [ -z "$ATTACK_TYPE" ] || [ -z "$ATTACKER" ]; then

    echo ""
    echo "Usage:"
    echo "  ./run_attacks_collection.sh <attack_type> <attacker> [endpoint]"
    echo ""
    echo "Examples:"
    echo "  ./run_attacks_collection.sh port_scan h6"
    echo "  ./run_attacks_collection.sh syn_flood h5"
    echo "  ./run_attacks_collection.sh malicious_post h7 /admin"
    echo ""

    exit 1
fi

# ------------------------------------------------------------
# Build PCAP filename
# ------------------------------------------------------------

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

PCAP_FILE="/home/fady/IoT-devices/captures/${ATTACK_TYPE}_${ATTACKER}_${TIMESTAMP}.pcap"

echo ""
echo "=============================================="
echo " Attack Collection"
echo "=============================================="
echo " Attack Type : $ATTACK_TYPE"
echo " Attacker    : $ATTACKER"
echo " Endpoint    : $ENDPOINT"
echo " PCAP File   : $PCAP_FILE"
echo "=============================================="
echo ""

# ------------------------------------------------------------
# Start capture on h2
# ------------------------------------------------------------

echo "[1/3] Starting tcpdump on h2..."

h2 tcpdump -i h2-eth0 -nn -s 0 -w "$PCAP_FILE" &

sleep 2

# ------------------------------------------------------------
# Run attack
# ------------------------------------------------------------

echo "[2/3] Running attack..."

if [ -z "$ENDPOINT" ]; then

    echo "attack $ATTACKER $ATTACK_TYPE h2" | nc -q 1 localhost 5000

else

    echo "attack $ATTACKER $ATTACK_TYPE h2 $ENDPOINT" | nc -q 1 localhost 5000

fi

sleep 2

# ------------------------------------------------------------
# Stop capture
# ------------------------------------------------------------

echo "[3/3] Stopping tcpdump..."

h2 pkill tcpdump

sleep 1

# ------------------------------------------------------------
# Verify PCAP
# ------------------------------------------------------------

if [ -f "$PCAP_FILE" ]; then

    echo ""
    echo "=============================================="
    echo " PCAP CREATED SUCCESSFULLY"
    echo "=============================================="
    ls -lh "$PCAP_FILE"
    echo "=============================================="
    echo ""

else

    echo ""
    echo "ERROR: PCAP file not created."
    echo ""

fi
