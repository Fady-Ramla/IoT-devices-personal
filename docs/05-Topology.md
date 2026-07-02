# Network Topology

## Overview

The SDN testbed is designed using a Partial Mesh topology to evaluate traffic monitoring, feature extraction, AI-based anomaly detection, and self-healing mechanisms.

The topology is intentionally designed with redundant paths to allow future implementation of fault tolerance and automatic rerouting.

---

# Topology Type

Partial Mesh

---

# Components

* 5 OpenFlow Switches
* 10 Hosts
* 1 Ryu SDN Controller

---

# Design Tool

The topology was designed using Draw.io before implementation in Mininet.

---

# Purpose

The topology supports:

* SDN traffic monitoring
* Packet parsing
* Feature extraction
* AI integration
* REST APIs
* Self-Healing
* Dashboard visualization

---

# Current Status

✅ Initial topology designed.

🟨 Mininet implementation (next step).

🟨 Traffic generation.

🟨 Failure simulation.
