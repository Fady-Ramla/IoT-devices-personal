# Learning Switch (Switching Hub)

## Overview

The Learning Switch is the first SDN application implemented using the Ryu Controller.

Its purpose is to emulate the behavior of a traditional Layer-2 Ethernet switch while demonstrating how Software Defined Networking separates the Control Plane from the Data Plane.

Unlike traditional switches, forwarding decisions are made by the SDN controller rather than the switch itself.

---

# Objectives

The Learning Switch aims to:

* Understand OpenFlow communication.
* Learn source MAC addresses dynamically.
* Build a MAC-to-Port mapping table.
* Forward packets correctly.
* Reduce unnecessary Packet-In messages by installing Flow Entries.

---

# SDN Architecture

The Learning Switch consists of two main components:

## OpenFlow Switch (OVS)

Responsibilities:

* Receive packets.
* Search the Flow Table.
* Execute installed Flow Entries.
* Send Packet-In messages when no matching rule exists.

---

## Ryu Controller

Responsibilities:

* Receive Packet-In messages.
* Parse packets.
* Learn MAC addresses.
* Decide forwarding actions.
* Install Flow Entries inside the switch.

---

# Packet Processing Workflow

The forwarding process follows these steps:

1. A host sends a packet.
2. The switch searches its Flow Table.
3. If no matching rule exists, a Packet-In message is sent to the controller.
4. The controller parses the packet.
5. The source MAC address is learned.
6. The destination MAC address is searched in the MAC table.
7. If the destination is known, the output port is selected.
8. If the destination is unknown, the packet is flooded.
9. The controller sends a Packet-Out message.
10. A Flow Entry is installed inside the switch using FlowMod.
11. Future packets matching the same flow are forwarded directly by the switch.

---

# MAC Learning

The controller maintains a MAC Address Table.

Each entry maps:

MAC Address → Switch Port

Example:

| MAC Address       | Port |
| ----------------- | ---- |
| 00:00:00:00:00:01 | 1    |
| 00:00:00:00:00:02 | 2    |

Whenever a packet arrives, the controller updates this table using the packet's source MAC address.

---

# Packet-In

Packet-In is generated when:

* No matching Flow Entry exists.
* The switch requires the controller's decision.

Information carried by Packet-In includes:

* Incoming Port
* Ethernet Header
* Packet Data
* Buffer ID
* Datapath ID

---

# Packet-Out

After making a forwarding decision, the controller sends a Packet-Out message.

Packet-Out instructs the switch to immediately forward the current packet through the selected output port.

---

# FlowMod

To avoid contacting the controller for every packet, the controller installs a Flow Entry using FlowMod.

Each Flow Entry contains:

* Match Fields
* Actions
* Priority
* Counters
* Timeouts

Once installed, similar packets are forwarded locally by the switch.

---

# Flow Table

Each OpenFlow switch maintains a Flow Table.

Each Flow Entry consists of:

| Field    | Description                         |
| -------- | ----------------------------------- |
| Match    | Conditions used to identify packets |
| Actions  | Forwarding decision                 |
| Priority | Rule priority                       |
| Counters | Packet and byte statistics          |
| Timeouts | Rule lifetime                       |

---

# Flooding

If the destination MAC address is unknown, the controller selects:

OFPP_FLOOD

The switch broadcasts the packet to every port except the incoming port.

Once the destination replies, its MAC address becomes known and future packets are forwarded normally.

---

# Relationship with Traffic Monitor

The Learning Switch provides packet forwarding functionality.

The Traffic Monitor extends the Learning Switch by periodically collecting network statistics.

Traffic Monitoring inherits all switching functionality while adding:

* Datapath Registration
* Monitoring Thread
* Flow Statistics Requests
* Port Statistics Requests

---

# Current Implementation Status

✅ Packet-In handling.

✅ MAC learning.

✅ MAC table management.

✅ Flooding for unknown destinations.

✅ Packet-Out forwarding.

✅ FlowMod installation.

✅ Basic Layer-2 switching completed.

---

# Future Enhancements

The Learning Switch will be extended with:

* Traffic Monitoring.
* Packet Parsing.
* Feature Extraction.
* AI-based anomaly detection.
* Self-Healing mechanism.
* REST APIs.
* Dashboard integration.

---

# Conclusion

The Learning Switch serves as the foundation of the SDN controller. It demonstrates how packet forwarding decisions are moved from the switch to the controller and establishes the core functionality upon which Traffic Monitoring, Packet Parsing, Feature Extraction, and AI-based security mechanisms are built.
