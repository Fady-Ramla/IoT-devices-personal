# Traffic Monitor

## Overview

The Traffic Monitor module extends the basic Ryu Learning Switch by periodically collecting traffic statistics from all connected OpenFlow switches.

Instead of forwarding packets only, the controller continuously monitors network activity by requesting statistics from switches. These statistics provide the foundation for feature extraction, AI-based traffic analysis, anomaly detection, and dashboard visualization.

---

# Objectives

The main objectives of the Traffic Monitor are:

* Monitor the health of the SDN network.
* Collect real-time traffic statistics.
* Measure flow and port activity.
* Build the required features for the AI module.
* Provide network statistics for visualization on the dashboard.

---

# Why Traffic Monitoring?

A network administrator should continuously monitor the network instead of waiting until failures occur.

Traffic monitoring allows the controller to:

* Detect abnormal traffic.
* Monitor bandwidth utilization.
* Measure switch activity.
* Observe flow behavior.
* Build datasets required for machine learning.

Without continuous monitoring, it becomes difficult to determine whether network behavior is normal or abnormal.

---

# Traffic Monitoring Architecture

The monitoring process follows the following workflow:

1. An OpenFlow switch connects to the Ryu Controller.
2. The controller registers the switch (Datapath).
3. A background monitoring thread starts.
4. Every fixed interval (5–10 seconds), the controller requests statistics.
5. The switch replies with Flow Statistics and Port Statistics.
6. The controller processes these statistics.
7. The collected values become inputs for feature extraction and AI analysis.

---

# Datapath Registration

The controller maintains a dictionary called **datapaths** containing all currently connected switches.

Whenever a switch connects:

* The Datapath object is registered.
* The controller becomes able to communicate with that switch.

Whenever a switch disconnects:

* The Datapath object is removed.
* The controller stops sending monitoring requests.

This mechanism guarantees that only active switches are monitored.

---

# Monitoring Thread

Traffic monitoring runs in a separate Green Thread created using:

```python
hub.spawn(self._monitor)
```

The monitoring thread runs independently from packet forwarding.

Its responsibilities are:

* Iterate over all connected switches.
* Send statistics requests.
* Sleep for a fixed interval.
* Repeat indefinitely.

This allows the controller to monitor the network continuously without interrupting packet forwarding.

---

# Statistics Requests

Every monitoring cycle, the controller sends two OpenFlow requests to each switch.

## 1. Flow Statistics Request

```python
OFPFlowStatsRequest
```

This request retrieves information about every flow entry installed in the switch.

Returned information includes:

* Flow Match Fields
* Priority
* Actions
* Packet Count
* Byte Count
* Flow Duration

These statistics are later used to calculate AI features such as:

* Flow Duration
* Packet Rate
* Byte Rate

---

## 2. Port Statistics Request

```python
OFPPortStatsRequest
```

This request retrieves statistics for every switch port.

Returned information includes:

* RX Packets
* TX Packets
* RX Bytes
* TX Bytes
* RX Errors
* TX Errors
* Port Number

These statistics help monitor switch utilization and bandwidth usage.

---

# Flow Statistics Reply

After receiving a Flow Statistics Request, the switch replies with:

```python
EventOFPFlowStatsReply
```

The reply contains a list of flow entries.

Each flow entry contains information such as:

* Match
* Priority
* Duration
* Packet Count
* Byte Count
* Instructions
* Actions

The controller processes each flow separately and can calculate:

* Packet Rate
* Byte Rate
* Flow Duration

---

# Port Statistics Reply

After receiving a Port Statistics Request, the switch replies with:

```python
EventOFPPortStatsReply
```

Each port provides:

* RX Packets
* TX Packets
* RX Bytes
* TX Bytes
* RX Errors
* TX Errors

These values are useful for monitoring traffic load and detecting overloaded interfaces.

---

# Statistics Collected

## Flow Statistics

| Statistic    | Description                       |
| ------------ | --------------------------------- |
| Packet Count | Total packets matched by the flow |
| Byte Count   | Total transmitted bytes           |
| Duration     | Lifetime of the flow              |
| Match Fields | Flow matching conditions          |
| Priority     | Flow priority                     |
| Actions      | Output actions                    |

---

## Port Statistics

| Statistic  | Description         |
| ---------- | ------------------- |
| RX Packets | Received packets    |
| TX Packets | Transmitted packets |
| RX Bytes   | Received bytes      |
| TX Bytes   | Transmitted bytes   |
| RX Errors  | Receive errors      |
| TX Errors  | Transmission errors |

---

# Relationship with Packet Parsing

Traffic Monitoring and Packet Parsing complement each other.

Packet Parsing extracts information directly from packet headers, such as:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* TTL
* TCP Flags

Traffic Monitoring provides accumulated statistics over time, such as:

* Packet Count
* Byte Count
* Flow Duration
* RX/TX Bytes
* RX/TX Packets

Both sources are required to build the complete feature vector for the AI model.

---

# AI Feature Mapping

| AI Feature    | Source                          |
| ------------- | ------------------------------- |
| flow_duration | Flow Statistics                 |
| packet_rate   | Calculated from Flow Statistics |
| byte_rate     | Calculated from Flow Statistics |
| packet_count  | Flow Statistics                 |
| byte_count    | Flow Statistics                 |
| src_bytes     | Port Statistics                 |
| dst_bytes     | Port Statistics                 |
| rx_packets    | Port Statistics                 |
| tx_packets    | Port Statistics                 |

---

# Current Implementation Status

✅ Learning Switch completed.

✅ Datapath registration implemented.

✅ Monitoring thread implemented.

✅ Periodic statistics requests implemented.

✅ Flow Statistics processing implemented.

✅ Port Statistics processing implemented.

🟨 Packet Parsing (next module).

🟨 Feature Extraction (next module).

🟨 AI Integration (future work).

---

# Future Work

The next development stages include:

* Packet Parsing.
* Feature Extraction.
* Flow Data Structure.
* REST APIs.
* AI Integration.
* Self-Healing Mechanism.
* Dashboard Integration.

---

# Conclusion

The Traffic Monitor forms the monitoring layer of the SDN controller. It periodically gathers Flow and Port statistics from all connected OpenFlow switches, providing the quantitative network information required for visualization, traffic analysis, and AI-based intrusion detection. Together with Packet Parsing, it forms the foundation of the feature extraction pipeline used throughout the project.

