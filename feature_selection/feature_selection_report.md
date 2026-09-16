################################################################################
                   #  FEATURE SELECTION REPORT — READ ONLY                    #
################################################################################

================================================================================
  PACKET ML
================================================================================
File: /home/fady/IoT-devices/ML_FINAL/labeled_packet_features_ML.csv
Rows    : 142,987
Columns : 29

--------------------------------------------------------------------------------
COLUMN INVENTORY
--------------------------------------------------------------------------------
1   run_id                  object              28    52,379  GROUPING/ID
2   timestamp               float64        142,954         0  GROUPING/ID
3   switch                  float64              0   142,987  IDENTIFIER
4   src_mac                 object               7         0  IDENTIFIER
5   dst_mac                 object               8         0  IDENTIFIER
6   src_ip                  object               7         0  IDENTIFIER
7   dst_ip                  object               7         0  IDENTIFIER
8   src_port                int64           14,938         0  FEATURE
9   dst_port                int64            9,061         0  FEATURE
10  ip_proto                int64                3         0  FEATURE
11  ttl                     int64               25         0  FEATURE
12  tcp                     int64                2         0  FEATURE
13  udp                     int64                1         0  FEATURE
14  icmp                    int64                2         0  FEATURE
15  arp                     int64                2         0  FEATURE
16  http                    int64                2         0  FEATURE
17  https                   int64                2         0  FEATURE
18  dns                     int64                1         0  FEATURE
19  ssh                     int64                2         0  FEATURE
20  telnet                  int64                2         0  FEATURE
21  smtp                    int64                2         0  FEATURE
22  syn_flag_number         int64                2         0  FEATURE
23  ack_flag_number         int64                2         0  FEATURE
24  fin_flag_number         int64                2         0  FEATURE
25  rst_flag_number         int64                2         0  FEATURE
26  psh_flag_number         int64                2         0  FEATURE
27  packet_length           int64               19         0  FEATURE
28  payload_length          int64               13         0  FEATURE
29  label                   object               4         0  TARGET

--------------------------------------------------------------------------------
F-SCORE
--------------------------------------------------------------------------------
1   udp                                    inf
2   dns                                    inf
3   http                              1.142405
4   src_port                          0.972283
5   ttl                               0.619709
6   syn_flag_number                   0.458986
7   ack_flag_number                   0.360407
8   dst_port                          0.153710
9   rst_flag_number                   0.089714
10  packet_length                     0.083383
11  fin_flag_number                   0.067017
12  psh_flag_number                   0.057068
13  payload_length                    0.037359
14  tcp                               0.007229
15  ip_proto                          0.007112
16  arp                               0.004971
17  icmp                              0.002258
18  https                             0.000389
19  ssh                               0.000389
20  telnet                            0.000389
21  smtp                              0.000389

--------------------------------------------------------------------------------
REDUNDANCY (|r| >= 0.9)
--------------------------------------------------------------------------------
ip_proto                     ↔ tcp                          |r|=0.9972
packet_length                ↔ payload_length               |r|=0.9850
psh_flag_number              ↔ payload_length               |r|=0.9055
psh_flag_number              ↔ packet_length                |r|=0.9050
ip_proto                     ↔ arp                          |r|=0.9004

--------------------------------------------------------------------------------
RANDOM FOREST IMPORTANCE
--------------------------------------------------------------------------------
1   src_port                        0.32998240
2   dst_port                        0.10466573
3   ip_proto                        0.00122753
4   ttl                             0.10852384
5   tcp                             0.00165951
6   udp                             0.00000000
7   icmp                            0.00014203
8   arp                             0.00056522
9   http                            0.10556887
10  https                           0.00001646
11  dns                             0.00000000
12  ssh                             0.00002394
13  telnet                          0.00001267
14  smtp                            0.00001670
15  syn_flag_number                 0.05451900
16  ack_flag_number                 0.07116849
17  fin_flag_number                 0.00329532
18  rst_flag_number                 0.01346741
19  psh_flag_number                 0.00320055
20  packet_length                   0.19589875
21  payload_length                  0.00604557

--------------------------------------------------------------------------------
FEATURE SELECTION DECISION
--------------------------------------------------------------------------------
Feature                             RF     F-score  Online  Decision
--------------------------------------------------------------------------------
src_port                       0.32998      0.9723     yes  KEEP
dst_port                       0.10467      0.1537     yes  KEEP
ip_proto                       0.00123      0.0071     yes  REVIEW
ttl                            0.10852      0.6197     yes  KEEP
tcp                            0.00166      0.0072     yes  REVIEW
udp                            0.00000         inf     yes  DROP
icmp                           0.00014      0.0023     yes  REVIEW
arp                            0.00057      0.0050     yes  REVIEW
http                           0.10557      1.1424     yes  KEEP
https                          0.00002      0.0004     yes  REVIEW
dns                            0.00000         inf     yes  DROP
ssh                            0.00002      0.0004     yes  REVIEW
telnet                         0.00001      0.0004     yes  REVIEW
smtp                           0.00002      0.0004     yes  REVIEW
syn_flag_number                0.05452      0.4590     yes  KEEP
ack_flag_number                0.07117      0.3604     yes  KEEP
fin_flag_number                0.00330      0.0670     yes  REVIEW
rst_flag_number                0.01347      0.0897     yes  KEEP
psh_flag_number                0.00320      0.0571     yes  REVIEW
packet_length                  0.19590      0.0834     yes  KEEP
payload_length                 0.00605      0.0374     yes  KEEP

--------------------------------------------------------------------------------
FINAL LISTS
--------------------------------------------------------------------------------

KEEP (9):
  - src_port
  - dst_port
  - ttl
  - http
  - syn_flag_number
  - ack_flag_number
  - rst_flag_number
  - packet_length
  - payload_length

REVIEW (10):
  - ip_proto
  - tcp
  - icmp
  - arp
  - https
  - ssh
  - telnet
  - smtp
  - fin_flag_number
  - psh_flag_number

DROP (2):
  - udp
  - dns

--------------------------------------------------------------------------------
SYN FLOOD FEATURE CANDIDATES (proposed, not added)
--------------------------------------------------------------------------------
  + syn_ack_ratio          → syn / (ack + 1) — SYN dominance
  + is_syn_only            → (syn=1) AND (ack=0)
  + is_syn_ack             → (syn=1) AND (ack=1)
  + pkt_size_class         → bin(packet_length)

================================================================================
  FLOW ML
================================================================================
File: /home/fady/IoT-devices/ML_FINAL/labeled_traffic_features_ML.csv
Rows    : 183,072
Columns : 24

--------------------------------------------------------------------------------
COLUMN INVENTORY
--------------------------------------------------------------------------------
1   timestamp               float64        183,072         0  GROUPING/ID
2   switch                  int64                5         0  IDENTIFIER
3   src_ip                  object              10         0  IDENTIFIER
4   dst_ip                  object              10         0  IDENTIFIER
5   src_port                int64           25,331         0  FEATURE
6   dst_port                int64            7,012         0  FEATURE
7   ip_proto                int64                2         0  FEATURE
8   tcp                     int64                2         0  FEATURE
9   udp                     int64                1         0  FEATURE
10  icmp                    int64                2         0  FEATURE
11  http                    int64                2         0  FEATURE
12  https                   int64                2         0  FEATURE
13  dns                     int64                1         0  FEATURE
14  ssh                     int64                2         0  FEATURE
15  telnet                  int64                1         0  FEATURE
16  smtp                    int64                2         0  FEATURE
17  flow_duration           float64         21,126         0  FEATURE
18  total_pkts              int64               97         0  FEATURE
19  total_bytes             int64              556         0  FEATURE
20  packet_rate             float64         34,761         0  FEATURE
21  byte_rate               float64         47,652         0  FEATURE
22  avg_packet_size         float64            474         0  FEATURE
23  label                   object               4         0  TARGET
24  run_id                  object              60   157,489  GROUPING/ID

--------------------------------------------------------------------------------
F-SCORE
--------------------------------------------------------------------------------
1   udp                                    inf
2   dns                                    inf
3   telnet                                 inf
4   src_port                          0.320526
5   flow_duration                     0.195439
6   avg_packet_size                   0.044202
7   dst_port                          0.015601
8   byte_rate                         0.006210
9   total_pkts                        0.005977
10  total_bytes                       0.005428
11  packet_rate                       0.005281
12  ip_proto                          0.002116
13  tcp                               0.002116
14  icmp                              0.002116
15  http                              0.001685
16  smtp                              0.000730
17  ssh                               0.000043
18  https                             0.000030

--------------------------------------------------------------------------------
REDUNDANCY (|r| >= 0.9)
--------------------------------------------------------------------------------
tcp                          ↔ icmp                         |r|=1.0000
ip_proto                     ↔ icmp                         |r|=1.0000
ip_proto                     ↔ tcp                          |r|=1.0000
total_pkts                   ↔ total_bytes                  |r|=0.9975
packet_rate                  ↔ byte_rate                    |r|=0.9209

--------------------------------------------------------------------------------
RANDOM FOREST IMPORTANCE
--------------------------------------------------------------------------------
1   src_port                        0.21716270
2   dst_port                        0.03627071
3   ip_proto                        0.00032349
4   tcp                             0.00083296
5   udp                             0.00000000
6   icmp                            0.00095358
7   http                            0.00068726
8   https                           0.00001497
9   dns                             0.00000000
10  ssh                             0.00001660
11  telnet                          0.00000000
12  smtp                            0.00000131
13  flow_duration                   0.15672649
14  total_pkts                      0.06867767
15  total_bytes                     0.08102127
16  packet_rate                     0.11986565
17  byte_rate                       0.12262732
18  avg_packet_size                 0.19481802

--------------------------------------------------------------------------------
FEATURE SELECTION DECISION
--------------------------------------------------------------------------------
Feature                             RF     F-score  Online  Decision
--------------------------------------------------------------------------------
src_port                       0.21716      0.3205     yes  KEEP
dst_port                       0.03627      0.0156     yes  KEEP
ip_proto                       0.00032      0.0021     yes  REVIEW
tcp                            0.00083      0.0021     yes  REVIEW
udp                            0.00000         inf     yes  DROP
icmp                           0.00095      0.0021     yes  REVIEW
http                           0.00069      0.0017     yes  REVIEW
https                          0.00001      0.0000     yes  REVIEW
dns                            0.00000         inf     yes  DROP
ssh                            0.00002      0.0000     yes  REVIEW
telnet                         0.00000         inf     yes  DROP
smtp                           0.00000      0.0007     yes  REVIEW
flow_duration                  0.15673      0.1954     yes  KEEP
total_pkts                     0.06868      0.0060     yes  KEEP
total_bytes                    0.08102      0.0054     yes  KEEP
packet_rate                    0.11987      0.0053     yes  KEEP
byte_rate                      0.12263      0.0062     yes  KEEP
avg_packet_size                0.19482      0.0442     yes  KEEP

--------------------------------------------------------------------------------
FINAL LISTS
--------------------------------------------------------------------------------

KEEP (8):
  - src_port
  - dst_port
  - flow_duration
  - total_pkts
  - total_bytes
  - packet_rate
  - byte_rate
  - avg_packet_size

REVIEW (7):
  - ip_proto
  - tcp
  - icmp
  - http
  - https
  - ssh
  - smtp

DROP (3):
  - udp
  - dns
  - telnet

--------------------------------------------------------------------------------
SYN FLOOD FEATURE CANDIDATES (proposed, not added)
--------------------------------------------------------------------------------
  + syn_pkt_ratio          → SYN packets / total_pkts
  + pkt_density            → total_pkts / (flow_duration + 1)
  + bytes_per_pkt          → total_bytes / (total_pkts + 1)
  + flow_intensity         → packet_rate / (flow_duration + 1)

================================================================================
  PACKET vs FLOW
================================================================================
Common : 18
Packet-only : 11
Flow-only   : 6

Packet-only:
  - ack_flag_number
  - arp
  - dst_mac
  - fin_flag_number
  - packet_length
  - payload_length
  - psh_flag_number
  - rst_flag_number
  - src_mac
  - syn_flag_number
  - ttl

Flow-only:
  - avg_packet_size
  - byte_rate
  - flow_duration
  - packet_rate
  - total_bytes
  - total_pkts