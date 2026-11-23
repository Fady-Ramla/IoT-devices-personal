# SSH frontend: primary/standby verification

## Design

SSH clients use the dedicated TCP frontend `h38` (`10.10.20.100:2222`). New connections prefer primary `h4:22`; if it is unavailable, the frontend selects standby `h20:22`. The SSH listener is separate from the existing Web/API listener on `h38:5000`, which retains the default round-robin strategy.

Only `h36` (`10.10.40.36`) and `h37` (`10.10.40.37`) are authorized to connect to the SSH frontend. Other clients are denied and their attempts are recorded as `ssh_access_denied`. Direct SSH access to `h4:22` and `h20:22` is not allowed from clients; backend SSH connections must originate from the frontend `h38`.

## Runtime checks in the Mininet CLI

After starting Ryu and `mininet/Real_network_topology.py` with demo services enabled, check that both backends and the frontend are listening:

```text
mininet> h4 ss -lntp '( sport = :22 )'
mininet> h20 ss -lntp '( sport = :22 )'
mininet> h38 ss -lntp '( sport = :2222 )'
```

Check that both authorized clients can establish TCP connections to the frontend, then check the policy blocks an unauthorized client and direct backend access:

```text
mininet> h36 nc -vz -w 2 10.10.20.100 2222
mininet> h37 nc -vz -w 2 10.10.20.100 2222
mininet> h21 nc -vz -w 2 10.10.20.100 2222
mininet> h36 nc -vz -w 2 10.10.20.4 22
mininet> h37 nc -vz -w 2 10.10.20.20 22
```

The first two commands should succeed. The unauthorized frontend and direct-backend attempts should fail or time out. Check the controller's denial audit from a shell on the machine running Ryu:

```bash
curl -fsS http://127.0.0.1:8080/firewall/events |
  python3 -c 'import json,sys; [print(e) for e in json.load(sys.stdin) if e.get("event_type")=="ssh_access_denied"]'
```

## Verify primary selection and failover for new connections

Confirm `h4:22` is selected while the primary is healthy:

```text
mininet> h36 nc -vz -w 2 10.10.20.100 2222
mininet> h38 cat /tmp/secureiot-lb-ssh-stats.json
```

In the stats, `last_backend` should be `10.10.20.4:22`; `strategy` should be `primary-backup`. For a controlled failover test, stop only the primary sshd process, reconnect through the VIP, and inspect the stats again:

```text
mininet> h4 sh -c 'test -s /tmp/sshd-h4.pid && kill "$(cat /tmp/sshd-h4.pid)"'
mininet> h36 nc -vz -w 3 10.10.20.100 2222
mininet> h38 cat /tmp/secureiot-lb-ssh-stats.json
```

The new connection should succeed via `10.10.20.20:22`; the stats should show that backend in `last_backend`, and `backend_failovers` should increase. Restart the Mininet topology after this test to restore the primary backend to its normal startup state.

The authenticated runtime API also exposes SSH stats separately from the existing Web/API load-balancer counters:

```bash
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  http://127.0.0.1:8080/network/load-balancer/stats
```

The response keeps its existing top-level Web/API fields and adds `ssh_frontend` with the SSH strategy, backend list, selected backend, and failover counters.

## Session behavior and limits

This is TCP connection failover, not SSH session migration. If a backend fails during an established SSH session, that connection will break; users must reconnect, and the new connection can then use the standby. `--idle-timeout 0` disables the proxy's idle relay timeout but does not preserve a session across backend failure. Runtime SSH connections were not exercised in the cloud sandbox; these commands are for validation in the user's live Mininet environment.
