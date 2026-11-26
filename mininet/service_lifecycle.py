"""Safe service lifecycle inspection helpers for SecureIoT Mininet."""

import json
import re
import time


def listener_line(host, protocol, port):
    """Return the ss listener row for a TCP or UDP port, or an empty string."""
    options = {
        "tcp": "-H -ltnp",
        "udp": "-H -lunp",
    }
    if protocol not in options:
        raise ValueError("protocol must be tcp or udp")

    output = host.cmd("ss %s 2>/dev/null" % options[protocol])
    pattern = re.compile(r":%d(?:\s|$)" % int(port))

    for line in output.splitlines():
        if pattern.search(line):
            return line.strip()
    return ""


def listener_pid(line):
    """Extract the owning PID from an ss listener row."""
    match = re.search(r"\bpid=(\d+)", line or "")
    return int(match.group(1)) if match else None



def listener_rows(host, protocol, port, address=None):
    """Return listener rows matching a local port and optional address."""
    options = {
        "tcp": "-H -ltnp",
        "udp": "-H -lunp",
    }
    if protocol not in options:
        raise ValueError("protocol must be tcp or udp")

    output = host.cmd("ss %s 2>/dev/null" % options[protocol])
    rows = []

    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        try:
            local_address, local_port = fields[3].rsplit(":", 1)
            local_port = int(local_port)
        except (ValueError, TypeError):
            continue

        local_address = local_address.strip("[]")
        if local_port == int(port):
            if address is None or local_address == address:
                rows.append(line.strip())

    return rows


def listener_group_state(host, endpoints, expected_tokens):
    """Validate a complete multi-socket service owned by one expected PID.

    Each endpoint is (protocol, local_address, port).
    Returns (healthy|absent|conflict, pid, detail).
    """
    endpoints = tuple(endpoints)
    if not endpoints:
        raise ValueError("at least one endpoint is required")

    rows_by_endpoint = [
        listener_rows(host, protocol, port)
        for protocol, address, port in endpoints
    ]

    if not any(rows_by_endpoint):
        return "absent", None, ""

    pids = set()

    for (protocol, address, port), all_rows in zip(
        endpoints, rows_by_endpoint
    ):
        matching = []
        for row in all_rows:
            fields = row.split()
            try:
                local_address, local_port = fields[3].rsplit(":", 1)
                local_address = local_address.strip("[]")
                local_port = int(local_port)
            except (IndexError, ValueError):
                continue

            if local_address == address and local_port == int(port):
                matching.append(row)

        if len(all_rows) != 1 or len(matching) != 1:
            return (
                "conflict", None,
                "incomplete, ambiguous, or wrongly bound listener",
            )

        matches = re.findall(r"\bpid=(\d+)", matching[0])
        if len(matches) != 1:
            return "conflict", None, "listener PID is missing or ambiguous"

        pids.add(int(matches[0]))

    if len(pids) != 1:
        return "conflict", None, "listeners belong to different processes"

    pid = next(iter(pids))
    commandline = host.cmd(
        "tr '\\0' ' ' < /proc/%d/cmdline 2>/dev/null" % pid
    ).strip()

    if not commandline or not all(
        token in commandline for token in expected_tokens
    ):
        return "conflict", pid, "listener owner does not match expected service"

    return "healthy", pid, commandline


def listener_commandline(host, line):
    """Read the command line of the process owning a listener."""
    pid = listener_pid(line)
    if pid is None:
        return ""
    return host.cmd(
        "tr '\\0' ' ' < /proc/%d/cmdline 2>/dev/null" % pid
    ).strip()


def listener_owned_by(host, line, expected_tokens):
    """Check that a listener belongs to the expected executable/configuration."""
    command = listener_commandline(host, line)
    return bool(command) and all(
        token in command for token in expected_tokens
    )


def http_service_is_healthy(response, service_name):
    """Validate both HTTP health and the identity of a demo backend."""
    return (
        '"status": "healthy"' in (response or "")
        and ('"service": "%s"' % service_name) in (response or "")
    )


def load_balancer_command_matches(commandline, expected_args):
    """Check that a process is the expected Load Balancer configuration."""
    return (
        "load_balancer.py" in (commandline or "")
        and all(argument in commandline for argument in expected_args)
    )


def load_balancer_heartbeat_is_valid(
    heartbeat_text, commandline, expected_args, now=None, max_age=5.0,
    expected_pid=None,
):
    """Validate heartbeat PID, freshness, executable and configured arguments."""
    try:
        payload = json.loads(heartbeat_text)
        pid = int(payload["pid"])
        timestamp = float(payload["timestamp"])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return False

    current_time = time.time() if now is None else float(now)
    age = current_time - timestamp

    return (
        pid > 1
        and (expected_pid is None or pid == int(expected_pid))
        and -1.0 <= age <= float(max_age)
        and load_balancer_command_matches(commandline, expected_args)
    )


def ensure_listener_group(
    host, endpoints, expected_tokens, launch_command,
    timeout=10.0, poll_interval=0.25, health_check=None,
):
    """Reuse a healthy service, launch an absent one, reject conflicts.

    Returns (pid, started). Existing unhealthy/conflicting listeners are
    never killed or replaced automatically.
    """
    state, pid, detail = listener_group_state(
        host, endpoints, expected_tokens
    )

    if state == "healthy":
        if health_check is not None and not health_check(pid, detail):
            raise RuntimeError(
                "existing service listener is not healthy (pid=%s)" % pid
            )
        return pid, False

    if state != "absent":
        raise RuntimeError(
            "service startup refused: existing listener conflict: %s" % detail
        )

    if not launch_command or not str(launch_command).strip():
        raise ValueError("launch_command must be non-empty")

    host.cmd(launch_command)
    deadline = time.monotonic() + float(timeout)
    last_detail = "listeners have not appeared"

    while time.monotonic() < deadline:
        state, pid, detail = listener_group_state(
            host, endpoints, expected_tokens
        )
        last_detail = detail

        if state == "healthy":
            if health_check is None or health_check(pid, detail):
                return pid, True

        time.sleep(float(poll_interval))

    raise RuntimeError(
        "service did not become healthy within %.1fs: %s"
        % (float(timeout), last_detail)
    )
