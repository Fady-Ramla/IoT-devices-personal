#!/usr/bin/env python3
"""Generate ephemeral, lab-only Web API credentials for the TrustFlow v2 canary.

Secrets are written only to a mode-0600 shell env file. Nothing is printed,
logged, or added to the dataset. Do not use these credentials outside the lab.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import secrets
import shlex
import tempfile


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def password_record(password: str) -> str:
    iterations = 310_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${b64u(salt)}${b64u(digest)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("/tmp/trustflow_demo_auth.env"))
    args = parser.parse_args()
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise SystemExit(f"refusing symlink credential path: {output}")

    username = "trustflow_demo"
    password = secrets.token_urlsafe(24)
    jwt_secret = secrets.token_urlsafe(48)
    values = {
        "ADMIN_USERNAME": username,
        "ADMIN_PASSWORD_HASH": password_record(password),
        "JWT_SECRET": jwt_secret,
        "TRUSTFLOW_DEMO_PASSWORD": password,
    }
    content = "\n".join(f"export {key}={shlex.quote(value)}" for key, value in values.items()) + "\n"

    fd, temp_name = tempfile.mkstemp(prefix=".trustflow_demo_auth.", dir=str(output.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, output)
        os.chmod(output, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    print("Ephemeral lab demo credentials prepared (secret values not displayed).", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
