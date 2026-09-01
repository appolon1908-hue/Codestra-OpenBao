#!/usr/bin/env python3
"""Read back every applied plan operation without reading secret values."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def command(*args: str) -> str:
    result = subprocess.run(["bao", *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError("readback_command_failed:" + args[0])
    return result.stdout


def json_command(*args: str):
    return json.loads(command(*args, "-format=json"))


def data(value):
    return value.get("data", value) if isinstance(value, dict) else value


def selected(mapping: dict, keys) -> dict:
    return {key: mapping.get(key) for key in keys}


def verify(operation: dict) -> None:
    kind = operation["kind"]
    name = operation["name"]
    payload = operation["payload"]
    if kind == "secret_engine":
        mounts = data(json_command("secrets", "list"))
        item = mounts.get(name)
        if not item or item.get("type") != "kv" or (item.get("options") or {}).get("version") != "2":
            raise ValueError("secret_engine_readback_mismatch")
    elif kind == "auth_method":
        auths = data(json_command("auth", "list"))
        item = auths.get(name)
        if not item or item.get("type") != "jwt":
            raise ValueError("auth_method_readback_mismatch")
    elif kind == "policy":
        if command("policy", "read", name).strip() != payload["policy"].strip():
            raise ValueError("policy_readback_mismatch:" + name)
    elif kind in {"auth_config", "jwt_role"}:
        actual = data(json_command("read", name))
        keys = tuple(payload)
        if selected(actual, keys) != selected(payload, keys):
            raise ValueError(kind + "_readback_mismatch:" + name)
    elif kind == "audit_device":
        audits = data(json_command("audit", "list"))
        item = audits.get(name)
        if not item or item.get("type") != payload["type"]:
            raise ValueError("audit_device_readback_mismatch")
    else:
        raise ValueError("unknown_plan_kind:" + str(kind))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_applied_plan.py PLAN.json")
    try:
        plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        for operation in plan["operations"]:
            verify(operation)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"PLAN_APPLIED_EXACTLY=false ERROR={exc}") from exc
    print("PLAN_APPLIED_EXACTLY=true")
    print(f"PLAN_DESTROY_COUNT={plan['counts']['destroy']}")


if __name__ == "__main__":
    main()
