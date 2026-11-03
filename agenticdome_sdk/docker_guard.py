"""Docker Agent mandatory guard adapter. JSON in/out; fail closed; never execute."""
from __future__ import annotations
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit


def event_payload(event):
    if not isinstance(event, dict) or event.get("hook_event_name") != "tool_guard":
        raise ValueError("Expected a Docker tool_guard event")
    payload = {key: event.get(key, default) for key, default in {
        "hook_event_name": "", "agent_name": "", "tool_name": "", "tool_input": None,
        "session_id": "", "tool_use_id": "", "tool_category": "unknown", "cwd": ""}.items()}
    if not isinstance(payload["tool_input"], dict): raise ValueError("Expected tool input object")
    if any(not isinstance(payload[key], str) or not payload[key] for key in ("agent_name", "tool_name", "session_id", "tool_use_id")):
        raise ValueError("Incomplete tool guard identity")
    raw=json.dumps(payload,allow_nan=False)
    if len(raw.encode()) > 131072: raise ValueError("Tool input exceeds limit")
    return json.loads(raw)


def configured_client():
    from .client import AgenticDomeClient
    gateway = os.environ["AGENTICDOME_GATEWAY_URL"].rstrip("/")
    parsed = urlsplit(gateway)
    if (parsed.path != "/gateway/v1" or parsed.query or parsed.fragment or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or any(ord(c)<=32 for c in gateway)):
        raise ValueError("Use the assigned Gateway URL ending in /gateway/v1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise ValueError("Use HTTPS or a loopback sidecar")
    return AgenticDomeClient(api_base=gateway[:-len('/gateway/v1')], timeout=8, mode="live")


def check_tool(event, client=None):
    payload = event_payload(event)
    owned = client is None
    if owned: client = configured_client()
    try:
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        result = client.guard_native_tool(payload)
        if (not isinstance(result, dict) or result.get("schema") != "agenticdome.native-tool-decision.v1"
                or result.get("request_sha256") != expected or result.get("decision") not in {"allow", "deny"}
                or not isinstance(result.get("decision_id"), str) or not result["decision_id"]):
            raise ValueError("Unbound or incomplete native tool decision")
        return {"hook_specific_output": {"hook_event_name": "tool_guard", "permission_decision": result["decision"],
            "permission_decision_reason": "Allowed by AgenticDome policy" if result["decision"] == "allow" else "Blocked by AgenticDome policy",
            "metadata": {"agenticdome_decision_id": result["decision_id"], "evidence_scope": "pre_execution_policy_only"}}}
    finally:
        if owned: client.close()


def main():
    try:
        if sys.argv[1:] == ["--check"]:
            client = configured_client()
            try: report = client.native_guard_ready()
            finally: client.close()
            if (not isinstance(report, dict) or report.get("schema") != "agenticdome.native-guard-readiness.v1"
                    or report.get("ready") is not True or report.get("native_tool_guard") is not True):
                raise ValueError("Updated Gateway guard capability is required")
            print(json.dumps(report))
            return 0
        if sys.argv[1:]: raise ValueError("Unknown guard option")
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072: raise ValueError("Input exceeds limit")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError("Duplicate input member")
                result[key] = value
            return result
        event = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
        print(json.dumps(check_tool(event)))
        return 0
    except Exception as exc:
        # Never expose tool arguments, credentials, exception URLs or response bodies.
        if sys.argv[1:]==["--check"]:
            status=getattr(exc,"status_code",None)
            reasons={401:"Caller credentials or identity were rejected",403:"Caller is outside the approved Gateway boundary",
                404:"The assigned sidecar needs the native guard update",503:"The assigned Gateway is not security ready"}
            print(json.dumps({"schema":"agenticdome.native-guard-readiness.v1","ready":False,
                "reason":reasons.get(status,"Load the generated Gateway, tenant, Runtime API key and approved identity settings"),
                "tool_executed":False}))
            return 2
        print(json.dumps({"decision": "block", "reason": "AgenticDome tool check failed. Verify the assigned Gateway, identity and runtime readiness."}))
        return 2


if __name__ == "__main__": raise SystemExit(main())
