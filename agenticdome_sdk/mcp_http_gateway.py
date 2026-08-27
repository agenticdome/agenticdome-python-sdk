"""Fail-closed, fixed-upstream MCP Streamable HTTP gateway.

This module deliberately is not a general-purpose open proxy. The upstream,
upstream credential and service identity are operator configuration. Per-call
session and user identity must arrive from a trusted application boundary.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, Iterator, List
from urllib.parse import urlparse

import requests

from .mcp_host import AgenticDomeMCPHostFirewall


class MCPGatewayConfigurationError(RuntimeError):
    """Raised when the gateway cannot establish a safe fixed boundary."""


def _required_env(name: str) -> str:
    value = str(os.getenv(name) or "").strip()
    if not value:
        raise MCPGatewayConfigurationError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class MCPHTTPGatewayConfig:
    upstream_url: str
    server_id: str
    agent_id: str
    business_purpose: str
    bind_host: str = "127.0.0.1"
    bind_port: int = 8791
    max_request_bytes: int = 2 * 1024 * 1024
    upstream_authorization: str = ""
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> "MCPHTTPGatewayConfig":
        upstream = _required_env("AGENTICDOME_MCP_UPSTREAM_URL")
        parsed = urlparse(upstream)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise MCPGatewayConfigurationError(
                "AGENTICDOME_MCP_UPSTREAM_URL must be one fixed HTTP(S) origin/path without embedded credentials"
            )
        purpose = _required_env("AGENTICDOME_MCP_BUSINESS_PURPOSE")
        if purpose == "REVIEW_REQUIRED_NOT_INVENTED":
            raise MCPGatewayConfigurationError("Configure the genuine MCP business purpose before starting the gateway")
        if str(os.getenv("AGENTICDOME_MCP_TRUST_IDENTITY_HEADERS") or "").strip().lower() != "true":
            raise MCPGatewayConfigurationError(
                "Set AGENTICDOME_MCP_TRUST_IDENTITY_HEADERS=true only after authenticated ingress strips and sets the identity headers"
            )
        return cls(
            upstream_url=upstream,
            server_id=_required_env("AGENTICDOME_MCP_SERVER_ID"),
            agent_id=_required_env("AGENTICDOME_MCP_AGENT_ID"),
            business_purpose=purpose,
            bind_host=str(os.getenv("AGENTICDOME_MCP_GATEWAY_BIND") or "127.0.0.1").strip(),
            bind_port=int(os.getenv("AGENTICDOME_MCP_GATEWAY_PORT") or "8791"),
            max_request_bytes=int(os.getenv("AGENTICDOME_MCP_MAX_REQUEST_BYTES") or str(2 * 1024 * 1024)),
            upstream_authorization=str(os.getenv("AGENTICDOME_MCP_UPSTREAM_AUTHORIZATION") or "").strip(),
        )


def _context(headers: Any, config: MCPHTTPGatewayConfig) -> Dict[str, str]:
    session_id = str(headers.get("X-AgenticDome-Session-Id") or headers.get("MCP-Session-Id") or "").strip()
    user_id = str(headers.get("X-AgenticDome-User-Id") or "").strip()
    if not session_id or not user_id:
        raise MCPGatewayConfigurationError(
            "Trusted X-AgenticDome-Session-Id (or MCP-Session-Id) and X-AgenticDome-User-Id headers are required"
        )
    return {
        "agent_id": config.agent_id,
        "session_id": session_id,
        "user_id": user_id,
        "mcp_server_id": config.server_id,
        "business_purpose": config.business_purpose,
    }


def _sse_events(lines: Iterable[str]) -> Iterator[List[str]]:
    event: List[str] = []
    for line in lines:
        if line == "":
            if event:
                yield event
                event = []
            continue
        event.append(line)
    if event:
        yield event


async def _review_sse_event(
    firewall: AgenticDomeMCPHostFirewall,
    request: Dict[str, Any],
    event: List[str],
    context: Dict[str, str],
) -> List[str]:
    if any(line.strip().lower() == "event: endpoint" for line in event):
        error = firewall.jsonrpc_error(
            None,
            -32000,
            "AgenticDome Blocked: legacy SSE endpoint advertisement requires a reviewed local adapter",
        )
        return ["event: message", "data: " + json.dumps(error, separators=(",", ":"))]
    data_indexes = [index for index, line in enumerate(event) if line.startswith("data:")]
    if not data_indexes:
        return event
    raw = "\n".join(event[index][5:].lstrip() for index in data_indexes)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        error = firewall.jsonrpc_error(None, -32000, "AgenticDome Blocked: unreviewable MCP SSE data")
        return ["event: message", "data: " + json.dumps(error, separators=(",", ":"))]
    if not isinstance(payload, dict):
        error = firewall.jsonrpc_error(None, -32000, "AgenticDome Blocked: invalid MCP SSE JSON-RPC payload")
        return ["event: message", "data: " + json.dumps(error, separators=(",", ":"))]
    effective_request = request
    if not str(request.get("method") or ""):
        result = payload.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            effective_request = {"method": "tools/list"}
        elif isinstance(result, dict) and isinstance(result.get("resources"), list):
            effective_request = {"method": "resources/list"}
        elif isinstance(result, dict) and isinstance(result.get("prompts"), list):
            effective_request = {"method": "prompts/list"}
        elif "result" in payload:
            reviewed_result = await firewall.sanitize_mcp_result(
                tool_output=result,
                context=context,
                request_purpose="mcp_streaming_output_sanitization",
            )
            payload = dict(payload)
            payload["result"] = reviewed_result
    reviewed = await firewall.review_forwarded_response(
        mcp_request=effective_request,
        response=payload,
        context=context,
    )
    retained = [line for index, line in enumerate(event) if index not in data_indexes]
    retained.append("data: " + json.dumps(reviewed, separators=(",", ":")))
    return retained


def _upstream_headers(inbound: Any, config: MCPHTTPGatewayConfig) -> Dict[str, str]:
    headers = {
        "Accept": str(inbound.get("Accept") or "application/json, text/event-stream"),
        "Content-Type": "application/json",
    }
    for name in ("MCP-Protocol-Version", "MCP-Session-Id"):
        value = str(inbound.get(name) or "").strip()
        if value:
            headers[name] = value
    if config.upstream_authorization:
        headers["Authorization"] = config.upstream_authorization
    return headers


def build_handler(config: MCPHTTPGatewayConfig, firewall: AgenticDomeMCPHostFirewall):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgenticDomeMCPGateway/1"

        def _json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/mcp":
                self._json(404, {"error": "Not found"})
                return
            response_started = False
            try:
                context = _context(self.headers, config)
                upstream = requests.get(
                    config.upstream_url,
                    headers=_upstream_headers(self.headers, config),
                    stream=True,
                    allow_redirects=False,
                    timeout=(config.connect_timeout_seconds, config.read_timeout_seconds),
                )
                if 300 <= upstream.status_code < 400:
                    raise MCPGatewayConfigurationError("Upstream redirects are refused; configure the exact MCP endpoint")
                if "text/event-stream" not in str(upstream.headers.get("Content-Type") or "").lower():
                    raise MCPGatewayConfigurationError("MCP GET must return a Streamable HTTP event stream")
                self.send_response(upstream.status_code)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                if upstream.headers.get("MCP-Session-Id"):
                    self.send_header("MCP-Session-Id", upstream.headers["MCP-Session-Id"])
                self.end_headers()
                response_started = True
                for event in _sse_events(upstream.iter_lines(decode_unicode=True)):
                    reviewed = asyncio.run(_review_sse_event(firewall, {}, event, context))
                    self.wfile.write(("\n".join(reviewed) + "\n\n").encode("utf-8"))
                    self.wfile.flush()
            except Exception as exc:
                if response_started:
                    self.close_connection = True
                else:
                    self._json(502, firewall.jsonrpc_error(None, -32000, f"AgenticDome Blocked: {exc}"))

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/mcp":
                self._json(404, {"error": "Not found"})
                return
            response_started = False
            try:
                content_length = int(self.headers.get("Content-Length") or "0")
                if content_length <= 0 or content_length > config.max_request_bytes:
                    raise MCPGatewayConfigurationError("MCP request size is missing or outside the configured limit")
                request = json.loads(self.rfile.read(content_length).decode("utf-8"))
                if not isinstance(request, dict):
                    raise MCPGatewayConfigurationError("MCP request must be one JSON-RPC object")
                context = _context(self.headers, config)
                gated = asyncio.run(firewall.preflight_request(mcp_request=request, context=context))
                if "error" in gated:
                    self._json(403, gated)
                    return
                upstream = requests.post(
                    config.upstream_url,
                    headers=_upstream_headers(self.headers, config),
                    json=gated,
                    stream=True,
                    allow_redirects=False,
                    timeout=(config.connect_timeout_seconds, config.read_timeout_seconds),
                )
                if 300 <= upstream.status_code < 400:
                    raise MCPGatewayConfigurationError("Upstream redirects are refused; configure the exact MCP endpoint")
                content_type = str(upstream.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in content_type:
                    self.send_response(upstream.status_code)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-store")
                    if upstream.headers.get("MCP-Session-Id"):
                        self.send_header("MCP-Session-Id", upstream.headers["MCP-Session-Id"])
                    self.end_headers()
                    response_started = True
                    for event in _sse_events(upstream.iter_lines(decode_unicode=True)):
                        reviewed = asyncio.run(_review_sse_event(firewall, gated, event, context))
                        self.wfile.write(("\n".join(reviewed) + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                    return
                if upstream.status_code in {202, 204} or not upstream.content:
                    self._empty(upstream.status_code)
                    return
                payload = upstream.json()
                if not isinstance(payload, dict):
                    raise MCPGatewayConfigurationError("Upstream returned a non-object JSON-RPC response")
                reviewed = asyncio.run(
                    firewall.review_forwarded_response(mcp_request=gated, response=payload, context=context)
                )
                self._json(upstream.status_code, reviewed)
            except Exception as exc:
                if response_started:
                    self.close_connection = True
                else:
                    self._json(502, firewall.jsonrpc_error(None, -32000, f"AgenticDome Blocked: {exc}"))

        def log_message(self, _format: str, *_args: Any) -> None:
            return None

    return Handler


def main() -> None:
    config = MCPHTTPGatewayConfig.from_env()
    firewall = AgenticDomeMCPHostFirewall()
    server = ThreadingHTTPServer((config.bind_host, config.bind_port), build_handler(config, firewall))
    server.serve_forever()


if __name__ == "__main__":
    main()


__all__ = [
    "MCPGatewayConfigurationError",
    "MCPHTTPGatewayConfig",
    "build_handler",
]
