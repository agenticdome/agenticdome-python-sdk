"""Prepare once and send the policy-reviewed HTTP bytes without redirects."""
import base64
import json
from urllib.parse import urlsplit, urlunsplit

import requests

BOUND_HEADERS = ("content-type", "if-match", "if-none-match", "if-unmodified-since")


def prepare(method, url, body=b"", headers=None):
    method = method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("Unsupported exact HTTP method")
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not isinstance(body, bytes) or len(body) > 131072:
        raise ValueError("Supply at most 128 KiB of UTF-8 HTTP body bytes")
    if method in {"GET", "HEAD"} and body:
        raise ValueError("GET/HEAD bodies are not supported")
    body.decode("utf-8")
    headers = dict(headers or {})
    if any(str(k).lower() in {"host", "content-length", "transfer-encoding", "content-encoding"} or str(k).lower().startswith("x-agenticdome-") for k in headers):
        raise ValueError("HTTP transport and AgenticDome headers are managed by the SDK")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Use an absolute HTTP(S) URL without credentials or fragment")
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    if parsed.port and parsed.port != (443 if parsed.scheme == "https" else 80):
        host += ":" + str(parsed.port)
    url = urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))
    prepared = requests.Request(method, url, data=body, headers=headers).prepare()
    bound = {k.lower(): v for k, v in prepared.headers.items() if k.lower() in BOUND_HEADERS}
    content = None
    if body:
        content = json.loads(body) if "json" in bound.get("content-type", "").lower() else body.decode("utf-8")
    arguments = {"method": method, "url": prepared.url, "body": content, "headers": bound}
    descriptor = {"body_base64": base64.b64encode(body).decode("ascii"), "headers": bound}
    return prepared, arguments, descriptor


def send(prepared, authorization, client, *, workload_id=None, timeout=30, tool_name=None, arguments=None, require_graphql=None):
    from .client import AgenticDomeError
    broker = authorization.get("broker") or {}
    evidence = authorization.get("enforcement_evidence") or {}
    if authorization.get("verdict") != "ALLOWED" or not broker.get("verified") or not broker.get("token_consumed") or evidence.get("http_request_bound") is not True:
        raise AgenticDomeError("Exact HTTP execution requires a compatible enforcing broker receipt")
    if require_graphql and evidence.get("graphql_interpretation") != require_graphql:
        raise AgenticDomeError("GraphQL execution requires a compatible interpreting sidecar")
    if client.ownership_guard is not None:
        if not client.tenant_id:
            raise AgenticDomeError("Configure the enforcement tenant when using resource ownership adapters")
        client.ownership_guard.check_http(tool_name, arguments, evidence, expected_tenant=client.tenant_id)
    prepared.headers.update(client.enforcement_headers(authorization, workload_id=workload_id))
    # A fresh session has no agent-supplied hooks, cookies or automatic retries.
    with requests.Session() as session:
        settings = session.merge_environment_settings(prepared.url, {}, False, True, None)
        response = session.send(prepared, timeout=timeout, allow_redirects=False, **settings)
    if 300 <= response.status_code < 400:
        response.close()
        raise AgenticDomeError("Redirect refused; authorize its destination as a new action")
    return response
