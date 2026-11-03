"""Bounded MCP input validation. No network access or framework imports.

Mirrored in app/security/mcp_schema_core.py for independent sidecar packaging.
The integration suite verifies byte-for-byte parity. Update both copies together.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import time
import threading
from collections import OrderedDict


class McpSchemaError(ValueError):
    pass


class McpSchemaUnavailable(McpSchemaError):
    pass


_budget = contextvars.ContextVar("mcp_schema_budget", default=None)


def _bounded(value, *, nodes=4096, depth=32):
    remaining = nodes
    def visit(item, level):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or level > depth:
            raise McpSchemaError("MCP schema or arguments exceed validation complexity limits")
        if isinstance(item, dict):
            for child in item.values(): visit(child, level + 1)
        elif isinstance(item, list):
            for child in item: visit(child, level + 1)
    visit(value, 0)


def _safe_schema(schema):
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise McpSchemaError("MCP inputSchema must describe an object")
    _bounded(schema, nodes=1024, depth=20)
    raw = json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 32768:
        raise McpSchemaError("MCP inputSchema exceeds 32 KiB")
    visits = 4096
    def walk(node, references=()):
        nonlocal visits
        visits -= 1
        if visits < 0: raise McpSchemaError("Schema reference expansion exceeds limit")
        if isinstance(node, dict):
            # jsonschema.evolve otherwise switches nested dialect declarations
            # back to an unbounded built-in validator, including its regex engine.
            if node is not schema and "$schema" in node:
                raise McpSchemaError("Nested schema dialect changes are unsupported")
            if any(key in node for key in ("$dynamicRef", "$recursiveRef")):
                raise McpSchemaError("Dynamic schema references are unsupported")
            if "$id" in node:
                raise McpSchemaError("Schema resource identifiers require a reviewed adapter")
            ref = node.get("$ref")
            if ref is not None:
                if not isinstance(ref, str) or not ref.startswith("#/") or ref in references:
                    raise McpSchemaError("Only acyclic local JSON-pointer schema references are supported")
                target = schema
                try:
                    for part in ref[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                except (KeyError, TypeError):
                    raise McpSchemaError("Unresolved local schema reference") from None
                if len(references) >= 8: raise McpSchemaError("Schema reference depth exceeded")
                walk(target, (*references, ref))
            for key, child in node.items():
                if key in {"oneOf", "anyOf", "allOf"} and isinstance(child, list) and len(child) > 16:
                    raise McpSchemaError("Schema alternatives exceed limit")
                if key == "pattern" and (not isinstance(child, str) or len(child) > 1024):
                    raise McpSchemaError("Schema pattern exceeds limit")
                walk(child, references)
        elif isinstance(node, list):
            for child in node: walk(child, references)
    walk(schema)
    return raw


def _compile(schema):
    from jsonschema import Draft7Validator, Draft201909Validator, Draft202012Validator, ValidationError, validators
    import regex
    uri = schema.get("$schema", "https://json-schema.org/draft/2020-12/schema").rstrip("#")
    base = {"https://json-schema.org/draft/2020-12/schema": Draft202012Validator,
            "https://json-schema.org/draft/2019-09/schema": Draft201909Validator,
            "https://json-schema.org/draft-07/schema": Draft7Validator,
            "http://json-schema.org/draft-07/schema": Draft7Validator}.get(uri)
    if base is None: raise McpSchemaError("Unsupported MCP JSON Schema dialect")
    def tick():
        budget = _budget.get()
        if budget is not None:
            budget[0] -= 1
            if budget[0] < 0 or time.perf_counter() > budget[1]:
                raise McpSchemaError("MCP schema validation budget exceeded")
    def unique_key(item):
        tick()
        if isinstance(item, bool): return ("bool", item)
        if isinstance(item, int): return ("number", item, 1)
        if isinstance(item, float): return ("number", *item.as_integer_ratio())
        if isinstance(item, dict): return ("object", tuple((k, unique_key(v)) for k, v in sorted(item.items())))
        if isinstance(item, list): return ("array", tuple(unique_key(v) for v in item))
        return ("scalar", item)
    def bounded(keyword, validator):
        def check(instance_validator, value, instance, schema_node):
            tick()
            if keyword == "pattern" and isinstance(instance, str):
                try:
                    if not regex.search(value, instance, timeout=0.005):
                        yield ValidationError("String does not match the required pattern")
                except (TimeoutError, regex.error):
                    raise McpSchemaError("MCP schema pattern is invalid or exceeds budget") from None
            elif keyword == "patternProperties" and isinstance(instance, dict):
                for pattern, subschema in value.items():
                    if len(pattern) > 1024: raise McpSchemaError("Schema pattern exceeds limit")
                    for name, item in instance.items():
                        tick()
                        try: matched = regex.search(pattern, name, timeout=0.005)
                        except (TimeoutError, regex.error): raise McpSchemaError("MCP schema pattern exceeds budget") from None
                        if matched: yield from instance_validator.descend(item, subschema, path=name, schema_path=pattern)
            elif keyword == "additionalProperties" and isinstance(instance, dict):
                properties = schema_node.get("properties", {})
                patterns = schema_node.get("patternProperties", {})
                for name, item in instance.items():
                    tick()
                    if name in properties: continue
                    try: matched = any(regex.search(p, name, timeout=0.005) for p in patterns)
                    except (TimeoutError, regex.error): raise McpSchemaError("MCP schema pattern exceeds budget") from None
                    if matched: continue
                    if value is False: yield ValidationError("Unexpected argument property")
                    elif isinstance(value, dict): yield from instance_validator.descend(item, value, path=name)
            elif keyword == "uniqueItems" and value and isinstance(instance, list):
                seen = set()
                for item in instance:
                    key = unique_key(item)
                    if key in seen:
                        yield ValidationError("Array items must be unique")
                        break
                    seen.add(key)
            else:
                yield from validator(instance_validator, value, instance, schema_node)
        return check
    # Reject oversized property patterns before compiling the meta-schema.
    def check_patterns(node):
        if isinstance(node, dict):
            if any(len(p) > 1024 for p in node.get("patternProperties", {})):
                raise McpSchemaError("Schema pattern exceeds limit")
            for child in node.values(): check_patterns(child)
        elif isinstance(node, list):
            for child in node: check_patterns(child)
    check_patterns(schema)
    try: base.check_schema(schema)
    except Exception: raise McpSchemaError("Invalid MCP inputSchema") from None
    cls = validators.extend(base, {key: bounded(key, value) for key, value in base.VALIDATORS.items()})
    return cls(schema)


class McpSchemaCache:
    """LRU cache partitioned by authenticated server/caller scope, with a lease."""
    def __init__(self, *, ttl=300, max_entries=1024, max_bytes=4194304):
        self.ttl, self.max_entries, self.max_bytes = ttl, max_entries, max_bytes
        self.entries = OrderedDict()
        self.bytes = 0
        self.lock = threading.RLock()

    def install(self, scope, tools, *, replace_scope=False):
        if not isinstance(tools, list) or len(tools) > 256:
            raise McpSchemaError("MCP tool catalogue exceeds limit")
        prepared = []
        seen = set()
        for tool in tools:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not 0 < len(tool["name"]) <= 2048:
                raise McpSchemaError("Invalid MCP tool definition")
            name = tool["name"]
            if name in seen: raise McpSchemaError("Duplicate MCP tool definition")
            seen.add(name)
            schema = tool.get("inputSchema")
            raw = _safe_schema(schema)
            # Own an immutable snapshot, independent of response redaction/hooks.
            schema = json.loads(raw)
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            with self.lock: existing = self.entries.get((scope, name))
            prepared.append((name, raw, existing[2] if existing and existing[1] == digest else _compile(schema)))
        changes = []
        with self.lock:
            if replace_scope:
                for key in list(self.entries):
                    if key[0] == scope and key[1] not in seen:
                        self.bytes -= self.entries.pop(key)[3]
            for name, raw, validator in prepared:
                key = (scope, name)
                digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                old = self.entries.pop(key, None)
                if old:
                    self.bytes -= old[3]
                    if old[1] != digest: changes.append(name)
                self.entries[key] = (time.monotonic() + self.ttl, digest, validator, len(raw))
                self.bytes += len(raw)
                while len(self.entries) > self.max_entries or self.bytes > self.max_bytes:
                    _, item = self.entries.popitem(last=False)
                    self.bytes -= item[3]
        return changes

    def available(self, scope, name):
        with self.lock:
            entry = self.entries.get((scope, name))
            return bool(entry and entry[0] > time.monotonic())

    def fingerprint(self, scope, name):
        with self.lock:
            entry = self.entries.get((scope, name))
            return entry[1] if entry and entry[0] > time.monotonic() else None

    def retain_names(self, scope, names):
        with self.lock:
            for key in list(self.entries):
                if key[0] == scope and key[1] not in names:
                    self.bytes -= self.entries.pop(key)[3]

    def validate(self, scope, name, arguments, *, expected_digest=None):
        key = (scope, name)
        with self.lock:
            entry = self.entries.get(key)
            if not entry or entry[0] <= time.monotonic():
                raise McpSchemaUnavailable("MCP tool schema is unavailable or expired")
            self.entries.move_to_end(key)
        if expected_digest and entry[1] != expected_digest:
            raise McpSchemaError("MCP tool schema differs from its approved digest")
        if not isinstance(arguments, dict): raise McpSchemaError("MCP tool arguments must be an object")
        _bounded(arguments)
        if len(json.dumps(arguments, allow_nan=False).encode()) > 131072:
            raise McpSchemaError("MCP arguments exceed validation limit")
        token = _budget.set([10000, time.perf_counter() + 0.025])
        try:
            error = next(entry[2].iter_errors(arguments), None)
            if error:
                # Values and schema messages can contain secrets. Return paths only.
                raise McpSchemaError("MCP arguments do not satisfy inputSchema")
        finally: _budget.reset(token)
        return entry[1]
