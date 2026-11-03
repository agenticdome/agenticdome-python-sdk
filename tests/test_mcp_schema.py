import copy
import time

import pytest

from agenticdome_sdk.mcp_schema import McpSchemaCache, McpSchemaError, McpSchemaUnavailable

TOOL={"name":"refund","inputSchema":{"type":"object","properties":{"customer":{"type":"string"},"amount":{"type":"number","minimum":0}},"required":["customer","amount"],"additionalProperties":False}}


@pytest.mark.parametrize("arguments",[{"customer":"42"},{"customer":"42","amount":-1},{"customer":"42","amount":"5"},{"customer":"42","amount":5,"extra":True}])
def test_rejects_invalid_tool_inputs(arguments):
    cache=McpSchemaCache();cache.install("tenant/server/caller",[TOOL])
    with pytest.raises(McpSchemaError):cache.validate("tenant/server/caller","refund",arguments)


def test_schema_scope_leases_and_approved_pins():
    cache=McpSchemaCache();tool=copy.deepcopy(TOOL);cache.install("tenant/server/caller",[tool])
    expected=cache.validate("tenant/server/caller","refund",{"customer":"42","amount":5})
    with pytest.raises(McpSchemaUnavailable):cache.validate("other/server/caller","refund",{})
    tool["inputSchema"]["properties"]["amount"]["maximum"]=10;cache.install("tenant/server/caller",[tool])
    with pytest.raises(McpSchemaError):cache.validate("tenant/server/caller","refund",{"customer":"42","amount":5},expected_digest=expected)
    expired=McpSchemaCache(ttl=-1);expired.install("scope",[TOOL])
    with pytest.raises(McpSchemaUnavailable):expired.validate("scope","refund",{})


def test_warm_validation_never_recompiles_or_fetches(monkeypatch):
    from agenticdome_sdk import mcp_schema
    cache=McpSchemaCache();cache.install("scope",[TOOL])
    monkeypatch.setattr(mcp_schema,"_compile",lambda schema:pytest.fail("Warm validation recompiled the schema"))
    for _ in range(100):cache.validate("scope","refund",{"customer":"42","amount":5})


@pytest.mark.parametrize("schema",[{"type":"object","$ref":"https://untrusted.invalid/schema"},
    {"type":"object","$ref":"#/$defs/a","$defs":{"a":{"$ref":"#/$defs/a"}}},
    {"type":"object","$dynamicRef":"#node"},
    {"type":"object","properties":{"value":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","pattern":"(a|aa)+$"}}}])
def test_no_external_resolution_or_reference_cycles(schema):
    with pytest.raises(McpSchemaError):McpSchemaCache().install("scope",[{"name":"tool","inputSchema":schema}])


def test_cache_size_and_removed_tools_remain_bounded():
    cache=McpSchemaCache(max_entries=2)
    for scope in ("a","b","c"):cache.install(scope,[TOOL])
    assert len(cache.entries)==2
    assert not cache.available("a","refund")
    cache.retain_names("c",set());assert not cache.available("c","refund")


def test_expensive_schema_patterns_have_a_deadline():
    cache=McpSchemaCache();cache.install("scope",[{"name":"tool","inputSchema":{"type":"object","properties":{"value":{"type":"string","pattern":"(a|aa)+$"}}}}])
    started=time.monotonic()
    with pytest.raises(McpSchemaError):cache.validate("scope","tool",{"value":"a"*2000+"!"})
    assert time.monotonic()-started<0.5
