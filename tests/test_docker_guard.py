import hashlib
import json
from types import SimpleNamespace

import pytest

from agenticdome_sdk import AgenticDomeClient
from agenticdome_sdk.docker_guard import check_tool,event_payload

EVENT={"hook_event_name":"tool_guard","agent_name":"root","tool_name":"shell","tool_input":{"cmd":"git status"},"session_id":"s1","tool_use_id":"t1","cwd":"/work","tool_category":"shell"}


@pytest.mark.parametrize("decision",["allow","deny"])
def test_bridge_uses_the_published_sdk_and_exact_request_binding(decision):
    client=AgenticDomeClient(api_base="https://fixture.invalid",api_key="fixture",tenant_id="2")
    calls=[]
    def request(method,path,**kwargs):
        calls.append((method,path,kwargs));raw=json.dumps(kwargs["json_body"],sort_keys=True,separators=(",",":"),ensure_ascii=False)
        return {"schema":"agenticdome.native-tool-decision.v1","request_sha256":hashlib.sha256(raw.encode()).hexdigest(),"decision_id":"decision-fixture","decision":decision}
    client._request=request
    try:
        response=check_tool(EVENT,client)
        assert response["hook_specific_output"]["permission_decision"]==decision
        assert calls[0][1]=="/gateway/v1/guard" and calls[0][2]["allow_redirects"] is False
    finally:client.close()


@pytest.mark.parametrize("response",[{}, {"schema":"wrong"}, {"schema":"agenticdome.native-tool-decision.v1","decision":"allow","request_sha256":"wrong","decision_id":"d"}])
def test_unbound_or_missing_decisions_never_allow(response):
    with pytest.raises(ValueError):check_tool(EVENT,SimpleNamespace(guard_native_tool=lambda event:response))


def test_arguments_are_not_modified_and_event_cannot_claim_verified_roles():
    event={**EVENT,"user_id":"admin","roles":["admin"],"verified":True}
    payload=event_payload(event)
    assert payload["tool_input"]==EVENT["tool_input"]
    assert "user_id" not in payload and "roles" not in payload and "verified" not in payload
    payload['tool_input']['cmd']='changed'
    assert event['tool_input']['cmd']=='git status'


def test_short_lived_guard_uses_gateway_direct_proof_without_an_extra_token_exchange(monkeypatch):
    monkeypatch.setenv('AGENTICDOME_IDENTITY_DEPLOYMENT','deployment-fixture')
    monkeypatch.setenv('AGENTICDOME_AGENT_CREDENTIAL','fixture-credential')
    client=AgenticDomeClient(api_base='https://fixture.invalid',api_key='fixture',tenant_id='2')
    monkeypatch.setattr(client,'_managed_headers',lambda *args:pytest.fail('Native guard attempted a second authentication request'))
    sent=[]
    def request(**kwargs):
        sent.append(kwargs)
        return SimpleNamespace(ok=True,status_code=200,text='{}',json=lambda:{})
    monkeypatch.setattr(client.session,'request',request)
    try:
        client.guard_native_tool(EVENT)
        assert len(sent)==1
        assert sent[0]['headers']['X-AgenticDome-Agent-Credential']=='fixture-credential'
    finally:client.close()
