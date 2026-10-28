import pytest
from agenticdome_sdk.client import AgenticDomeClient


@pytest.fixture
def client():
    return AgenticDomeClient(api_base='https://runtime.example.test',api_key='runtime-key',tenant_id='tenant-a',max_retries=0)


def test_legacy_sdk_headers_remain_unchanged(client,monkeypatch):
    for key in list(__import__('os').environ):
        if key.startswith('AGENTICDOME_') and any(part in key for part in ('CREDENTIAL','DEPLOYMENT','TOKEN','TASK_ID','AGENT_FRAMEWORK','AGENT_ID')):monkeypatch.delenv(key,raising=False)
    headers=client._headers()
    assert headers['X-API-Key']=='runtime-key'
    assert not any(k.startswith('X-AgenticDome-') for k in headers)


def test_sdk_reads_renewed_workload_proof_without_changing_hooks(client,monkeypatch,tmp_path):
    proof=tmp_path/'workload-token';proof.write_text('first-proof\n')
    monkeypatch.setenv('AGENTICDOME_IDENTITY_DEPLOYMENT','approved-deployment')
    monkeypatch.setenv('AGENTICDOME_WORKLOAD_TOKEN_FILE',str(proof))
    assert client._headers()['X-AgenticDome-Workload-Token']=='first-proof'
    proof.write_text('renewed-proof\n')
    assert client._headers()['X-AgenticDome-Workload-Token']=='renewed-proof'
    monkeypatch.setenv('AGENTICDOME_WORKLOAD_TOKEN','ambiguous-proof')
    with pytest.raises(ValueError,match='one identity'):client._headers()


def test_sdk_managed_token_overrides_connection_proof_without_forwarding_both(client,monkeypatch):
    monkeypatch.setenv('AGENTICDOME_AGENT_CREDENTIAL','deployment-secret')
    monkeypatch.setenv('AGENTICDOME_AGENT_TOKEN','short-lived-token')
    headers=client._headers()
    assert headers['X-AgenticDome-Agent-Token']=='short-lived-token'
    assert 'X-AgenticDome-Agent-Credential' not in headers


def test_identity_helper_methods_use_scoped_sidecar_endpoints(client,monkeypatch):
    calls=[]
    monkeypatch.setattr(client,'_request',lambda method,path,**kw:calls.append((method,path,kw)) or {'ok':True})
    client.enrol_identity('research-agent','crewai')
    client.delegate_identity('receiving-agent','case-42')
    client.exchange_identity('enrolled-token','approved-receiver','case-42','cases:read')
    assert [c[1] for c in calls]==['/identity/v1/enrol','/identity/v1/delegate','/identity/v1/token']
    assert calls[0][2]['json_body']=={'agent_id':'research-agent','framework':'crewai'}
    assert calls[2][2]['json_body']['subject_token_type']=='urn:ietf:params:oauth:token-type:access_token'


def test_existing_hooks_enrol_once_then_reuse_short_lived_identity(client,monkeypatch):
    import json
    from types import SimpleNamespace
    monkeypatch.setenv('AGENTICDOME_IDENTITY_DEPLOYMENT','approved-deployment');monkeypatch.setenv('AGENTICDOME_AGENT_CREDENTIAL','deployment-secret')
    calls=[]
    def send(**kwargs):
        calls.append(kwargs);payload={'access_token':'verified-agent-token','expires_in':900} if kwargs['url'].endswith('/identity/v1/enrol') else {'verdict':'ALLOWED'}
        return SimpleNamespace(ok=True,status_code=200,text=json.dumps(payload),json=lambda:payload)
    monkeypatch.setattr(client.session,'request',send)
    payload={'agent_id':'research-specialist','policy_context':{'platform':'crewai'}}
    client._request('POST','/tools/guardrail/validate',json_body=payload);client._request('POST','/tools/guardrail/validate',json_body=payload)
    assert len(calls)==3
    assert calls[0]['json']=={'agent_id':'research-specialist','framework':'crewai'}
    for call in calls[1:]:
        assert call['headers']['X-AgenticDome-Agent-Token']=='verified-agent-token'
        assert 'X-AgenticDome-Agent-Credential' not in call['headers']


def test_old_runtime_is_rejected_before_a_protected_action(client,monkeypatch):
    from types import SimpleNamespace
    from agenticdome_sdk.client import AgenticDomeHTTPError
    monkeypatch.setenv('AGENTICDOME_IDENTITY_DEPLOYMENT','approved-deployment');monkeypatch.setenv('AGENTICDOME_AGENT_CREDENTIAL','deployment-secret')
    calls=[]
    monkeypatch.setattr(client.session,'request',lambda **kw:calls.append(kw) or SimpleNamespace(ok=False,status_code=404,text='not found'))
    with pytest.raises(AgenticDomeHTTPError):client._request('POST','/tools/guardrail/validate',json_body={'agent_id':'research'})
    assert len(calls)==1 and calls[0]['url'].endswith('/identity/v1/enrol')


def test_concurrent_delegated_tasks_keep_their_own_identity_and_clear_on_exit(client,monkeypatch):
    import asyncio
    for key in ('AGENTICDOME_USER_TOKEN','AGENTICDOME_DELEGATION_TOKEN','AGENTICDOME_TASK_ID'):monkeypatch.delenv(key,raising=False)
    async def task(token,task_id):
        with client.identity_context(delegation_token=token,task_id=task_id):
            await asyncio.sleep(0)
            return client._headers()
    async def run():
        first,second=await asyncio.gather(task('first-delegation','case-1'),task('second-delegation','case-2'))
        assert first['X-AgenticDome-Delegation-Token']=='first-delegation' and first['X-AgenticDome-Task-Id']=='case-1'
        assert second['X-AgenticDome-Delegation-Token']=='second-delegation' and second['X-AgenticDome-Task-Id']=='case-2'
    asyncio.run(run())
    assert 'X-AgenticDome-Delegation-Token' not in client._headers()
