import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from agenticdome_sdk import AgenticDomeClient, AgenticDomeError, ApprovalRequired


def test_denied_and_paused_mutations_never_reach_real_local_api():
    observed = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append((self.path, self.rfile.read(int(self.headers.get('Content-Length', '0'))), self.headers.get('If-Match')))
            self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    client = AgenticDomeClient(api_base='https://sidecar.invalid', api_key='fixture', tenant_id='test')
    state = {'mode': 'deny', 'consumed': False}
    rid = '8d50b9df-d260-4f45-9773-85daceb0edb2'
    def decision(method, route, **kw):
        if route.endswith('/grant'): return {'approval_grant': 'fixture'}
        payload = kw['json_body']
        assert payload['tool_args']['body'] == {'id': 'one'}
        assert base64.b64decode(payload['execution_request']['body_base64']) == b'{"id":"one"}'
        if state['mode'] == 'deny' or state['consumed']:
            return {'verdict': 'BLOCKED', 'broker': {'verified': False}}
        if not payload['policy_context'].get('approval_grant'):
            return {'verdict': 'APPROVAL_REQUIRED', 'context': {'approval': {'id': rid}}}
        state['consumed'] = True
        return {'verdict': 'ALLOWED', 'execution_receipt': 'exact-fixture', 'enforcement_evidence': {'http_request_bound': True},
                'broker': {'verified': True, 'token_consumed': True, 'approval_request_id': rid}}
    client._request = decision
    kwargs = dict(method='POST', url=f'http://127.0.0.1:{server.server_port}/cancel', body=b'{"id":"one"}',
                  headers={'Content-Type': 'application/json', 'If-Match': 'v1'}, agent_id='agent', tool_name='bookings.cancel')
    try:
        with pytest.raises(AgenticDomeError): client.execute_http(**kwargs)
        assert observed == []
        state['mode'] = 'approval'
        with pytest.raises(ApprovalRequired) as error: client.execute_http(**kwargs)
        assert observed == []
        assert client.resume_approved_http(error.value).status_code == 200
        assert observed == [('/cancel', b'{"id":"one"}', 'v1')]
        with pytest.raises(AgenticDomeError): client.resume_approved_http(error.value)
        assert len(observed) == 1
    finally:
        client.close(); server.shutdown(); server.server_close(); worker.join(timeout=2)
