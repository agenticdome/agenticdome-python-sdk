import json

from agenticdome_sdk.lifecycle import VerifiedActionReporter, verified_action


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return b"{}"


def test_reporter_preserves_order_and_never_sends_raw_arguments(monkeypatch):
    delivered = []

    def urlopen(request, timeout):
        delivered.append((request.full_url, json.loads(request.data.decode("utf-8")), timeout))
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    reporter = VerifiedActionReporter("https://portal.example", "scoped-token", tenant_id="2")
    context = reporter.new_context(
        operation_type="tool_call", tool_name="crm.lookup",
        arguments={"password": "must-not-leave-process"}, destination="crm.internal",
        initiator_type="human", executor_type="tool", target_type="tool",
    )
    reporter.phase(context, "requested", "requested")
    reporter.phase(context, "attempted", "attempted")
    reporter.outcome(context, "succeeded")
    assert reporter.flush()

    assert [item[0].rsplit("/", 1)[-1] for item in delivered] == ["events", "events", "outcomes"]
    serialized = json.dumps([item[1] for item in delivered])
    assert "must-not-leave-process" not in serialized
    assert delivered[0][1]["details"]["initiator_type"] == "human"
    assert delivered[2][1]["tenant_id"] == "2"


def test_disabled_decorator_preserves_sync_result():
    reporter = VerifiedActionReporter()

    @verified_action(reporter=reporter, operation_type="function_call", executor_type="function", target_type="service")
    def add(left, right):
        return left + right

    assert add(2, 3) == 5

