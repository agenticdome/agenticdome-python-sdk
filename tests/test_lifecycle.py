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


def test_runtime_reporting_is_default_without_portal_credentials(monkeypatch):
    monkeypatch.delenv("AGENTICDOME_EVIDENCE_API_BASE", raising=False)
    monkeypatch.delenv("AGENTICDOME_EVIDENCE_TOKEN", raising=False)
    monkeypatch.delenv("AGENTICDOME_EVIDENCE_ENABLED", raising=False)
    records = []
    reporter = VerifiedActionReporter.from_env(tenant_id="2", api_base="https://runtime.example", api_key="tenant-key", sender=lambda kind, payload: records.append((kind, payload)))
    assert reporter.enabled
    context = reporter.new_context(operation_type="tool_call", arguments={"secret": "RAW_ARGUMENT"})
    reporter.phase(context, "requested", "requested")
    reporter.phase(context, "authorised", "blocked")
    reporter.outcome(context, "not_attempted")
    assert reporter.flush()
    assert [kind for kind, _ in records] == ["events", "events", "outcomes"]
    assert records[-1][1]["outcome_class"] == "not_attempted"
    assert "attempted_at" not in records[-1][1]
    assert "RAW_ARGUMENT" not in json.dumps(records)
    assert reporter.stats()["delivered"] == 3


def test_retries_preserve_record_id_and_failed_delivery_is_visible(monkeypatch):
    attempts = []
    def unavailable(kind, payload):
        attempts.append(payload["event_id"])
        raise ConnectionError("unavailable")
    reporter = VerifiedActionReporter.from_env(tenant_id="2", api_base="https://runtime.example", api_key="key", sender=unavailable)
    reporter.phase(reporter.new_context(operation_type="tool_call"), "requested", "requested")
    assert not reporter.flush()
    assert len(attempts) == 3 and len(set(attempts)) == 1
    assert reporter.stats()["failed"] == 1


def test_explicit_opt_out_disables_default_reporting(monkeypatch):
    monkeypatch.setenv("AGENTICDOME_EVIDENCE_ENABLED", "false")
    assert not VerifiedActionReporter.from_env(tenant_id="2", api_base="https://runtime.example", api_key="key").enabled

