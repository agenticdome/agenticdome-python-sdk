from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from agenticdome_sdk.attestation import build_hook_heartbeat, build_hook_manifest, ensure_attestation_key, manifest_sha256
from agenticdome_sdk.onboarding_cli import build_parser
from agenticdome_sdk.outcomes import sdk_outcome


def test_connect_command_is_first_class_and_source_upload_is_opt_in():
    args = build_parser().parse_args(["connect", "--yes", "--environment", "staging"])
    assert args.command == "connect"
    assert args.portal == "https://www.agenticdome.io"
    assert args.yes is True
    assert args.environment == "staging"


def test_manifest_and_heartbeat_are_signed_and_bound(tmp_path):
    private_pem, public_pem = ensure_attestation_key(tmp_path)
    manifest = build_hook_manifest(
        tenant_id="tenant-1", workload_uuid="2b8c7d58-fdb4-49e8-bf95-b5cc2be91726",
        deployment_id="deploy-1", expected_hooks=["tool.refund", "tool.lookup"],
        observed_hooks=["tool.lookup"], private_key_pem=private_pem, sdk_version="1.2.29",
        high_impact_actions=["tool.refund"],
    )
    claims = {key: value for key, value in manifest.items() if key != "signature"}
    public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    public_key.verify(
        base64.b64decode(manifest["signature"]),
        json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        padding.PKCS1v15(), hashes.SHA256(),
    )
    heartbeat = build_hook_heartbeat(
        tenant_id="tenant-1", workload_uuid=claims["workload_uuid"], deployment_id="deploy-1",
        manifest_sha256=manifest_sha256(manifest), active_hooks=["tool.lookup"], sequence=1,
        private_key_pem=private_pem,
    )
    assert heartbeat["manifest_sha256"] == manifest_sha256(manifest)
    assert (tmp_path / "attestation-private.pem").stat().st_mode & 0o777 == 0o600


def test_sdk_outcome_never_claims_gateway_or_destination_assurance():
    receipt = sdk_outcome(
        tenant_id="tenant-1", chain_id="chain-1", action_id="action-1", outcome_class="succeeded",
        destination="https://payments.example.test/charge", side_effect_reference="transaction-123",
    )
    assert receipt["assurance_level"] == "sdk_reported"
    assert len(receipt["destination_sha256"]) == 64
    assert "transaction-123" not in json.dumps(receipt)
