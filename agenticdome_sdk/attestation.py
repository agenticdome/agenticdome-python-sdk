"""Signed runtime-coverage evidence with no customer source or proprietary analysis."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


EVIDENCE_CONTRACT_VERSION = "agenticdome.evidence.v1"


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:  # pragma: no cover - packaging/install failure
        raise RuntimeError("Runtime attestation requires the SDK's cryptography dependency.") from exc
    return hashes, serialization, padding, rsa


def canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ensure_attestation_key(directory: Path) -> tuple[str, str]:
    """Return private/public PEM, creating a local non-uploaded private key once."""
    hashes, serialization, padding, rsa = _crypto()
    del hashes, padding
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "attestation-private.pem"
    public_path = directory / "attestation-public.pem"
    if private_path.exists():
        private_pem = private_path.read_text(encoding="ascii")
        key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        private_path.write_text(private_pem, encoding="ascii")
        os.chmod(private_path, 0o600)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_path.write_text(public_pem, encoding="ascii")
    os.chmod(public_path, 0o644)
    return private_pem, public_pem


def sign_claims(claims: Dict[str, Any], private_key_pem: str) -> str:
    hashes, serialization, padding, rsa = _crypto()
    del rsa
    key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    signature = key.sign(canonical_json(claims), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def build_hook_manifest(
    *, tenant_id: str, workload_uuid: str, deployment_id: str,
    expected_hooks: Iterable[str], observed_hooks: Iterable[str],
    private_key_pem: str, sdk_version: str, framework_versions: Optional[Dict[str, str]] = None,
    high_impact_actions: Optional[Iterable[str]] = None, build_sha256: Optional[str] = None,
    sdk_checksum: Optional[str] = None, ttl_seconds: int = 600,
) -> Dict[str, Any]:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "schema": "agenticdome.hook-manifest.v1",
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "tenant_id": tenant_id,
        "workload_uuid": workload_uuid,
        "deployment_id": deployment_id,
        "manifest_id": str(uuid.uuid4()),
        "build_sha256": build_sha256,
        "sdk_checksum": sdk_checksum,
        "sdk_version": sdk_version,
        "framework_versions": framework_versions or {},
        "expected_hooks": sorted(set(str(item) for item in expected_hooks if item)),
        "observed_hooks": sorted(set(str(item) for item in observed_hooks if item)),
        "high_impact_actions": sorted(set(str(item) for item in (high_impact_actions or []) if item)),
        "started_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(now + max(60, min(ttl_seconds, 600)), timezone.utc).isoformat(),
    }
    return {**claims, "signature": sign_claims(claims, private_key_pem)}


def build_hook_heartbeat(
    *, tenant_id: str, workload_uuid: str, deployment_id: str, manifest_sha256: str,
    active_hooks: Iterable[str], sequence: int, private_key_pem: str, ttl_seconds: int = 120,
) -> Dict[str, Any]:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "schema": "agenticdome.hook-heartbeat.v1",
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "tenant_id": tenant_id,
        "workload_uuid": workload_uuid,
        "deployment_id": deployment_id,
        "manifest_sha256": manifest_sha256,
        "sequence": max(1, int(sequence)),
        "active_hooks": sorted(set(str(item) for item in active_hooks if item)),
        "observed_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(now + max(30, min(ttl_seconds, 300)), timezone.utc).isoformat(),
    }
    return {**claims, "signature": sign_claims(claims, private_key_pem)}


def manifest_sha256(manifest: Dict[str, Any]) -> str:
    claims = {key: value for key, value in manifest.items() if key != "signature"}
    return hashlib.sha256(canonical_json(claims)).hexdigest()


def _post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(url, data=canonical_json(payload), method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - explicit AgenticDome portal
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("AgenticDome returned an invalid attestation response.")
    return value


class RuntimeCoverageAttestor:
    """Background signed manifest/heartbeat reporter; never sends source or arguments."""

    def __init__(self, *, portal: str, tenant_id: str, workload_uuid: str, deployment_id: str,
                 private_key_pem: str, expected_hooks: Iterable[str], sdk_version: str,
                 high_impact_actions: Optional[Iterable[str]] = None, heartbeat_seconds: int = 60):
        self.portal = portal.rstrip("/")
        self.tenant_id = tenant_id
        self.workload_uuid = workload_uuid
        self.deployment_id = deployment_id
        self.private_key_pem = private_key_pem
        self.expected_hooks = set(str(item) for item in expected_hooks if item)
        self.observed_hooks: set[str] = set()
        self.sdk_version = sdk_version
        self.high_impact_actions = set(str(item) for item in (high_impact_actions or []) if item)
        self.heartbeat_seconds = max(15, min(int(heartbeat_seconds), 120))
        self.sequence = 0
        self.current_manifest_sha256 = ""
        self.last_error: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @classmethod
    def from_environment(cls, expected_hooks: Iterable[str], high_impact_actions: Optional[Iterable[str]] = None) -> Optional["RuntimeCoverageAttestor"]:
        names = ["AGENTICDOME_CONTROL_PLANE_URL", "AGENTICDOME_TENANT_ID", "AGENTICDOME_WORKLOAD_UUID", "AGENTICDOME_DEPLOYMENT_ID", "AGENTICDOME_ATTESTATION_KEY_PATH"]
        values = {name: os.getenv(name, "").strip() for name in names}
        if not all(values.values()):
            return None
        key = Path(values["AGENTICDOME_ATTESTATION_KEY_PATH"]).read_text(encoding="ascii")
        return cls(portal=values["AGENTICDOME_CONTROL_PLANE_URL"], tenant_id=values["AGENTICDOME_TENANT_ID"],
                   workload_uuid=values["AGENTICDOME_WORKLOAD_UUID"], deployment_id=values["AGENTICDOME_DEPLOYMENT_ID"],
                   private_key_pem=key, expected_hooks=expected_hooks, sdk_version=os.getenv("AGENTICDOME_SDK_VERSION", "unknown"),
                   high_impact_actions=high_impact_actions)

    def observe(self, hook_id: str) -> None:
        if hook_id:
            with self._lock:
                self.observed_hooks.add(str(hook_id))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="agenticdome-coverage", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(0.0, timeout))

    def _manifest(self) -> None:
        with self._lock:
            observed = sorted(self.observed_hooks)
        manifest = build_hook_manifest(tenant_id=self.tenant_id, workload_uuid=self.workload_uuid,
                                       deployment_id=self.deployment_id, expected_hooks=self.expected_hooks,
                                       observed_hooks=observed, private_key_pem=self.private_key_pem,
                                       sdk_version=self.sdk_version, high_impact_actions=self.high_impact_actions)
        _post_json(self.portal + "/api/agentguard/runtime/hook-manifest", manifest)
        self.current_manifest_sha256 = manifest_sha256(manifest)

    def _run(self) -> None:
        manifest_at = 0.0
        while not self._stop.is_set():
            try:
                if not self.current_manifest_sha256 or time.monotonic() - manifest_at >= 300:
                    self._manifest()
                    manifest_at = time.monotonic()
                self.sequence += 1
                with self._lock:
                    active = sorted(self.observed_hooks)
                heartbeat = build_hook_heartbeat(tenant_id=self.tenant_id, workload_uuid=self.workload_uuid,
                                                 deployment_id=self.deployment_id, manifest_sha256=self.current_manifest_sha256,
                                                 active_hooks=active, sequence=self.sequence, private_key_pem=self.private_key_pem)
                _post_json(self.portal + "/api/agentguard/runtime/hook-heartbeat", heartbeat)
                self.last_error = None
            except Exception as exc:  # evidence failure is surfaced via stale coverage; action fail-closed remains gateway-owned
                self.last_error = exc.__class__.__name__
            self._stop.wait(self.heartbeat_seconds)
