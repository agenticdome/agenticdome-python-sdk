"""Certify an installed immutable wheel without importing the editable checkout."""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    wheel, output = Path(args.wheel).resolve(), Path(args.output).resolve()
    root = Path(__file__).resolve().parents[1]
    if output.is_relative_to(root): parser.error('Certification output must be outside the SDK checkout')
    if not wheel.is_file() or wheel.suffix != '.whl': parser.error('Use an existing SDK wheel')
    import agenticdome_sdk
    if not shutil.which('git'): parser.error('Certification fixtures require Git on PATH')
    if Path(agenticdome_sdk.__file__).resolve().is_relative_to(root):
        parser.error('Certification requires the installed wheel, not editable SDK source')
    expected = tomllib.loads((root / 'pyproject.toml').read_text())['project']['version']
    if importlib.metadata.version('agenticdome-python-sdk') != expected:
        parser.error('The installed SDK version does not match the release source')
    installed_root = Path(agenticdome_sdk.__file__).resolve().parent.parent
    verified_files = 0
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith('agenticdome_sdk/') and not name.endswith('/'):
                if archive.read(name) != (installed_root / name).read_bytes():
                    parser.error('Installed SDK files do not match this exact wheel')
                verified_files += 1
    output.mkdir(parents=True, exist_ok=True)
    evidence_source = output / 'test-source'
    if evidence_source.exists(): parser.error('Use a fresh certification output directory')
    shutil.copytree(root, evidence_source, ignore=shutil.ignore_patterns('agenticdome_sdk', '.venv', '.git', '.harness_runtime',
        '.pytest_cache', '.ruff_cache', '__pycache__', 'build', 'dist', '*.egg-info'))
    dependency_check = subprocess.run([sys.executable, '-m', 'pip', 'check'], capture_output=True, text=True)
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '--tb=short', '-p', 'no:cacheprovider', 'tests',
        '--junitxml=' + str(output / 'results.xml')], cwd=evidence_source)
    counts = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0}
    if (output / 'results.xml').is_file():
        for suite in ET.parse(output / 'results.xml').getroot().iter('testsuite'):
            for key in counts: counts[key] += int(suite.get(key, 0))
    report = {'schema': 'agenticdome.python-sdk-certification.v1',
        'status': 'passed' if result.returncode == 0 and dependency_check.returncode == 0 and counts['tests'] else 'failed',
        'scope': 'installed_sdk_public_tests', 'sdk_version': expected,
        'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
        'verified_installed_files': verified_files,
        'python': platform.python_version(), 'implementation': platform.python_implementation(),
        'platform': platform.platform(), 'architecture': platform.machine(), 'results': counts,
        'dependency_check_passed': dependency_check.returncode == 0,
        'dependencies': sorted([{'name': d.metadata['Name'], 'version': d.version} for d in importlib.metadata.distributions()], key=lambda d: d['name'])}
    (output / 'certification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'dependencies'}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__': raise SystemExit(main())
