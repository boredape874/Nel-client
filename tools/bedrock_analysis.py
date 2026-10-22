#!/usr/bin/env python3
"""Separate, report-only Bedrock server/client binary analysis. Python 3.11+."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_API = 'https://net-secondary.web.minecraft-services.net/api/v1.0/download/links'
REGISTRY = 'https://raw.githubusercontent.com/EndstoneMC/bedrock-server-data/v2'
BDS_HOSTS = {'www.minecraft.net', 'minecraft.net', 'minecraft.azureedge.net', 'download.minecraft.net'}
HEX = re.compile(r'[0-9a-fA-F]{64}')
VERSION = re.compile(r'\d+\.\d+\.\d+(?:\.\d+|-preview\.\d+)?')
MAX_DOWNLOAD = 1536 * 1024 * 1024
MAX_BINARY = 2048 * 1024 * 1024


class Blocked(Exception):
    """An input or security prerequisite is missing; never report compatibility."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Blocked(message)


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def check_url(url: str, hosts: set[str], resolve: bool = True) -> None:
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in hosts, 'HTTPS host is not approved')
    require(not parsed.username and not parsed.password and parsed.port in (None, 443), 'Unsafe URL authority')
    if resolve:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        require(bool(addresses), 'DNS returned no addresses')
        require(all(ipaddress.ip_address(item[4][0]).is_global for item in addresses), 'Non-public destination rejected')


class RedirectGuard(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: set[str]):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url: str, hosts: set[str], authorization: str = ''):
    check_url(url, hosts)
    headers = {'User-Agent': 'Nel-client-Bedrock-Analysis/1.0', 'Accept': 'application/json, */*'}
    if authorization:
        require(hosts == {'api.github.com'}, 'Authentication restricted to GitHub API')
        headers['Authorization'] = 'Bearer ' + authorization
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RedirectGuard(hosts))
    for attempt in range(3):
        try:
            return opener.open(urllib.request.Request(url, headers=headers), timeout=60)
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise Blocked('Download/API HTTP failure; source URL withheld') from None
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise Blocked('Network request failed; source URL withheld') from None
        time.sleep(2 ** attempt)
    raise Blocked('Network retries exhausted')


def get_json(url: str, hosts: set[str], token: str = '') -> dict:
    with request(url, hosts, token) as response:
        content = response.read(4 * 1024 * 1024 + 1)
    require(len(content) <= 4 * 1024 * 1024, 'JSON response too large')
    result = json.loads(content)
    require(isinstance(result, dict), 'JSON root must be an object')
    return result


def bds_entry(version: str, platform: str, channel: str) -> dict:
    if version == 'latest':
        key = 'serverBedrock' + ('Preview' if channel == 'preview' else '') + platform.title()
        links = get_json(OFFICIAL_API, {'net-secondary.web.minecraft-services.net'})['result']['links']
        matches = [item['downloadUrl'] for item in links if item['downloadType'] == key]
        require(len(matches) == 1, 'Official BDS link not uniquely identified')
        url = matches[0]
        digest = None  # Official endpoint does not publish a checksum.
    else:
        require(bool(VERSION.fullmatch(version)), 'Invalid BDS version')
        if channel == 'preview':
            require('-preview.' in version or len(version.split('.')) == 4, 'Preview requires its full build number')
            key = version if '-preview.' in version else '.'.join(version.split('.')[:3]) + '-preview.' + version.split('.')[3]
        else:
            require('-preview.' not in version, 'Preview version used with release channel')
            key = '.'.join(version.split('.')[:3])
        metadata = get_json(f'{REGISTRY}/{channel}/{key}/metadata.json', {'raw.githubusercontent.com'})
        entry = metadata['binary'][platform]
        url, digest = entry['url'], entry['sha256']
        require(bool(HEX.fullmatch(digest)), 'Registry checksum is invalid')
    check_url(url, BDS_HOSTS)
    match = re.search(r'/bedrock-server-(\d+\.\d+\.\d+\.\d+)\.zip$', urllib.parse.urlsplit(url).path)
    require(match is not None, 'Cannot identify the full BDS build')
    full = match.group(1)
    if version != 'latest' and '-preview.' not in version and len(version.split('.')) == 4:
        require(version == full, 'Registry points to a different full build; refusing substitution')
    return {'version': full, 'platform': platform, 'channel': channel, 'url': url,
            'download_sha256': digest, 'format': 'zip',
            'member': 'bedrock_server.exe' if platform == 'windows' else 'bedrock_server',
            'checksum_source': 'endstone-registry' if digest else 'recorded-after-official-download'}


def client_entries() -> tuple[dict, dict, set[str]]:
    hosts = {host.strip().lower() for host in os.environ.get('MCBE_ALLOWED_HOSTS', '').split(',') if host.strip()}
    require(bool(hosts), 'Set MCBE_ALLOWED_HOSTS to exact trusted download/redirect hosts')
    source = os.environ.get('MCBE_INPUTS_JSON', '')
    manifest_url = os.environ.get('MCBE_MANIFEST_URL', '')
    require(bool(source) != bool(manifest_url), 'Set exactly one of MCBE_INPUTS_JSON or MCBE_MANIFEST_URL')
    data = json.loads(source) if source else get_json(manifest_url, hosts)
    require(data.get('role') == 'client' and data.get('platform') == 'windows-x64', 'Expected a Windows x64 client manifest')
    require(data.get('channel') in {'release', 'preview'}, 'Client channel must be release or preview')
    for side in ('old', 'new'):
        item = data[side]
        require(bool(VERSION.fullmatch(item['version'])), 'Invalid client build identifier')
        require(bool(HEX.fullmatch(item['download_sha256'])), 'Client download SHA256 is required')
        require(item['format'] in {'raw', 'zip'}, 'Client input must be raw executable or ordinary ZIP')
        require(item.get('member', 'Minecraft.Windows.exe') == 'Minecraft.Windows.exe', 'Only the selected main executable is supported in M1')
        check_url(item['url'], hosts)
        item.update(platform='windows', channel=data['channel'], member='Minecraft.Windows.exe', checksum_source='owner-manifest')
    return data['old'], data['new'], hosts


def extract_member(archive: Path, member: str, output: Path) -> None:
    # Extract exactly one regular member, never extractall or an installer.
    with zipfile.ZipFile(archive) as zf:
        matches = [item for item in zf.infolist() if item.filename == member]
        require(len(matches) == 1, 'Expected executable is missing or duplicated in ZIP')
        info = matches[0]
        require(not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16), 'ZIP member is not a regular file')
        require(0 < info.file_size <= MAX_BINARY and not info.flag_bits & 1, 'Invalid, encrypted, or oversized ZIP member')
        require(info.file_size / max(1, info.compress_size) <= 500, 'Suspicious ZIP expansion ratio')
        total = 0
        with zf.open(info) as source, output.open('wb') as target:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                require(total <= MAX_BINARY, 'Expanded binary is too large')
                target.write(chunk)
        require(total == info.file_size, 'Truncated ZIP member')


def acquire(item: dict, destination: Path, hosts: set[str]) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    download = destination.with_suffix('.download')
    count = 0
    with request(item['url'], hosts) as source, download.open('wb') as target:
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            require(count <= MAX_DOWNLOAD, 'Download size limit exceeded')
            target.write(chunk)
    observed = sha256(download)
    expected = item.get('download_sha256')
    require(expected is None or observed == expected.lower(), 'Download SHA256 mismatch')
    if item['format'] == 'zip':
        extract_member(download, item['member'], destination)
        download.unlink()
    else:
        download.replace(destination)
    binary_hash = sha256(destination)
    if item.get('binary_sha256'):
        require(binary_hash == item['binary_sha256'].lower(), 'Executable SHA256 mismatch')
    return {'version': item['version'], 'platform': item['platform'], 'channel': item['channel'],
            'download_sha256': observed, 'binary_sha256': binary_hash,
            'checksum_source': item['checksum_source'], 'bytes': destination.stat().st_size}


def executable_regions(data) -> tuple[str, list[dict]]:
    def read(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), 'Malformed executable header')
        return struct.unpack_from(fmt, data, offset)
    regions = []
    if data[:2] == b'MZ':
        pe, = read('<I', 0x3c)
        require(data[pe:pe+4] == b'PE\0\0', 'Invalid PE signature')
        machine, count = read('<HH', pe + 4)
        size, = read('<H', pe + 20)
        magic, = read('<H', pe + 24)
        require(machine == 0x8664 and magic == 0x20b and 0 < count <= 96 and size >= 112, 'Expected a PE32+ x64 executable')
        base, = read('<Q', pe + 48)
        for index in range(count):
            at = pe + 24 + size + index * 40
            name, virtual_size, rva, raw_size, offset = read('<8sIIII', at)
            flags, = read('<I', at + 36)
            require(offset + raw_size <= len(data), 'PE section outside file')
            if flags & 0x20000000 and raw_size:
                regions.append({'name': name.rstrip(b'\0').decode('ascii', 'replace'), 'offset': offset,
                                'size': raw_size, 'rva': rva, 'va': base + rva})
        kind = 'PE-x64'
    elif data[:6] == b'\x7fELF\x02\x01':
        machine, = read('<H', 18)
        phoff, = read('<Q', 32)
        entry_size, count = read('<HH', 54)
        require(machine == 62 and entry_size >= 56 and count <= 512, 'Expected ELF64 little-endian x86-64')
        for index in range(count):
            typ, flags, offset, va, physical, size = read('<IIQQQQ', phoff + index * entry_size)
            require(offset + size <= len(data), 'ELF segment outside file')
            if typ == 1 and flags & 1 and size:
                regions.append({'name': f'PT_LOAD_X_{index}', 'offset': offset, 'size': size, 'va': va})
        kind = 'ELF-x64'
    else:
        raise Blocked('Input is not an analyzable x64 PE/ELF; encrypted packages are not supported')
    require(bool(regions), 'No executable file-backed regions found')
    return kind, regions


def scan(path: Path, targets: list[dict]) -> dict:
    require(len(targets) <= 128, 'Too many signature targets for M1')
    ids = [target['id'] for target in targets]
    require(len(ids) == len(set(ids)), 'Duplicate signature target IDs')
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        kind, regions = executable_regions(data)
        result = {'format': kind, 'executable_regions': [], 'signatures': []}
        for region in regions:
            content = data[region['offset']:region['offset'] + region['size']]
            result['executable_regions'].append({**region, 'sha256': hashlib.sha256(content).hexdigest()})
        for target in targets:
            require(bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', target['id'])), 'Invalid signature target ID')
            tokens = target['pattern'].split()
            require(4 <= len(tokens) <= 512 and sum(t not in {'?', '??'} for t in tokens) >= 2, 'Signature needs at least four tokens and two fixed bytes')
            require(all(t in {'?', '??'} or re.fullmatch(r'[0-9a-fA-F]{2}', t) for t in tokens), 'Invalid signature pattern')
            expression = b''.join(b'.' if t in {'?', '??'} else re.escape(bytes.fromhex(t)) for t in tokens)
            pattern = re.compile(b'(?=(' + expression + b'))', re.DOTALL)
            matches = []
            for region in regions:
                start, end = region['offset'], region['offset'] + region['size']
                for match in pattern.finditer(data, start, end):
                    delta = match.start() - start
                    hit = {'file_offset': match.start(), 'static_va': region['va'] + delta}
                    if 'rva' in region:
                        hit['rva'] = region['rva'] + delta
                    matches.append(hit)
                    if len(matches) >= 16:
                        break
                if len(matches) >= 16:
                    break
            result['signatures'].append({'id': target['id'], 'matches': matches,
                                         'count_is_lower_bound': len(matches) >= 16,
                                         'status': 'UNIQUE_CANDIDATE' if len(matches) == 1 else 'MISSING' if not matches else 'AMBIGUOUS'})
    return result


def deep_diff(work: Path, old: Path, new: Path, settings: dict) -> dict:
    image = settings['ghidriff_image']
    require(bool(re.fullmatch(r'ghcr\.io/clearbluejar/ghidriff@sha256:[0-9a-f]{64}', image)), 'Analysis image must be digest-pinned')
    require(shutil.which('docker') is not None, 'Docker is required for deep analysis')
    output = work / 'engine'
    output.mkdir()
    output.chmod(0o777)  # Only the disposable container output, never the repository/secrets.
    log = work / 'engine.log'
    name = 'nel-analysis-' + str(os.getpid())
    available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
    memory = max(2, min(10, available // (1024**3) - 2))
    with log.open('wb') as stream:
        inspected = subprocess.run(['docker', 'image', 'inspect', image], stdout=stream, stderr=subprocess.STDOUT, timeout=30)
        require(inspected.returncode == 0, 'Pinned local analysis image was not built')
        command = ['docker', 'run', '--rm', '--name', name, '--network=none', '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--pids-limit=512', f'--memory={memory}g',
                   f'--memory-swap={memory}g', '--cpus=2', '-v', f'{old.parent}:/inputs:ro',
                   '-v', f'{output}:/output:rw', image, f'/inputs/{old.name}', f'/inputs/{new.name}',
                   '--output-path', '/output/results', '--project-location', '/output/projects',
                   '--symbols-path', '/output/symbols', '--gzfs-path', '/output/gzfs',
                   '--log-path', '/output/engine.log', '--no-symbols', '--no-threaded',
                   f'--jvm-args=-Xmx{max(1, memory-1)}G']
        try:
            finished = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                      timeout=settings['deep_timeout_seconds'])
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    require(finished.returncode == 0, 'Ghidriff failed; compatibility is not established')
    files = sorted((output / 'results').rglob('*.json'))
    require(bool(files), 'Ghidriff produced no JSON diff')
    # Parse results to detect empty/truncated output; do not publish decompiled content by default.
    for file in files:
        require(file.stat().st_size <= 150 * 1024 * 1024, 'Diff report exceeds export budget')
        parsed = json.loads(file.read_text())
        require(isinstance(parsed, dict) and bool(parsed), 'Empty/invalid diff JSON')
    return {'status': 'ENGINE_FINISHED_REVIEW_REQUIRED', 'image': image, 'json_reports': len(files),
            'memory_limit_gib': memory, 'timeout_seconds': settings['deep_timeout_seconds']}


def export_details(work: Path, report: dict) -> None:
    results = work / 'engine' / 'results'
    if not results.exists():
        return
    files = [p for p in results.rglob('*') if p.is_file() and p.suffix in {'.json', '.md', '.html'}]
    require(sum(p.stat().st_size for p in files) <= 250 * 1024 * 1024, 'Detailed report export too large')
    private = os.environ.get('REPOSITORY_PRIVATE') == 'true'
    recipient = os.environ.get('REPORT_AGE_RECIPIENT', '')
    if not private and not recipient:
        report['details'] = 'NOT_PUBLISHED: public repository requires REPORT_AGE_RECIPIENT for full diff'
        return
    bundle = work / 'details.tar.gz'
    with tarfile.open(bundle, 'w:gz') as archive:
        for file in files:
            archive.add(file, arcname=str(file.relative_to(results)), recursive=False)
    if private:
        shutil.copyfile(bundle, work / 'publish' / 'details.tar.gz')
        report['details'] = 'PRIVATE_REPOSITORY_ARTIFACT'
    else:
        require(bool(re.fullmatch(r'age1[0-9a-z]{40,100}', recipient)), 'Invalid age recipient; use a public age key')
        require(shutil.which('age') is not None, 'Install age before exporting full reports')
        subprocess.run(['age', '-r', recipient, '-o', str(work / 'publish' / 'details.tar.gz.age'), str(bundle)], check=True)
        report['details'] = 'AGE_ENCRYPTED_ARTIFACT'


def already_done(name: str) -> bool:
    if os.environ.get('GITHUB_EVENT_NAME') != 'schedule':
        return False
    repository, token = os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GH_READ_TOKEN')
    if not repository or not token:
        return False
    require(bool(re.fullmatch(r'[\w.-]+/[\w.-]+', repository)), 'Invalid GitHub repository identity')
    url = f'https://api.github.com/repos/{repository}/actions/artifacts?name={urllib.parse.quote(name)}&per_page=100'
    artifacts = get_json(url, {'api.github.com'}, token).get('artifacts', [])
    return any(item.get('name') == name and not item.get('expired', True) for item in artifacts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['bds', 'client'])
    parser.add_argument('--mode', choices=['detect', 'triage', 'deep'], default='detect')
    parser.add_argument('--old-version', default='')
    parser.add_argument('--new-version', default='latest')
    parser.add_argument('--platform', choices=['windows', 'linux'], default='windows')
    parser.add_argument('--channel', choices=['release', 'preview'], default='release')
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    require(not work.exists(), 'Work directory must be new to prevent stale-result reuse')
    (work / 'publish').mkdir(parents=True)
    report = {'schema': 1, 'role': args.role, 'mode': args.mode, 'status': 'STARTED',
              'source_commit': os.environ.get('GITHUB_SHA', 'local'), 'runtime': 'NOT_RUN',
              'build': 'NOT_RUN', 'compatibility': 'NOT_VERIFIED',
              'note': 'BDS and client addresses/ABI are not interchangeable. No source auto-patching.'}
    artifact = f'bedrock-{args.role}-incomplete-{os.environ.get("GITHUB_RUN_ID", "local")}'
    code = 0
    try:
        settings = json.loads((ROOT / 'analysis' / 'settings.json').read_text())
        if args.role == 'bds':
            new = bds_entry(args.new_version, args.platform, args.channel)
            old = bds_entry(args.old_version, args.platform, args.channel) if args.old_version else None
            hosts = BDS_HOSTS
        else:
            old, new, hosts = client_entries()
        def public(item):
            return {key: item.get(key) for key in ('version', 'platform', 'channel', 'download_sha256', 'checksum_source')}
        report['old'] = public(old) if old else None
        report['new'] = public(new)
        catalogue = f'bds-{args.platform}-signatures.json' if args.role == 'bds' else 'client-signatures.json'
        signature_path = ROOT / 'analysis' / catalogue
        signatures = json.loads(signature_path.read_text())
        require(signatures['role'] == args.role, 'Signature catalogue belongs to another role')
        require(signatures.get('platform') == args.platform or (args.role == 'client' and signatures.get('platform') == 'windows'), 'Signature platform mismatch')
        targets = signatures['targets']
        report['signature_coverage'] = len(targets)
        identity = {'role': args.role, 'mode': args.mode, 'old': report['old'], 'new': report['new'],
                    'toolchain': settings, 'signature_sha': sha256(signature_path), 'source_commit': report['source_commit']}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
        complete_name = f'bedrock-{args.role}-{args.mode}-{key}'
        if args.mode == 'detect':
            report['status'] = 'DETECTED' if old else 'DETECTED_BASELINE_NOT_CONFIGURED'
        elif old is None:
            raise Blocked('A known old BDS version is required for comparison; set old_version or BDS_BASELINE_VERSION')
        elif already_done(complete_name):
            report['status'] = 'SKIPPED_EXISTING_REPORT'
            report['existing_artifact'] = complete_name
        else:
            suffix = '.exe' if new['platform'] == 'windows' else '.elf'
            old_path, new_path = work / 'inputs' / ('old' + suffix), work / 'inputs' / ('new' + suffix)
            report['old'] = acquire(old, old_path, hosts)
            report['new'] = acquire(new, new_path, hosts)
            report['old_scan'], report['new_scan'] = scan(old_path, targets), scan(new_path, targets)
            expected = 'PE-x64' if new['platform'] == 'windows' else 'ELF-x64'
            require(report['old_scan']['format'] == report['new_scan']['format'] == expected, 'Input platform/architecture mismatch')
            if report['old']['binary_sha256'] == report['new']['binary_sha256']:
                report['status'] = 'IDENTICAL_BINARIES'
            elif args.mode == 'deep':
                report['engine'] = deep_diff(work, old_path, new_path, settings)
                report['status'] = 'DIFF_FINISHED_REVIEW_REQUIRED'
                export_details(work, report)
            else:
                report['status'] = 'TRIAGE_COMPLETE_NOT_A_FUNCTION_DIFF'
            artifact = complete_name
    except Blocked as error:
        report['status'], report['reason'], code = 'BLOCKED', str(error), 2
    except subprocess.TimeoutExpired:
        report['status'], report['reason'], code = 'INCOMPLETE', 'A bounded operation timed out; no compatibility claim', 3
    except Exception as error:
        # Do not print exception text: network exceptions can include signed URLs.
        report['status'], report['reason'], code = 'FAILED', f'{type(error).__name__}; sensitive diagnostics withheld', 1
    finally:
        write_json(work / 'publish' / 'summary.json', report)
        summary = (f'# {args.role.upper()} binary analysis\n\n'
                   f'- Status: **{report["status"]}**\n- Mode: `{args.mode}`\n'
                   '- Compatibility: **NOT_VERIFIED**\n- Game/server execution: **NOT_RUN**\n'
                   '- Client DLL build / AI patching: **NOT_RUN**\n\n'
                   'See summary.json. Unique signatures are candidates, not verified ABI. '
                   'Triage is only executable-region/signature inspection; deep runs Ghidra/ghidriff.\n')
        (work / 'publish' / 'summary.md').write_text(summary, encoding='utf-8')
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write(summary)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write(f'artifact_name={artifact}\nstatus={report["status"]}\n')
        print(f'{args.role}: {report["status"]}; see sanitized report')
    return code


if __name__ == '__main__':
    sys.exit(main())
