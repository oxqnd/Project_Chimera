import subprocess
import sys
import os
import time
import shlex
import tempfile
from typing import Optional
from urllib.parse import urlparse

import requests
from zapv2 import ZAPv2

from .session_manager import get_session_headers_for_host

def run_subfinder(domain: str) -> list[str]:
    subfinder_path = os.path.expanduser("~/go/bin/subfinder")
    if not os.path.exists(subfinder_path):
        raise FileNotFoundError("Subfinder not found")
    
    command = [subfinder_path, "-d", domain, "-silent"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(timeout=300)

    if process.returncode != 0:
        raise Exception(stderr)

    return stdout.strip().split('\n')

def get_host_ip_from_wsl():
    """Reads /etc/resolv.conf to get the host IP address from within WSL2."""
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.strip().startswith('nameserver'):
                    return line.split()[1]
    except FileNotFoundError:
        return "127.0.0.1" # Fallback for non-WSL environments
    return "127.0.0.1"


def _merge_headers_with_session(target_url: str, headers: dict | None) -> dict[str, str]:
    parsed = urlparse(target_url)
    session_headers = get_session_headers_for_host(parsed.hostname or "")
    merged = dict(session_headers)
    if headers:
        merged.update(headers)
    return merged


def _inject_session_into_curl(parts: list[str], session_headers: dict[str, str]) -> list[str]:
    if not session_headers:
        return parts

    existing_headers = {
        header.split(":", 1)[0].strip()
        for idx, part in enumerate(parts)
        if part in {"-H", "--header"} and idx + 1 < len(parts)
        for header in [parts[idx + 1]]
    }

    updated_parts = parts[:]

    cookie_value = session_headers.get("Cookie")
    if cookie_value and all(flag not in updated_parts for flag in ("--cookie", "-b")):
        updated_parts.extend(["--cookie", cookie_value])

    for header_name, header_value in session_headers.items():
        if header_name.lower() == "cookie":
            continue
        if header_name in existing_headers:
            continue
        updated_parts.extend(["-H", f"{header_name}: {header_value}"])

    return updated_parts

class ExternalZAPv2(ZAPv2):
    """ZAP client that allows overriding the API host."""

    def __init__(self, base_url: str):
        super().__init__(proxies={})
        # Ensure outbound requests hit the desired endpoint directly.
        self._ZAPv2__proxies = {}
        self.base = f"{base_url}/JSON/"
        self.base_other = f"{base_url}/OTHER/"
        self._base_url = base_url

    def _request_api(self, url, query=None, method="GET", body=None):
        """Copy of upstream logic without host restriction."""
        if not url.startswith("http"):
            raise ValueError(f"ZAP API url must be absolute, got: {url}")

        self.session = requests.Session()
        if self._ZAPv2__apikey is not None:
            self.session.headers['X-ZAP-API-Key'] = self._ZAPv2__apikey

        response = self.session.request(
            method,
            url,
            params=query,
            data=body,
            proxies=self._ZAPv2__proxies or None,
            verify=False,
        )

        if (self._ZAPv2__validate_status_code and 300 <= response.status_code < 500):
            raise Exception(
                "Non-successful status code returned from ZAP, which indicates a bad request: "
                + str(response.status_code)
                + "response: "
                + response.text
            )
        if (self._ZAPv2__validate_status_code and response.status_code >= 500):
            raise Exception(
                "Non-successful status code returned from ZAP, which indicates a ZAP internal error: "
                + str(response.status_code)
                + "response: "
                + response.text
            )
        return response

def _build_zap_client(base_url: str) -> ZAPv2:
    """Create a ZAP client targeting the provided base URL."""
    zap = ExternalZAPv2(base_url)
    zap.urlopen = lambda url: requests.get(  # noqa: E731
        f"{base_url}/OTHER/core/other/urlopen/",
        params={"url": url},
        timeout=30,
        verify=False,
    ).text
    return zap

def _wait_for_zap(zap: ZAPv2, attempts: int = 12, delay: int = 5) -> None:
    """Poll the ZAP instance until it is ready or timeout is reached."""
    print("Waiting for ZAP to be ready...")
    for i in range(attempts):
        try:
            version = zap.core.version
            print(f"Successfully connected to ZAP version {version}")
            return
        except Exception as exc:
            print(f"Attempt {i + 1}/{attempts}: ZAP not ready yet ({exc!r}), waiting {delay} seconds...")
            time.sleep(delay)
    raise TimeoutError(f"Timeout: Could not connect to ZAP after {attempts * delay} seconds.")

def _get_zap_client() -> ZAPv2:
    """Finds and connects to the ZAP instance, returning a client."""
    zap_port = os.getenv("ZAP_PORT", "8080")
    candidate_bases: list[str] = []

    zap_base_override = os.getenv("ZAP_BASE_URL")
    if zap_base_override:
        candidate_bases.append(zap_base_override.rstrip("/"))

    zap_host_override = os.getenv("ZAP_HOST")
    if zap_host_override:
        candidate_bases.append(f"http://{zap_host_override}:{zap_port}")

    host_candidates = ["127.0.0.1", "localhost", "host.docker.internal"]

    wsl_host = get_host_ip_from_wsl()
    if wsl_host:
        host_candidates.append(wsl_host)

    seen = set()
    unique_hosts = [host for host in host_candidates if host and not (host in seen or seen.add(host))]

    for host in unique_hosts:
        candidate_bases.append(f"http://{host}:{zap_port}")

    print(f"ZAP candidate endpoints: {candidate_bases}")

    for base_url in candidate_bases:
        print(f"Connecting to ZAP at: {base_url}")
        try:
            zap = _build_zap_client(base_url)
            _wait_for_zap(zap, attempts=12, delay=5)
            return zap
        except Exception as e:
            print(f"Failed to connect to ZAP at {base_url}: {e!r}")

    raise ConnectionError("Unable to connect to any ZAP instance.")

def run_zap_scan(target: str) -> list[dict]:
    if not target.startswith('http'):
        target = f"https://{target}"
    
    zap = _get_zap_client()
    
    print(f"Scanning target: {target}")
    zap.urlopen(target)
    time.sleep(5) # Allow passive scanner to run

    alerts = zap.core.alerts(baseurl=target)

    findings = []
    for alert in alerts:
        severity = alert.get('risk', 'info')
        if severity == 'High': severity = 'high'
        if severity == 'Medium': severity = 'medium'
        if severity == 'Low': severity = 'low'
        if severity == 'Informational': severity = 'info'

        findings.append({
            "finding": alert.get('name'),
            "severity": severity
        })
    return findings

def run_zap_spider(target: str) -> list[str]:
    """
    Runs the ZAP spider against a target URL to discover URLs.
    """
    if not target.startswith('http'):
        target = f"https://{target}"

    zap = _get_zap_client()
    print(f"[*] Running ZAP Spider on {target}...")
    scan_id = zap.spider.scan(url=target)
    
    # Poll the status until it's 100% complete
    while int(zap.spider.status(scan_id)) < 100:
        print(f"    -> Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)
    
    print("[*] ZAP Spider completed.")
    
    # Return the found URLs
    results = zap.spider.results(scan_id)
    return results

def run_zap_send_request(target_url: str, method: str = "GET", headers: dict | None = None, body: str = "") -> dict:
    """
    Sends a custom HTTP request through ZAP.
    """
    zap = _get_zap_client()
    print(f"[*] Sending custom request to {target_url} via ZAP...")

    merged_headers = _merge_headers_with_session(target_url, headers)
    parsed = urlparse(target_url)
    if parsed.hostname and "host" not in {key.lower() for key in merged_headers}:
        merged_headers["Host"] = parsed.netloc

    header_str = ""
    for key, value in merged_headers.items():
        header_str += f"{key}: {value}\r\n"

    response = zap.core.send_request(request=f"{method} {target_url} HTTP/1.1\r\n{header_str}\r\n{body}")
    
    return response

def run_zap_custom_scan(target: str, policy: str) -> list[dict]:
    """
    Runs a custom ZAP active scan with a specified policy.
    """
    if not target.startswith('http'):
        target = f"https://{target}"

    zap = _get_zap_client()
    
    policy_name = f"Chimera-{policy}"
    print(f"[*] Configuring ZAP policy: {policy_name}")

    scanner_ids_to_enable = {
        "sqli": "40018",
        "xss": "40012,40014,40016,40017" 
    }
    
    scanner_id = scanner_ids_to_enable.get(policy.lower())
    if not scanner_id:
        raise ValueError(f"Unknown custom scan policy: {policy}. Available: {list(scanner_ids_to_enable.keys())}")

    try:
        zap.ascan.remove_scan_policy(policy_name)
        print(f"    -> Removed existing policy: {policy_name}")
    except:
        pass

    zap.ascan.add_scan_policy(policy_name)
    print(f"    -> Created new policy: {policy_name}")
    
    zap.ascan.disable_all_scanners(scanpolicyname=policy_name)
    
    zap.ascan.enable_scanners(ids=scanner_id, scanpolicyname=policy_name)
    print(f"    -> Enabled scanner(s) {scanner_id} for policy {policy_name}")

    print(f"[*] Running custom ZAP Active Scan on {target} with policy {policy_name}...")
    scan_id = zap.ascan.scan(url=target, scanpolicyname=policy_name)

    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    -> Active Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(5)

    print("[*] Custom ZAP Active Scan completed.")
    
    alerts = zap.core.alerts(baseurl=target)
    findings = []
    for alert in alerts:
        severity = alert.get('risk', 'info')
        if severity == 'High': severity = 'high'
        if severity == 'Medium': severity = 'medium'
        if severity == 'Low': severity = 'low'
        if severity == 'Informational': severity = 'info'

        findings.append({
            "finding": alert.get('name'),
            "severity": severity
        })
    return findings

def run_zap_fuzzer(target_url: str, payloads: list[str], method: str = "GET", headers: dict | None = None) -> list[dict]:
    """
    Runs the ZAP fuzzer against a target URL with a given list of payloads.
    The target URL should contain 'FUZZ' where the payload should be inserted.
    """
    if 'FUZZ' not in target_url:
        raise ValueError("Target URL for fuzzer must contain 'FUZZ' placeholder.")

    zap = _get_zap_client()

    print(f"[*] Running ZAP Fuzzer on {target_url} with {len(payloads)} payloads...")

    fuzz_results = []
    # Limit to 100 payloads for this demonstration to avoid excessively long runs
    for payload in payloads[:100]:
        fuzzed_url = target_url.replace('FUZZ', payload)
        try:
            merged_headers = _merge_headers_with_session(fuzzed_url, headers)
            parsed = urlparse(fuzzed_url)
            if parsed.hostname and "host" not in {key.lower() for key in merged_headers}:
                merged_headers["Host"] = parsed.netloc

            header_str = ""
            for key, value in merged_headers.items():
                header_str += f"{key}: {value}\r\n"

            request_str = f"{method} {fuzzed_url} HTTP/1.1\r\n{header_str}"
            msg = zap.core.send_request(request=request_str, follow_redirects=False)
            status_line = msg.split('\r\n')[0]
            status_code = int(status_line.split(' ')[1])

            if status_code != 404:
                fuzz_results.append({
                    "payload": payload,
                    "status_code": status_code,
                    "url": fuzzed_url
                })
        except Exception as e:
            print(f"    -> Error fuzzing {fuzzed_url}: {e}")

    print(f"[*] Fuzzing completed. Found {len(fuzz_results)} interesting results.")
    return fuzz_results

def run_nmap(domain: str) -> list[str]:
    """Runs nmap to find open ports."""
    print(f"[*] Running nmap on {domain}...")
    command = ["nmap", "-F", domain]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=300)
        if process.returncode != 0:
            print(f"[!] Error running nmap: {stderr}", file=sys.stderr)
            return []
        
        open_ports = []
        for line in stdout.split('\n'):
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_info = f"{parts[0]} {parts[1]}"
                    open_ports.append(port_info)
        
        print(f"[*] Found {len(open_ports)} open ports on {domain}.")
        return open_ports
    except Exception as e:
        print(f"[!] An unexpected error occurred during nmap scan: {e}", file=sys.stderr)
        return []

def run_curl(command: str) -> str:
    """Executes a curl command and returns the output."""
    print(f"[*] Running curl: {command}")
    try:
        # We use shlex.split to properly handle quoted arguments
        command_parts = shlex.split(command)
        if command_parts[0] != 'curl':
            raise ValueError("Only curl commands are allowed.")

        target_url = next((part for part in command_parts[1:] if part.startswith("http")), None)
        if target_url:
            parsed = urlparse(target_url)
            session_headers = get_session_headers_for_host(parsed.hostname or "")
            command_parts = _inject_session_into_curl(command_parts, session_headers)

        process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        stdout, stderr = process.communicate(timeout=120)
        
        if process.returncode != 0:
            return f"Error executing curl: {stderr}"
        
        return stdout
    except Exception as e:
        return f"An unexpected error occurred during curl execution: {e}"


def list_zap_scripts() -> dict:
    zap = _get_zap_client()
    scripts = zap.script.list_scripts()
    return scripts


def run_zap_script(script_name: str) -> dict:
    zap = _get_zap_client()
    try:
        return zap.script.run_stored_script(scriptname=script_name)
    except Exception:
        return zap.script.run_standalone_script(scriptname=script_name)


def remove_zap_script(script_name: str) -> dict:
    zap = _get_zap_client()
    return zap.script.remove(scriptname=script_name)


def load_zap_script(script_name: str, script_type: str, script_engine: str, script_content: str, description: str | None = None) -> dict:
    zap = _get_zap_client()

    extension_map = {
        "ECMAScript": ".js",
        "Python": ".py",
        "Zest": ".zst",
        "WebSockets": ".js",
    }
    suffix = extension_map.get(script_engine, ".txt")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as tmp_file:
            tmp_file.write(script_content)
            temp_path = tmp_file.name

        try:
            response = zap.script.load(script_name, script_type, script_engine, temp_path, description or "")
        except TypeError:
            response = zap.script.load(
                scriptname=script_name,
                scripttype=script_type,
                scriptengine=script_engine,
                filename=temp_path,
            )

        try:
            zap.script.enable(scriptname=script_name)
        except Exception:
            pass

        return response
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
