"""SSRF-safe HTTPS download of a PDF/EPUB to a local file (for remarkable_upload_url)."""

import ipaddress
import os
import socket
import time
import zipfile
from typing import Optional, Tuple
from urllib.parse import urljoin, urlsplit

import urllib3

MAX_REDIRECTS = 3
TIMEOUT = urllib3.Timeout(connect=10, read=30)
TOTAL_DEADLINE_S = 120  # ponytail: wall-clock cap so a slow-drip server can't hold a worker


class FetchError(Exception):
    """User-presentable download failure; `kind` becomes the make_error type."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def max_bytes() -> int:
    return int(float(os.environ.get("REMARKABLE_UPLOAD_URL_MAX_MB", "50")) * 1024 * 1024)


def _public_ip(host: str, port: int) -> str:
    """Resolve host; refuse if ANY address is non-global. Returns the vetted IP."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError("dns_failed", f"Cannot resolve '{host}': {e}")
    ips = [i[4][0].split("%")[0] for i in infos]
    if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise FetchError("blocked_address", f"'{host}' resolves to a non-public address")
    return ips[0]


def _sniff(path: str) -> Optional[str]:
    """Return 'pdf'/'epub' by content (not Content-Type/extension), else None."""
    with open(path, "rb") as f:
        if f.read(5) == b"%PDF-":
            return "pdf"
    try:
        with zipfile.ZipFile(path) as z:
            if z.read("mimetype").strip() == b"application/epub+zip":
                return "epub"
    except (zipfile.BadZipFile, KeyError, OSError):
        pass
    return None


def download(url: str, dest_dir: str) -> Tuple[str, str]:
    """Stream `url` into dest_dir. Returns (path, 'pdf'|'epub'). Raises FetchError."""
    limit, deadline = max_bytes(), time.monotonic() + TOTAL_DEADLINE_S
    path = os.path.join(dest_dir, "download.bin")
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise FetchError(
                "invalid_url", "Only plain https:// URLs without credentials are allowed"
            )
        port = parts.port or 443
        ip = _public_ip(parts.hostname, port)
        # Connect to the vetted IP (no DNS-rebinding gap); verify TLS against the hostname.
        pool = urllib3.HTTPSConnectionPool(
            ip,
            port,
            server_hostname=parts.hostname,
            assert_hostname=parts.hostname,
            cert_reqs="CERT_REQUIRED",
            timeout=TIMEOUT,
            retries=False,
        )
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            resp = pool.urlopen(
                "GET",
                target,
                headers={"Host": parts.netloc},
                redirect=False,
                preload_content=False,
            )
        except urllib3.exceptions.HTTPError as e:
            raise FetchError("download_failed", f"Request failed: {e}")
        try:
            if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                url = urljoin(url, resp.headers["Location"])
                continue
            if resp.status != 200:
                raise FetchError("download_failed", f"Server returned HTTP {resp.status}")
            size = 0
            try:
                with open(path, "wb") as f:
                    for chunk in resp.stream(64 * 1024):
                        size += len(chunk)
                        if size > limit or time.monotonic() > deadline:
                            raise FetchError(
                                "too_large" if size > limit else "timeout",
                                f"Download exceeded {limit // (1024 * 1024)} MB or "
                                f"{TOTAL_DEADLINE_S}s limit",
                            )
                        f.write(chunk)
            except urllib3.exceptions.HTTPError as e:
                raise FetchError("download_failed", f"Download interrupted: {e}")
        finally:
            resp.release_conn()
            pool.close()
        kind = _sniff(path)
        if kind is None:
            raise FetchError("unsupported_format", "Downloaded file is not a valid PDF or EPUB")
        final = os.path.join(dest_dir, f"document.{kind}")
        os.replace(path, final)
        return final, kind
    raise FetchError("too_many_redirects", f"More than {MAX_REDIRECTS} redirects")
