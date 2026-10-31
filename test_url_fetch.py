"""Tests for the SSRF-safe URL downloader behind remarkable_upload_url."""

import io
import json
import os
import zipfile
from unittest.mock import Mock, patch

import pytest

from remarkable_mcp import url_fetch
from remarkable_mcp.url_fetch import FetchError

PDF = b"%PDF-1.4 test"


def _epub() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("mimetype", "application/epub+zip")
    return buf.getvalue()


def _resp(status=200, body=PDF, location=None):
    r = Mock(status=status, headers={"Location": location} if location else {})
    r.stream.return_value = iter([body])
    return r


def _pool(*responses):
    pool = Mock()
    pool.urlopen.side_effect = list(responses)
    return pool


@pytest.fixture
def public_dns():
    with patch.object(url_fetch, "_public_ip", return_value="93.184.216.34") as m:
        yield m


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"]
)
def test_non_public_addresses_blocked(ip):
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", (ip, 443))]):
        with pytest.raises(FetchError) as e:
            url_fetch._public_ip("evil.example", 443)
    assert e.value.kind == "blocked_address"


def test_mixed_dns_answer_blocked():
    infos = [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("10.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=infos):
        with pytest.raises(FetchError):
            url_fetch._public_ip("rebind.example", 443)


@pytest.mark.parametrize(
    "url",
    ["http://example.com/a.pdf", "ftp://x/a.pdf", "https://u:p@example.com/a.pdf", "https:///x"],
)
def test_bad_scheme_or_credentials(url, tmp_path):
    with pytest.raises(FetchError) as e:
        url_fetch.download(url, str(tmp_path))
    assert e.value.kind == "invalid_url"


@pytest.mark.parametrize("body,kind", [(PDF, "pdf"), (_epub(), "epub")])
def test_download_ok_sniffs_content(public_dns, tmp_path, body, kind):
    with patch("urllib3.HTTPSConnectionPool", return_value=_pool(_resp(body=body))):
        path, got = url_fetch.download("https://example.com/whatever.bin", str(tmp_path))
    assert got == kind and path.endswith(f"document.{kind}") and os.path.exists(path)


def test_wrong_content_rejected_and_cleaned(public_dns, tmp_path):
    with patch("urllib3.HTTPSConnectionPool", return_value=_pool(_resp(body=b"<html>hi"))):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "unsupported_format"


def test_size_cap(public_dns, tmp_path, monkeypatch):
    monkeypatch.setenv("REMARKABLE_UPLOAD_URL_MAX_MB", "0.00001")  # ~10 bytes
    with patch("urllib3.HTTPSConnectionPool", return_value=_pool(_resp(body=PDF))):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "too_large"


def test_redirect_target_is_revalidated(tmp_path):
    seen = []

    def fake_ip(host, port):
        seen.append(host)
        if host == "internal.example":
            raise FetchError("blocked_address", "nope")
        return "93.184.216.34"

    pool = _pool(_resp(302, location="https://internal.example/secret"))
    with (
        patch.object(url_fetch, "_public_ip", side_effect=fake_ip),
        patch("urllib3.HTTPSConnectionPool", return_value=pool),
    ):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "blocked_address" and seen == ["example.com", "internal.example"]


def test_redirect_to_http_rejected(public_dns, tmp_path):
    pool = _pool(_resp(302, location="http://example.com/a.pdf"))
    with patch("urllib3.HTTPSConnectionPool", return_value=pool):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "invalid_url"


def test_redirect_loop_capped(public_dns, tmp_path):
    loop = [_resp(302, location="https://example.com/a.pdf") for _ in range(10)]
    with patch("urllib3.HTTPSConnectionPool", return_value=_pool(*loop)):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "too_many_redirects"


def test_non_200(public_dns, tmp_path):
    with patch("urllib3.HTTPSConnectionPool", return_value=_pool(_resp(404))):
        with pytest.raises(FetchError) as e:
            url_fetch.download("https://example.com/a.pdf", str(tmp_path))
    assert e.value.kind == "download_failed"


@pytest.mark.asyncio
async def test_tool_uploads_downloaded_file_and_cleans_up(public_dns):
    from test_server import _call_tool

    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("REMARKABLE_USE_SSH", "REMARKABLE_USE_USB_WEB")
    }
    client = Mock(spec=["get_meta_items", "upload_document"])
    client.get_meta_items.return_value = []
    client.upload_document.return_value = Mock(id="doc-id")
    with (
        patch.dict(os.environ, env, clear=True),
        patch("remarkable_mcp.write_tools.get_rmapi", return_value=client),
        patch("urllib3.HTTPSConnectionPool", return_value=_pool(_resp())),
    ):
        result = await _call_tool(
            "remarkable_upload_url", {"url": "https://example.com/files/My%20Notes.pdf"}
        )
    data = json.loads(result.content[0].text)
    assert data["uploaded"] is True and data["name"] == "My Notes"
    content, name, ext, _ = client.upload_document.call_args.args
    assert content == PDF and ext == "pdf"


@pytest.mark.asyncio
async def test_tool_surfaces_fetch_error():
    from test_server import _call_tool

    result = await _call_tool("remarkable_upload_url", {"url": "http://example.com/a.pdf"})
    assert json.loads(result.content[0].text)["_error"]["type"] == "invalid_url"
