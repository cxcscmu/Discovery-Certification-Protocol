"""Allowlisted live-Web capture and exact, network-free replay."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import http.client
import ipaddress
from pathlib import Path
import socket
import ssl
from typing import Any, Protocol
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from dcp_harness.config import WebConfig
from dcp_harness.ledger import EventLedger
from dcp_harness.util import (
    HarnessError,
    hash_file,
    hash_json,
    load_json,
    load_json_object,
    safe_child,
    sha256_bytes,
    utc_now,
    write_json,
)


REQUEST_SCHEMA = "dcp_web_request_v1"
RESULT_SCHEMA = "dcp_web_result_v1"
MANIFEST_SCHEMA = "dcp_web_snapshot_v1"
PACKET_SCHEMA = "dcp_web_privileged_packet_v1"


@dataclass(frozen=True)
class WebPolicy:
    enabled: bool
    allowed_hosts: tuple[str, ...]
    allow_subdomains: bool
    max_requests: int
    max_redirects: int
    max_raw_bytes: int
    max_delivered_bytes: int
    timeout_seconds: int
    allowed_content_types: tuple[str, ...] = (
        "application/json",
        "application/xhtml+xml",
        "application/xml",
        "text/html",
        "text/plain",
        "text/xml",
    )
    user_agent: str = "DCP-Harness/0.1 (+offline-audit-capture)"

    @classmethod
    def from_config(cls, config: WebConfig) -> WebPolicy:
        hosts = tuple(_canonical_host(host) for host in config.allowed_hosts)
        return cls(
            enabled=config.enabled,
            allowed_hosts=hosts,
            allow_subdomains=config.allow_subdomains,
            max_requests=config.max_requests,
            max_redirects=config.max_redirects,
            max_raw_bytes=config.max_raw_bytes,
            max_delivered_bytes=config.max_delivered_bytes,
            timeout_seconds=config.timeout_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["allowed_hosts"] = list(self.allowed_hosts)
        value["allowed_content_types"] = list(self.allowed_content_types)
        return value


def _canonical_host(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HarnessError("Web host must be nonempty canonical text")
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HarnessError(f"invalid Web host: {value!r}") from exc
    if not host or ":" in host or "/" in host or "@" in host:
        raise HarnessError(f"invalid Web host: {value!r}")
    return host


def _host_allowed(host: str, policy: WebPolicy) -> bool:
    if host in policy.allowed_hosts:
        return True
    return policy.allow_subdomains and any(
        host.endswith("." + allowed) for allowed in policy.allowed_hosts
    )


def canonicalize_url(value: str, policy: WebPolicy) -> str:
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise HarnessError("Web URL must be a nonempty string of at most 8192 bytes")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise HarnessError("Web URL contains whitespace or control characters")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise HarnessError("only HTTPS Web URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise HarnessError("Web URL credentials are forbidden")
    if parsed.hostname is None:
        raise HarnessError("Web URL has no hostname")
    host = _canonical_host(parsed.hostname)
    if not _host_allowed(host, policy):
        raise HarnessError(f"Web host is outside the allowlist: {host}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HarnessError("Web URL has an invalid port") from exc
    if port not in (None, 443):
        raise HarnessError("only the default HTTPS port is allowed")
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    return urlunsplit(("https", host, path, query, ""))


def _safe_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_public_addresses(host: str) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HarnessError(f"cannot resolve Web host {host!r}") from exc
    addresses = sorted({str(item[4][0]) for item in results})
    if not addresses:
        raise HarnessError(f"Web host {host!r} resolved to no addresses")
    rejected = [address for address in addresses if not _safe_ip(address)]
    if rejected:
        raise HarnessError(
            f"Web host {host!r} resolves to a forbidden address: {rejected[0]}"
        )
    return tuple(addresses)


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    headers: dict[str, str]
    raw_body: bytes
    redirect_chain: tuple[str, ...]
    peer_ip: str


class Fetcher(Protocol):
    live_network_used: bool

    def fetch(self, url: str, policy: WebPolicy) -> FetchResult: ...


class LiveHttpsFetcher:
    """HTTPS client that connects to the exact public IP it validated."""

    live_network_used = True

    def fetch(self, url: str, policy: WebPolicy) -> FetchResult:
        requested = canonicalize_url(url, policy)
        current = requested
        redirects: list[str] = []
        for redirect_index in range(policy.max_redirects + 1):
            status, headers, body, peer = self._request(current, policy)
            if status in {301, 302, 303, 307, 308}:
                if redirect_index >= policy.max_redirects:
                    raise HarnessError("Web response exceeded the redirect limit")
                location = headers.get("location")
                if not location:
                    raise HarnessError("Web redirect has no Location header")
                current = canonicalize_url(urljoin(current, location), policy)
                redirects.append(current)
                continue
            if not 200 <= status < 300:
                raise HarnessError(f"Web endpoint returned HTTP {status}")
            return FetchResult(
                requested_url=requested,
                final_url=current,
                status=status,
                headers=_filtered_headers(headers),
                raw_body=body,
                redirect_chain=tuple(redirects),
                peer_ip=peer,
            )
        raise HarnessError("unreachable redirect state")

    @staticmethod
    def _request(
        url: str, policy: WebPolicy
    ) -> tuple[int, dict[str, str], bytes, str]:
        parsed = urlsplit(url)
        host = str(parsed.hostname)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        addresses = resolve_public_addresses(host)
        last_error: Exception | None = None
        for address in addresses:
            raw_socket: socket.socket | None = None
            tls_socket: ssl.SSLSocket | None = None
            try:
                raw_socket = socket.create_connection(
                    (address, 443), timeout=policy.timeout_seconds
                )
                context = ssl.create_default_context()
                tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
                raw_socket = None
                request = (
                    f"GET {target} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {policy.user_agent}\r\n"
                    "Accept: text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1\r\n"
                    "Accept-Encoding: identity\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                tls_socket.sendall(request)
                response = http.client.HTTPResponse(tls_socket)
                response.begin()
                headers = {key.lower(): value.strip() for key, value in response.getheaders()}
                encoding = headers.get("content-encoding", "identity").lower()
                if encoding not in {"", "identity"}:
                    raise HarnessError("compressed Web responses are not accepted")
                content_length = headers.get("content-length")
                if content_length is not None:
                    try:
                        announced = int(content_length)
                    except ValueError as exc:
                        raise HarnessError("invalid Web Content-Length") from exc
                    if announced > policy.max_raw_bytes:
                        raise HarnessError("Web response exceeds the raw-byte limit")
                body = response.read(policy.max_raw_bytes + 1)
                if len(body) > policy.max_raw_bytes:
                    raise HarnessError("Web response exceeds the raw-byte limit")
                return int(response.status), headers, body, address
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
            finally:
                if tls_socket is not None:
                    tls_socket.close()
                if raw_socket is not None:
                    raw_socket.close()
        raise HarnessError(f"HTTPS fetch failed for {host}: {last_error}")


class FixtureFetcher:
    """Deterministic injected backend for offline tests and calibration."""

    live_network_used = False

    def __init__(self, fixtures: Mapping[str, tuple[str, bytes]]) -> None:
        self.fixtures = dict(fixtures)

    def fetch(self, url: str, policy: WebPolicy) -> FetchResult:
        canonical = canonicalize_url(url, policy)
        if canonical not in self.fixtures:
            raise HarnessError(f"no fixture for Web URL: {canonical}")
        content_type, raw = self.fixtures[canonical]
        if len(raw) > policy.max_raw_bytes:
            raise HarnessError("fixture exceeds the raw-byte limit")
        return FetchResult(
            requested_url=canonical,
            final_url=canonical,
            status=200,
            headers={"content-type": content_type, "content-length": str(len(raw))},
            raw_body=raw,
            redirect_chain=(),
            peer_ip="fixture",
        )


def _filtered_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "cache-control",
        "content-language",
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "location",
    }
    return {key.lower(): str(value) for key, value in headers.items() if key.lower() in allowed}


class _VisibleHtml(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.lower() in {"script", "style", "noscript", "template"}:
            self._hidden += 1
        elif tag.lower() in {"p", "br", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "template"} and self._hidden:
            self._hidden -= 1
        elif tag.lower() in {"p", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.parts.append(data)


def _content_type(headers: Mapping[str, str]) -> tuple[str, str]:
    raw = headers.get("content-type", "").strip()
    if not raw:
        raise HarnessError("Web response has no Content-Type")
    pieces = [piece.strip() for piece in raw.split(";")]
    media_type = pieces[0].lower()
    charset = "utf-8"
    for piece in pieces[1:]:
        if piece.lower().startswith("charset="):
            charset = piece.split("=", 1)[1].strip('"').lower()
    if charset not in {"utf-8", "utf8", "us-ascii", "iso-8859-1", "latin-1"}:
        raise HarnessError(f"unsupported Web charset: {charset}")
    return media_type, charset


def model_visible_bytes(result: FetchResult, policy: WebPolicy) -> bytes:
    media_type, charset = _content_type(result.headers)
    if media_type not in policy.allowed_content_types:
        raise HarnessError(f"unsupported Web Content-Type: {media_type}")
    try:
        text = result.raw_body.decode(charset, errors="strict")
    except UnicodeError as exc:
        raise HarnessError("Web response does not match its declared charset") from exc
    if media_type in {"text/html", "application/xhtml+xml"}:
        parser = _VisibleHtml()
        parser.feed(text)
        text = "".join(parser.parts)
    lines = [" ".join(line.split()) for line in text.replace("\r", "\n").split("\n")]
    normalized = "\n".join(line for line in lines if line).strip() + "\n"
    raw = normalized.encode("utf-8")
    if len(raw) > policy.max_delivered_bytes:
        raise HarnessError("model-visible Web text exceeds the delivered-byte limit")
    return raw


def parse_requests(document: Mapping[str, Any], policy: WebPolicy) -> list[dict[str, str]]:
    if document.get("schema") != REQUEST_SCHEMA:
        raise HarnessError(f"Web request schema must be {REQUEST_SCHEMA!r}")
    requests = document.get("requests")
    if not isinstance(requests, list) or not requests:
        raise HarnessError("Web request must contain a nonempty requests array")
    if len(requests) > policy.max_requests:
        raise HarnessError("Web request exceeds the registered request limit")
    parsed: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(requests):
        if not isinstance(item, dict) or set(item) != {"request_id", "query", "url"}:
            raise HarnessError(f"Web request item {index} has the wrong fields")
        request_id = item["request_id"]
        query = item["query"]
        if not isinstance(request_id, str) or not request_id or any(
            char.isspace() for char in request_id
        ):
            raise HarnessError(f"Web request item {index} has an invalid request_id")
        if request_id in seen:
            raise HarnessError("Web request IDs are duplicated")
        if not isinstance(query, str) or not query.strip() or len(query) > 4096:
            raise HarnessError(f"Web request item {index} has an invalid query")
        seen.add(request_id)
        parsed.append(
            {
                "request_id": request_id,
                "query": query,
                "url": canonicalize_url(item["url"], policy),
            }
        )
    return parsed


class CaptureGateway:
    def __init__(self, root: Path, policy: WebPolicy, fetcher: Fetcher | None = None) -> None:
        self.root = root.resolve()
        self.policy = policy
        self.fetcher = fetcher or LiveHttpsFetcher()
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects = self.root / "objects"
        self.objects.mkdir(exist_ok=True)
        self.records_path = self.root / "records.json"
        self.policy_path = self.root / "policy.json"
        self.manifest_path = self.root / "manifest.json"
        self.ledger = EventLedger(self.root / "events.jsonl")
        if self.policy_path.exists():
            if load_json_object(self.policy_path) != policy.to_dict():
                raise HarnessError("Web policy differs from the frozen snapshot policy")
        else:
            write_json(self.policy_path, policy.to_dict())
        if not self.records_path.exists():
            write_json(self.records_path, [])

    @property
    def live_network_used(self) -> bool:
        return bool(self.fetcher.live_network_used)

    def records(self) -> list[dict[str, Any]]:
        value = load_json(self.records_path)
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise HarnessError("Web records file is malformed")
        return list(value)

    def capture(self, document: Mapping[str, Any], *, batch_id: str) -> dict[str, Any]:
        if not self.policy.enabled:
            raise HarnessError("live Web access is disabled by the frozen policy")
        requests = parse_requests(document, self.policy)
        records = self.records()
        if len(records) + len(requests) > self.policy.max_requests:
            raise HarnessError("run exceeds the registered Web request limit")
        results: list[dict[str, Any]] = []
        for request in requests:
            started = self.ledger.append(
                "web_request_started",
                {
                    "batch_id": batch_id,
                    "request_id": request["request_id"],
                    "query_hash": hash_json({"query": request["query"]}),
                    "canonical_url": request["url"],
                    "request_hash": hash_json(request),
                    "credentials_forwarded": False,
                    "cookies_forwarded": False,
                },
            )
            fetched = self.fetcher.fetch(request["url"], self.policy)
            visible = model_visible_bytes(fetched, self.policy)
            raw_hash = sha256_bytes(fetched.raw_body)
            visible_hash = sha256_bytes(visible)
            raw_path = self.objects / f"{raw_hash.removeprefix('sha256:')}.raw"
            visible_path = self.objects / f"{visible_hash.removeprefix('sha256:')}.txt"
            if raw_path.exists() and raw_path.read_bytes() != fetched.raw_body:
                raise HarnessError("raw Web object hash collision")
            if visible_path.exists() and visible_path.read_bytes() != visible:
                raise HarnessError("visible Web object hash collision")
            raw_path.write_bytes(fetched.raw_body)
            visible_path.write_bytes(visible)
            captured = self.ledger.append(
                "web_response_captured",
                {
                    "batch_id": batch_id,
                    "request_id": request["request_id"],
                    "request_prestart_event_hash": started["event_hash"],
                    "raw_hash": raw_hash,
                    "model_visible_hash": visible_hash,
                    "status": fetched.status,
                    "final_url": fetched.final_url,
                    "peer_ip": fetched.peer_ip,
                },
            )
            record: dict[str, Any] = {
                "sequence": len(records) + 1,
                "batch_id": batch_id,
                "request_id": request["request_id"],
                "query": request["query"],
                "requested_url": fetched.requested_url,
                "final_url": fetched.final_url,
                "redirect_chain": list(fetched.redirect_chain),
                "status": fetched.status,
                "response_headers": fetched.headers,
                "peer_ip": fetched.peer_ip,
                "request_prestart_event_index": started["event_index"],
                "request_prestart_event_hash": started["event_hash"],
                "capture_event_index": captured["event_index"],
                "capture_event_hash": captured["event_hash"],
                "raw_object": {
                    "path": raw_path.relative_to(self.root).as_posix(),
                    "hash": raw_hash,
                    "size_bytes": len(fetched.raw_body),
                },
                "model_visible_object": {
                    "path": visible_path.relative_to(self.root).as_posix(),
                    "hash": visible_hash,
                    "size_bytes": len(visible),
                },
            }
            record["record_hash"] = hash_json(record)
            records.append(record)
            results.append(_result_row(self.root, record))
            write_json(self.records_path, records)
        response = {
            "schema": RESULT_SCHEMA,
            "mode": "capture",
            "batch_id": batch_id,
            "captured_at": utc_now(),
            "results": results,
            "all_requests_satisfied": True,
            "live_network_used": self.live_network_used,
        }
        response["packet_hash"] = hash_json(response)
        return response

    def finalize(self) -> dict[str, Any]:
        records = self.records()
        chain_ok, errors = self.ledger.verify()
        if not chain_ok:
            raise HarnessError("Web ledger is invalid: " + "; ".join(errors))
        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "profile": "observed_url_cache_v1" if records else "no_web_observed_v1",
            "policy": self.policy.to_dict(),
            "policy_hash": hash_file(self.policy_path),
            "request_count": len(records),
            "records": records,
            "event_log_hash": hash_file(self.ledger.path) if self.ledger.path.exists() else None,
            "all_model_visible_bytes_recorded": True,
            "main_live_web": self.live_network_used and bool(records),
            "capture_backend": (
                "hardened_live_https_v1"
                if self.live_network_used and records
                else "injected_or_unused_backend"
            ),
            "replay_live_web": False,
        }
        manifest["snapshot_id"] = hash_json(manifest)
        write_json(self.manifest_path, manifest)
        valid, validation_errors = validate_snapshot(self.root)
        if not valid:
            raise HarnessError("invalid finalized Web snapshot: " + "; ".join(validation_errors))
        return manifest


def _result_row(root: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    descriptor = record["model_visible_object"]
    text_path = safe_child(root, str(descriptor["path"]))
    return {
        "request_id": record["request_id"],
        "requested_url": record["requested_url"],
        "final_url": record["final_url"],
        "status": record["status"],
        "content_text": text_path.read_text(encoding="utf-8"),
        "raw_response_hash": record["raw_object"]["hash"],
        "model_visible_content_hash": descriptor["hash"],
        "capture_event_hash": record["capture_event_hash"],
    }


class ReplayGateway:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        valid, errors = validate_snapshot(self.root)
        if not valid:
            raise HarnessError("invalid Web snapshot: " + "; ".join(errors))
        self.manifest = load_json_object(self.root / "manifest.json")
        self.policy = _policy_from_dict(self.manifest["policy"])
        self.by_url = {row["requested_url"]: row for row in self.manifest["records"]}

    def replay(self, document: Mapping[str, Any], *, batch_id: str) -> dict[str, Any]:
        requests = parse_requests(document, self.policy)
        results: list[dict[str, Any]] = []
        for request in requests:
            record = self.by_url.get(request["url"])
            if record is None:
                raise HarnessError("Web request is outside the frozen observed-URL snapshot")
            row = _result_row(self.root, record)
            row["request_id"] = request["request_id"]
            results.append(row)
        response = {
            "schema": RESULT_SCHEMA,
            "mode": "replay",
            "batch_id": batch_id,
            "snapshot_id": self.manifest["snapshot_id"],
            "results": results,
            "all_requests_satisfied": True,
            "live_network_used": False,
        }
        response["packet_hash"] = hash_json(response)
        return response


def privileged_packet(snapshot_root: Path) -> dict[str, Any]:
    replay = ReplayGateway(snapshot_root)
    documents: list[dict[str, Any]] = []
    for index, record in enumerate(replay.manifest["records"], start=1):
        row = _result_row(replay.root, record)
        documents.append(
            {
                "document_id": f"web-doc-{index:04d}",
                "requested_url": row["requested_url"],
                "final_url": row["final_url"],
                "content_text": row["content_text"],
                "raw_response_hash": row["raw_response_hash"],
                "model_visible_content_hash": row["model_visible_content_hash"],
                "capture_event_hash": row["capture_event_hash"],
            }
        )
    packet = {
        "schema": PACKET_SCHEMA,
        "snapshot_id": replay.manifest["snapshot_id"],
        "profile": replay.manifest["profile"],
        "privileged_disclosure": True,
        "main_selection_trajectory_included": False,
        "main_queries_included": False,
        "main_reading_order_included": False,
        "all_main_model_visible_web_bytes_included": True,
        "live_network_available": False,
        "documents": documents,
    }
    packet["packet_hash"] = hash_json(packet)
    return packet


def _policy_from_dict(value: object) -> WebPolicy:
    if not isinstance(value, dict):
        raise HarnessError("Web snapshot policy is malformed")
    expected = {
        "enabled",
        "allowed_hosts",
        "allow_subdomains",
        "max_requests",
        "max_redirects",
        "max_raw_bytes",
        "max_delivered_bytes",
        "timeout_seconds",
        "allowed_content_types",
        "user_agent",
    }
    if set(value) != expected:
        raise HarnessError("Web snapshot policy fields are not canonical")
    if type(value["enabled"]) is not bool or type(value["allow_subdomains"]) is not bool:
        raise HarnessError("Web snapshot policy booleans are malformed")
    for key in (
        "max_requests",
        "max_redirects",
        "max_raw_bytes",
        "max_delivered_bytes",
        "timeout_seconds",
    ):
        minimum = 0 if key == "max_redirects" else 1
        if (
            not isinstance(value[key], int)
            or isinstance(value[key], bool)
            or value[key] < minimum
        ):
            raise HarnessError(f"Web snapshot policy {key} is malformed")
    for key in ("allowed_hosts", "allowed_content_types"):
        if not isinstance(value[key], list) or any(
            not isinstance(item, str) or not item for item in value[key]
        ):
            raise HarnessError(f"Web snapshot policy {key} is malformed")
    if not isinstance(value["user_agent"], str) or not value["user_agent"]:
        raise HarnessError("Web snapshot policy user_agent is malformed")
    try:
        policy = WebPolicy(
            enabled=value["enabled"],
            allowed_hosts=tuple(_canonical_host(host) for host in value["allowed_hosts"]),
            allow_subdomains=value["allow_subdomains"],
            max_requests=int(value["max_requests"]),
            max_redirects=int(value["max_redirects"]),
            max_raw_bytes=int(value["max_raw_bytes"]),
            max_delivered_bytes=int(value["max_delivered_bytes"]),
            timeout_seconds=int(value["timeout_seconds"]),
            allowed_content_types=tuple(value["allowed_content_types"]),
            user_agent=str(value["user_agent"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HarnessError("Web snapshot policy is malformed") from exc
    if policy.max_delivered_bytes > policy.max_raw_bytes:
        raise HarnessError("Web snapshot delivered-byte limit exceeds raw-byte limit")
    return policy


def validate_snapshot(root: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    root = root.resolve()
    paths = {
        "manifest": root / "manifest.json",
        "policy": root / "policy.json",
        "records": root / "records.json",
    }
    if any(not path.is_file() or path.is_symlink() for path in paths.values()):
        return False, ["snapshot is missing a regular manifest, policy, or records file"]
    try:
        manifest = load_json_object(paths["manifest"])
        policy_doc = load_json_object(paths["policy"])
        records = load_json(paths["records"])
        policy = _policy_from_dict(policy_doc)
    except HarnessError as exc:
        return False, [str(exc)]
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append("snapshot schema mismatch")
    body = dict(manifest)
    claimed = body.pop("snapshot_id", None)
    if claimed != hash_json(body):
        errors.append("snapshot_id mismatch")
    if manifest.get("policy") != policy_doc or manifest.get("policy_hash") != hash_file(paths["policy"]):
        errors.append("snapshot policy binding mismatch")
    if not isinstance(records, list) or records != manifest.get("records"):
        errors.append("snapshot records do not match the manifest")
        return False, errors
    if manifest.get("request_count") != len(records) or len(records) > policy.max_requests:
        errors.append("snapshot request count is invalid")
    expected_profile = "observed_url_cache_v1" if records else "no_web_observed_v1"
    if manifest.get("profile") != expected_profile:
        errors.append("snapshot profile is inconsistent with its records")
    if manifest.get("all_model_visible_bytes_recorded") is not True:
        errors.append("snapshot does not bind all model-visible bytes")
    if manifest.get("replay_live_web") is not False:
        errors.append("snapshot replay is not network-free")
    main_live = manifest.get("main_live_web")
    if type(main_live) is not bool:
        errors.append("snapshot main_live_web flag is malformed")
    expected_backend = (
        "hardened_live_https_v1"
        if main_live is True and records
        else "injected_or_unused_backend"
    )
    if manifest.get("capture_backend") != expected_backend:
        errors.append("snapshot capture backend is inconsistent")
    event_path = root / "events.jsonl"
    events: list[dict[str, Any]] = []
    if records:
        if not event_path.is_file() or event_path.is_symlink():
            errors.append("snapshot event ledger is missing")
        else:
            ledger = EventLedger(event_path)
            ok, ledger_errors = ledger.verify()
            if not ok:
                errors.extend(f"Web ledger: {error}" for error in ledger_errors)
            events = ledger.events()
            if manifest.get("event_log_hash") != hash_file(event_path):
                errors.append("snapshot event-log hash mismatch")
            if len(events) != 2 * len(records):
                errors.append("snapshot event count is not two per request")
    elif manifest.get("event_log_hash") is not None:
        errors.append("empty snapshot unexpectedly binds an event log")
    seen_ids: set[str] = set()
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            errors.append("snapshot contains a non-object record")
            continue
        body = dict(record)
        record_hash = body.pop("record_hash", None)
        if record_hash != hash_json(body):
            errors.append(f"Web record {index} hash mismatch")
        if record.get("sequence") != index:
            errors.append(f"Web record {index} sequence mismatch")
        request_id = record.get("request_id")
        if not isinstance(request_id, str) or request_id in seen_ids:
            errors.append(f"Web record {index} request ID is missing or duplicated")
        else:
            seen_ids.add(request_id)
        try:
            if canonicalize_url(str(record.get("requested_url")), policy) != record.get("requested_url"):
                errors.append(f"Web record {index} requested URL is not canonical")
            if canonicalize_url(str(record.get("final_url")), policy) != record.get("final_url"):
                errors.append(f"Web record {index} final URL is not canonical")
            redirects = record.get("redirect_chain")
            if not isinstance(redirects, list) or len(redirects) > policy.max_redirects:
                raise HarnessError("redirect chain is malformed")
            for redirect in redirects:
                if canonicalize_url(str(redirect), policy) != redirect:
                    raise HarnessError("redirect URL is not canonical")
        except HarnessError as exc:
            errors.append(f"Web record {index} URL is invalid: {exc}")
        headers = record.get("response_headers")
        if not isinstance(headers, dict) or headers != _filtered_headers(headers):
            errors.append(f"Web record {index} response headers are malformed")
        object_paths: dict[str, Path] = {}
        for key, suffix, limit in (
            ("raw_object", ".raw", policy.max_raw_bytes),
            ("model_visible_object", ".txt", policy.max_delivered_bytes),
        ):
            descriptor = record.get(key)
            if not isinstance(descriptor, dict):
                errors.append(f"Web record {index} lacks {key}")
                continue
            try:
                path = safe_child(root, str(descriptor.get("path", "")))
                if not path.is_file() or path.is_symlink():
                    raise HarnessError("object is not a regular file")
                if descriptor.get("hash") != hash_file(path):
                    errors.append(f"Web record {index} {key} hash mismatch")
                if descriptor.get("size_bytes") != path.stat().st_size or path.stat().st_size > limit:
                    errors.append(f"Web record {index} {key} size mismatch")
                digest = str(descriptor.get("hash", "")).removeprefix("sha256:")
                if descriptor.get("path") != f"objects/{digest}{suffix}":
                    errors.append(f"Web record {index} {key} path is not content addressed")
                object_paths[key] = path
            except (HarnessError, OSError) as exc:
                errors.append(f"Web record {index} {key} is invalid: {exc}")
        if {"raw_object", "model_visible_object"} <= set(object_paths):
            try:
                reconstructed = model_visible_bytes(
                    FetchResult(
                        requested_url=str(record["requested_url"]),
                        final_url=str(record["final_url"]),
                        status=int(record["status"]),
                        headers=dict(record["response_headers"]),
                        raw_body=object_paths["raw_object"].read_bytes(),
                        redirect_chain=tuple(record.get("redirect_chain", ())),
                        peer_ip=str(record.get("peer_ip", "")),
                    ),
                    policy,
                )
                if reconstructed != object_paths["model_visible_object"].read_bytes():
                    errors.append(
                        f"Web record {index} visible bytes do not reconstruct from raw bytes"
                    )
            except (HarnessError, KeyError, OSError, TypeError, ValueError) as exc:
                errors.append(f"Web record {index} reconstruction failed: {exc}")
        start_index = record.get("request_prestart_event_index")
        capture_index = record.get("capture_event_index")
        if (
            not isinstance(start_index, int)
            or isinstance(start_index, bool)
            or not isinstance(capture_index, int)
            or isinstance(capture_index, bool)
            or start_index < 0
            or capture_index < 0
            or capture_index >= len(events)
            or start_index >= len(events)
        ):
            errors.append(f"Web record {index} event indices are invalid")
        else:
            started = events[start_index]
            captured = events[capture_index]
            started_payload = started.get("payload")
            captured_payload = captured.get("payload")
            if not isinstance(started_payload, dict) or not isinstance(
                captured_payload, dict
            ):
                errors.append(f"Web record {index} event payloads are malformed")
            else:
                request_body = {
                    "request_id": record.get("request_id"),
                    "query": record.get("query"),
                    "url": record.get("requested_url"),
                }
                if (
                    started.get("event_type") != "web_request_started"
                    or started.get("event_hash")
                    != record.get("request_prestart_event_hash")
                    or started_payload.get("batch_id") != record.get("batch_id")
                    or started_payload.get("request_id") != record.get("request_id")
                    or started_payload.get("query_hash")
                    != hash_json({"query": record.get("query")})
                    or started_payload.get("canonical_url")
                    != record.get("requested_url")
                    or started_payload.get("request_hash") != hash_json(request_body)
                    or started_payload.get("credentials_forwarded") is not False
                    or started_payload.get("cookies_forwarded") is not False
                ):
                    errors.append(f"Web record {index} request event does not bind it")
                raw_descriptor = record.get("raw_object")
                visible_descriptor = record.get("model_visible_object")
                if (
                    captured.get("event_type") != "web_response_captured"
                    or captured.get("event_hash") != record.get("capture_event_hash")
                    or captured_payload.get("batch_id") != record.get("batch_id")
                    or captured_payload.get("request_id") != record.get("request_id")
                    or captured_payload.get("request_prestart_event_hash")
                    != record.get("request_prestart_event_hash")
                    or captured_payload.get("raw_hash")
                    != (
                        raw_descriptor.get("hash")
                        if isinstance(raw_descriptor, dict)
                        else None
                    )
                    or captured_payload.get("model_visible_hash")
                    != (
                        visible_descriptor.get("hash")
                        if isinstance(visible_descriptor, dict)
                        else None
                    )
                    or captured_payload.get("status") != record.get("status")
                    or captured_payload.get("final_url") != record.get("final_url")
                ):
                    errors.append(f"Web record {index} capture event does not bind it")
    return not errors, errors
