"""Explicit external-service and constrained-shell effects.

These actions are irreversible or externally visible.  Construction is pure;
execution requires an explicit backend and is captured as an opaque trace
boundary so replay never submits a flag or uploads bytes twice.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .actions import Action
from .architecture import CredentialReference
from .domain import EffectContract, Evidence, Scope
from .errors import ConstraintError, ProtocolError
from .expressions import Expr
from .trace import ReplayTube
from .transfers import RemoteArtifact, ShellCommandCodec


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path, maximum: int) -> tuple[str, int]:
    try:
        stat = path.stat()
    except OSError as error:
        raise ProtocolError(f"cannot inspect cached artifact {path}: {error}") from error
    if not path.is_file():
        raise ProtocolError(f"cached artifact is not a regular file: {path}")
    if stat.st_size > maximum:
        raise ConstraintError(f"cached artifact is {stat.st_size} bytes; maximum is {maximum}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ProtocolError(f"cannot read cached artifact {path}: {error}") from error
    return digest.hexdigest(), stat.st_size


def _origin(url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), parsed.netloc.lower()


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class _BoundedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(
        self,
        origin: tuple[str, str],
        maximum: int,
        *,
        allow_cross_origin: bool,
        allow_insecure_http: bool,
    ) -> None:
        self.origin = origin
        self.maximum = maximum
        self.allow_cross_origin = allow_cross_origin
        self.allow_insecure_http = allow_insecure_http
        self.count = 0
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        self.count += 1
        if self.count > self.maximum:
            raise urllib.error.HTTPError(
                newurl, code, f"redirect limit {self.maximum} exceeded", headers, fp
            )
        if not self.allow_cross_origin and _origin(newurl) != self.origin:
            raise urllib.error.HTTPError(newurl, code, "cross-origin redirect refused", headers, fp)
        if _origin(newurl)[0] != "https" and not self.allow_insecure_http:
            raise urllib.error.HTTPError(
                newurl, code, "HTTPS downgrade redirect refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _runtime_effect(
    runtime: Any,
    *,
    identity: str,
    input_digest: str,
    name: str,
    live: Callable[[], Any],
    encode: Callable[[Any], Mapping[str, Any]],
    decode: Callable[[Mapping[str, Any]], Any],
) -> Any:
    tube = runtime.tube
    if isinstance(tube, ReplayTube):
        raw = tube.consume_opaque(identity, input_digest)
        try:
            value = json.loads(raw.decode("utf-8"))
            return decode(value)
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as error:
            raise ProtocolError(f"recorded {name} result is malformed") from error
    trace = runtime.trace
    if trace is not None:
        trace.append(
            "opaque_start",
            operation=identity,
            details={"name": name, "inputs_sha256": input_digest},
        )
    result = live()
    if trace is not None:
        buffered = getattr(tube, "buffered_bytes", b"")
        trace.append(
            "opaque",
            json.dumps(encode(result), sort_keys=True, separators=(",", ":")).encode(),
            operation=identity,
            details={
                "name": name,
                "inputs_sha256": input_digest,
                "buffered_base64": base64.b64encode(buffered).decode("ascii"),
            },
        )
    return result


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    accepted: bool
    status: str
    message: str
    response_sha256: str
    backend: str
    idempotency_key: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "status": self.status,
            "message": self.message,
            "response_sha256": self.response_sha256,
            "backend": self.backend,
            "idempotency_key": self.idempotency_key,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SubmissionResult":
        return cls(
            bool(value["accepted"]),
            str(value["status"]),
            str(value["message"]),
            str(value["response_sha256"]),
            str(value["backend"]),
            str(value["idempotency_key"]),
            tuple(str(item) for item in value.get("evidence", ())),
        )


class CompetitionBackend(Protocol):
    name: str

    @property
    def identity(self) -> str: ...

    def submit(self, request: "SubmissionRequest") -> SubmissionResult: ...


@dataclass(frozen=True)
class SubmissionRequest(Action):
    endpoint: str
    challenge: str
    flag: str = field(repr=False)
    backend: CompetitionBackend
    credential: CredentialReference | None = None
    idempotency_key: str = ""
    authorized: bool = False
    deadline: float = 10.0
    max_response: int = 1024 * 1024
    target: Expr | None = None

    def __post_init__(self) -> None:
        if not self.authorized:
            raise ConstraintError(
                "competition submission is irreversible; set authorized=True explicitly"
            )
        if not self.endpoint or not self.challenge or not self.flag:
            raise ValueError("endpoint, challenge, and flag must not be empty")
        if not self.idempotency_key:
            raise ValueError("submission requires an explicit idempotency key")
        if self.deadline <= 0 or self.max_response <= 0:
            raise ValueError("submission deadline and response bound must be positive")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "competition-submission",
                "endpoint": self.endpoint,
                "challenge": self.challenge,
                "backend": self.backend.identity,
                "credential": self.credential.name if self.credential else None,
            }
        )

    @property
    def input_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity,
                "flag_sha256": hashlib.sha256(self.flag.encode()).hexdigest(),
                "idempotency_key": self.idempotency_key,
                "deadline": self.deadline,
                "max_response": self.max_response,
            }
        )

    def contract(self) -> EffectContract:
        reads = {"credential:reference"} if self.credential is not None else set()
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(reads),
            writes=frozenset({"competition:submission"}),
            scope=Scope.SERVICE,
            evidence=(
                Evidence(
                    "irreversible-effect",
                    "explicitly authorized one-shot competition submission",
                    self.backend.name,
                ),
            ),
        )

    def execute(self, runtime: Any) -> SubmissionResult:
        result = _runtime_effect(
            runtime,
            identity=self.identity,
            input_digest=self.input_digest,
            name=self.describe(),
            live=lambda: self.backend.submit(self),
            encode=SubmissionResult.to_dict,
            decode=SubmissionResult.from_dict,
        )
        if self.target is not None:
            runtime.bind(self.target, result.to_dict(), source=self.describe())
        return result

    def perform(self) -> SubmissionResult:
        return self.backend.submit(self)

    def describe(self) -> str:
        return (
            f"submit result for challenge {self.challenge!r} through "
            f"{self.backend.name} (idempotency {self.idempotency_key!r})"
        )


HTTPRequester = Callable[
    [urllib.request.Request, float, ssl.SSLContext],
    tuple[int, Mapping[str, str], bytes, str],
]


@dataclass(frozen=True)
class JSONCompetitionBackend:
    endpoint: str
    credential_resolver: Callable[[CredentialReference], str] | None = field(
        default=None, compare=False, repr=False
    )
    requester: HTTPRequester | None = field(default=None, compare=False, repr=False)
    token_header: str = "Authorization"
    verify_tls: bool = True
    name: str = "json-http"

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "endpoint": self.endpoint,
                "token_header": self.token_header,
                "verify_tls": self.verify_tls,
            }
        )

    def submit(self, request: SubmissionRequest) -> SubmissionResult:
        if request.endpoint != self.endpoint:
            raise ConstraintError("submission endpoint does not match backend")
        parsed = urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme != "https" and self.verify_tls:
            raise ConstraintError("verified competition submissions require HTTPS")
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": request.idempotency_key,
        }
        if request.credential is not None:
            if self.credential_resolver is None:
                raise ProtocolError("credential reference has no resolver")
            secret = self.credential_resolver(request.credential)
            headers[self.token_header] = secret
        body = json.dumps(
            {"challenge": request.challenge, "flag": request.flag},
            separators=(",", ":"),
        ).encode()
        http_request = urllib.request.Request(
            self.endpoint, data=body, headers=headers, method="POST"
        )
        context = (
            ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-out
        )
        if self.requester is None:
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=context),
                    _RejectRedirects(),
                )
                with opener.open(http_request, timeout=request.deadline) as response:
                    raw = response.read(request.max_response + 1)
                    status_code = response.status
                    response_headers = dict(response.headers.items())
                    final_url = response.geturl()
            except (OSError, urllib.error.URLError) as error:
                raise ProtocolError(f"submission request failed: {error}") from error
        else:
            status_code, received_headers, raw, final_url = self.requester(
                http_request, request.deadline, context
            )
            response_headers = dict(received_headers)
        if _origin(final_url) != _origin(self.endpoint):
            raise ProtocolError("competition submission redirect was refused")
        if len(raw) > request.max_response:
            raise ConstraintError("competition response exceeds configured bound")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProtocolError("competition response is not valid JSON") from error
        if not isinstance(decoded, dict):
            raise ProtocolError("competition response must be a JSON object")
        accepted = bool(decoded.get("accepted", 200 <= status_code < 300))
        message = str(decoded.get("message", ""))
        return SubmissionResult(
            accepted,
            str(decoded.get("status", status_code)),
            message,
            hashlib.sha256(raw).hexdigest(),
            self.name,
            request.idempotency_key,
            (
                f"HTTP {status_code} from {urllib.parse.urlsplit(final_url).netloc}",
                f"content-type {response_headers.get('Content-Type', '<unknown>')}",
            ),
        )


@dataclass(frozen=True, slots=True)
class WebArtifact:
    source_url: str
    final_url: str
    cache_path: str
    sha256: str
    size: int
    status: int
    content_type: str
    cache_hit: bool
    backend: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "final_url": self.final_url,
            "cache_path": self.cache_path,
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "content_type": self.content_type,
            "cache_hit": self.cache_hit,
            "backend": self.backend,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "WebArtifact":
        return cls(
            str(value["source_url"]),
            str(value["final_url"]),
            str(value["cache_path"]),
            str(value["sha256"]),
            int(value["size"]),
            int(value["status"]),
            str(value["content_type"]),
            bool(value["cache_hit"]),
            str(value["backend"]),
            tuple(str(item) for item in value.get("evidence", ())),
        )


class WebArtifactBackend(Protocol):
    name: str

    @property
    def identity(self) -> str: ...

    def acquire(self, request: "AcquireWebArtifact") -> WebArtifact: ...


@dataclass(frozen=True)
class AcquireWebArtifact(Action):
    """Acquire one content-addressed artifact through a bounded cache.

    The expected digest is mandatory.  A URL is discovery information; the
    digest is the artifact identity.  Construction performs no network or
    filesystem I/O, while execution records one opaque result boundary.
    """

    url: str
    expected_sha256: str
    cache_dir: str
    backend: WebArtifactBackend
    credential: CredentialReference | None = None
    deadline: float = 15.0
    max_size: int = 64 * 1024 * 1024
    max_redirects: int = 3
    allow_insecure_http: bool = False
    allow_cross_origin_redirects: bool = False
    target: Expr | None = None

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("web artifact URL must be absolute HTTP(S)")
        if parsed.scheme != "https" and not self.allow_insecure_http:
            raise ConstraintError(
                "plain HTTP artifact acquisition requires allow_insecure_http=True"
            )
        if self.credential is not None and parsed.scheme != "https":
            raise ConstraintError("credential references cannot be used over plain HTTP")
        if self.credential is not None and self.allow_cross_origin_redirects:
            raise ConstraintError("credential references require same-origin artifact redirects")
        digest = self.expected_sha256.lower()
        if len(digest) != 64 or any(item not in "0123456789abcdef" for item in digest):
            raise ValueError("expected_sha256 must be a hexadecimal SHA-256 digest")
        object.__setattr__(self, "expected_sha256", digest)
        if not self.cache_dir:
            raise ValueError("web artifact cache directory must not be empty")
        object.__setattr__(
            self,
            "cache_dir",
            str(Path(self.cache_dir).expanduser().resolve()),
        )
        if self.deadline <= 0 or self.max_size <= 0 or self.max_redirects < 0:
            raise ValueError("web artifact bounds must be positive")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "web-artifact",
                "url": self.url,
                "expected_sha256": self.expected_sha256,
                "cache_dir": self.cache_dir,
                "backend": self.backend.identity,
                "credential": self.credential.name if self.credential else None,
            }
        )

    @property
    def input_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity,
                "deadline": self.deadline,
                "max_size": self.max_size,
                "max_redirects": self.max_redirects,
                "allow_insecure_http": self.allow_insecure_http,
                "allow_cross_origin_redirects": self.allow_cross_origin_redirects,
            }
        )

    def contract(self) -> EffectContract:
        reads = {"network:web"}
        if self.credential is not None:
            reads.add("credential:reference")
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(reads),
            writes=frozenset({"filesystem:artifact-cache"}),
            scope=Scope.ARTIFACT,
            evidence=(
                Evidence(
                    "content-addressed-acquisition",
                    f"requires SHA-256 {self.expected_sha256}",
                    self.backend.name,
                ),
            ),
        )

    def execute(self, runtime: Any) -> WebArtifact:
        result = _runtime_effect(
            runtime,
            identity=self.identity,
            input_digest=self.input_digest,
            name=self.describe(),
            live=lambda: self.backend.acquire(self),
            encode=WebArtifact.to_dict,
            decode=WebArtifact.from_dict,
        )
        if self.target is not None:
            runtime.bind(self.target, result.to_dict(), source=self.describe())
        return result

    def perform(self) -> WebArtifact:
        return self.backend.acquire(self)

    def describe(self) -> str:
        return (
            f"acquire artifact {self.expected_sha256[:12]} from {self.url!r} "
            f"through {self.backend.name}"
        )


@dataclass(frozen=True)
class HTTPArtifactBackend:
    credential_resolver: Callable[[CredentialReference], str] | None = field(
        default=None, compare=False, repr=False
    )
    requester: HTTPRequester | None = field(default=None, compare=False, repr=False)
    token_header: str = "Authorization"
    verify_tls: bool = True
    name: str = "https-artifact"

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "token_header": self.token_header,
                "verify_tls": self.verify_tls,
            }
        )

    def acquire(self, request: AcquireWebArtifact) -> WebArtifact:
        cache_dir = Path(request.cache_dir)
        cache_path = cache_dir / request.expected_sha256
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise ProtocolError(f"cannot create artifact cache {cache_dir}: {error}") from error

        if cache_path.exists():
            cached_digest, cached_size = _file_sha256(cache_path, request.max_size)
            if cached_digest == request.expected_sha256:
                return WebArtifact(
                    request.url,
                    request.url,
                    str(cache_path),
                    cached_digest,
                    cached_size,
                    0,
                    "application/octet-stream",
                    True,
                    self.name,
                    ("verified content-addressed cache hit",),
                )

        headers: dict[str, str] = {"Accept": "application/octet-stream"}
        if request.credential is not None:
            if self.credential_resolver is None:
                raise ProtocolError("credential reference has no resolver")
            headers[self.token_header] = self.credential_resolver(request.credential)
        web_request = urllib.request.Request(request.url, headers=headers, method="GET")
        context = (
            ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-out
        )
        if self.requester is None:
            redirects = _BoundedRedirects(
                _origin(request.url),
                request.max_redirects,
                allow_cross_origin=request.allow_cross_origin_redirects,
                allow_insecure_http=request.allow_insecure_http,
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context),
                redirects,
            )
            try:
                with opener.open(web_request, timeout=request.deadline) as response:
                    content_length = response.headers.get("Content-Length")
                    if content_length is not None and int(content_length) > request.max_size:
                        raise ConstraintError(
                            "web artifact Content-Length exceeds configured bound"
                        )
                    raw = response.read(request.max_size + 1)
                    status = int(response.status)
                    response_headers = dict(response.headers.items())
                    final_url = response.geturl()
            except ConstraintError:
                raise
            except (OSError, ValueError, urllib.error.URLError) as error:
                raise ProtocolError(f"web artifact request failed: {error}") from error
        else:
            status, received_headers, raw, final_url = self.requester(
                web_request, request.deadline, context
            )
            response_headers = dict(received_headers)
        if not 200 <= status < 300:
            raise ProtocolError(f"web artifact request returned HTTP {status}")
        if len(raw) > request.max_size:
            raise ConstraintError("web artifact exceeds configured size bound")
        if not request.allow_cross_origin_redirects and _origin(final_url) != _origin(request.url):
            raise ProtocolError("cross-origin web artifact redirect was refused")
        if _origin(final_url)[0] != "https" and not request.allow_insecure_http:
            raise ProtocolError("web artifact redirected to insecure HTTP")

        digest = hashlib.sha256(raw).hexdigest()
        if digest != request.expected_sha256:
            raise ProtocolError(
                f"web artifact digest {digest} does not match expected {request.expected_sha256}"
            )

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{request.expected_sha256}.",
            suffix=".pwnx-download",
            dir=cache_dir,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, cache_path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

        return WebArtifact(
            request.url,
            final_url,
            str(cache_path),
            digest,
            len(raw),
            status,
            response_headers.get("Content-Type", "application/octet-stream"),
            False,
            self.name,
            (
                "verified expected SHA-256 before atomic cache publication",
                f"redirects permitted: {request.max_redirects}",
            ),
        )


class ShellSessionBackend(Protocol):
    name: str

    @property
    def identity(self) -> str: ...

    def execute(self, command: str, *, deadline: float) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ShellUploadResult:
    artifact: RemoteArtifact
    commands: int
    backend: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "commands": self.commands,
            "backend": self.backend,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ShellUploadResult":
        return cls(
            RemoteArtifact.from_dict(value["artifact"]),
            int(value["commands"]),
            str(value["backend"]),
            tuple(str(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True)
class ShellUploadAction(Action):
    data: bytes = field(repr=False)
    remote_path: str
    backend: ShellSessionBackend
    codec: ShellCommandCodec = field(default_factory=ShellCommandCodec)
    executable: bool = False
    deadline: float = 30.0
    max_size: int = 16 * 1024 * 1024
    max_response: int = 4096
    service_scope: str = "service:shell"
    connection_scope: str = "connection:shell"
    target: Expr | None = None

    def __post_init__(self) -> None:
        if not self.remote_path:
            raise ValueError("remote path must not be empty")
        if len(self.data) > self.max_size:
            raise ConstraintError("shell upload exceeds configured maximum")
        if self.deadline <= 0 or self.max_response <= 0:
            raise ValueError("shell upload deadline and response bound must be positive")
        self.codec.quote(self.remote_path)

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "shell-upload",
                "remote_path": self.remote_path,
                "backend": self.backend.identity,
                "codec": {
                    "dialect": self.codec.dialect,
                    "max_command_length": self.codec.max_command_length,
                },
                "service_scope": self.service_scope,
                "connection_scope": self.connection_scope,
            }
        )

    @property
    def input_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity,
                "data_sha256": hashlib.sha256(self.data).hexdigest(),
                "size": len(self.data),
                "executable": self.executable,
                "deadline": self.deadline,
                "max_size": self.max_size,
                "max_response": self.max_response,
            }
        )

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            writes=frozenset({"filesystem:remote", "shell:commands"}),
            invalidates=(f"remote.file.{self.remote_path}",),
            scope=Scope.SERVICE,
            evidence=(
                Evidence(
                    "shell-transfer-bound",
                    f"{len(self.data)} bytes through bounded shell commands",
                    self.backend.name,
                ),
            ),
        )

    def _perform(self) -> ShellUploadResult:
        commands = self.codec.upload_commands(
            self.data, self.remote_path, executable=self.executable
        )
        for command in commands:
            response = self.backend.execute(command, deadline=self.deadline)
            if len(response) > self.max_response:
                raise ConstraintError("shell upload command response exceeds configured bound")
        digest = hashlib.sha256(self.data).hexdigest()
        hash_command = self.codec.command(
            "sh",
            "-c",
            f"sha256sum -- {self.codec.quote(self.remote_path)}; "
            f"stat -c %s -- {self.codec.quote(self.remote_path)}",
        )
        evidence = self.backend.execute(hash_command, deadline=self.deadline)
        if len(evidence) > self.max_response:
            raise ConstraintError("shell upload verification exceeds configured bound")
        lines = evidence.decode("utf-8", "replace").splitlines()
        if len(lines) < 2:
            raise ProtocolError("shell upload verification response is incomplete")
        remote_digest = lines[0].split(maxsplit=1)[0]
        try:
            remote_size = int(lines[1])
        except ValueError as error:
            raise ProtocolError("shell upload remote size is invalid") from error
        if remote_digest != digest or remote_size != len(self.data):
            raise ProtocolError("shell upload verification does not match local data")
        artifact = RemoteArtifact(
            self.remote_path,
            digest,
            len(self.data),
            self.backend.name,
            self.service_scope,
            self.connection_scope,
            ("chunked shell upload and atomic rename",),
        )
        return ShellUploadResult(
            artifact,
            len(commands) + 1,
            self.backend.name,
            (f"verified SHA-256 {digest}",),
        )

    def execute(self, runtime: Any) -> ShellUploadResult:
        result = _runtime_effect(
            runtime,
            identity=self.identity,
            input_digest=self.input_digest,
            name=self.describe(),
            live=self._perform,
            encode=ShellUploadResult.to_dict,
            decode=ShellUploadResult.from_dict,
        )
        context = getattr(runtime, "context", None)
        invalidator = getattr(context, "invalidate", None)
        if callable(invalidator):
            invalidator(*self.contract().invalidates)
        if self.target is not None:
            runtime.bind(self.target, result.to_dict(), source=self.describe())
        return result

    def perform(self) -> ShellUploadResult:
        return self._perform()

    def describe(self) -> str:
        return (
            f"upload {len(self.data)} bytes to {self.remote_path!r} through "
            f"{self.backend.name} shell"
        )
