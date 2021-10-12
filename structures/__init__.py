from dataclasses import dataclass
from typing import Optional


@dataclass
class BodyLogEntry:
    bytes: int
    content: Optional[str] = None


@dataclass
class ResponseLogEntry:
    body: BodyLogEntry
    bytes: int
    status_code: int
    mime_type: Optional[str] = None


@dataclass
class RequestLogEntry:
    bytes: int
    method: str
    mime_type: Optional[str] = None
    body: Optional[BodyLogEntry] = None
    referrer: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class HttpLogEntry:
    request: RequestLogEntry
    response: ResponseLogEntry
    version: str


@dataclass
class UrlLogEntry:
    domain: str
    full: str
    original: str
    path: str
    port: int
    scheme: str
    subdomain: str
    top_level_domain: str
    extension: Optional[str] = None
    fragment: Optional[str] = None
    password: Optional[str] = None
    username: Optional[str] = None
    query: Optional[str] = None


@dataclass
class LogEntry:
    http: HttpLogEntry
    url: UrlLogEntry
