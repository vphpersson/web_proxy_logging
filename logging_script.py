from dataclasses import asdict
from typing import Optional
from pathlib import Path
from json import dumps as json_dumps
from urllib.parse import urlparse, parse_qsl
from re import sub as re_sub
from datetime import datetime
from ipaddress import ip_address, IPv6Address
from gzip import decompress as gzip_decompress

from mitmproxy.http import HTTPFlow
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie
from public_suffix import DomainProperties
from user_agents import parse as user_agents_parse
from user_agents.parsers import UserAgent
from magic import from_buffer as magic_from_buffer

from structures import LogEntry, HttpLogEntry, RequestLogEntry, ResponseLogEntry, BodyLogEntry, UrlLogEntry, \
    ClientLogEntry, ServerLogEntry, UserAgentLogEntry, UserAgentOSLogEntry, UserAgentDeviceLogEntry, \
    NetworkLogEntry, EventLogEntry


class WebProxyLogger:

    def __init__(self):
        self._log_file = Path('http.log').open(mode='a+')

        self.public_suffix_list_trie = PublicSuffixListTrie.from_public_suffix_list_file(file=Path('public_suffix_list.dat'))

    def _build_log_entry(self, flow: HTTPFlow) -> LogEntry:

        event_created: datetime = datetime.now().astimezone()

        response_log_entry: Optional[ResponseLogEntry] = None
        event_end: Optional[datetime] = None
        if flow.response:
            response_raw_content: Optional[bytes] = flow.response.raw_content
            response_raw_headers = bytes(flow.response.headers)

            response_headers: dict[str, list[str]] = {
                key.replace('-', '_').lower(): (value if isinstance(value, list) else [value])
                for key, value in flow.response.headers.items()
            }

            response_log_entry = ResponseLogEntry(
                body=BodyLogEntry(
                    bytes=(len(response_raw_content) if response_raw_content is not None else 0),
                    content=None
                ),
                bytes=(
                    len(response_raw_headers)
                    + (len(response_raw_content) if response_raw_content is not None else 0)
                ),
                headers=response_headers or None,
                status_code=flow.response.status_code,
                mime_type=magic_from_buffer(
                    buffer=(response_raw_content or b''),
                    mime=True
                ).lower() if response_raw_content else None,
                mime_type_content_type=[
                    re_sub(pattern=r'; charset=.+$', repl='', string=content_type)
                    for content_type in (response_headers.get('content_type') or [])
                ]
            )

            event_end = (
                datetime.fromtimestamp(flow.request.timestamp_end).astimezone()
                if flow.request.timestamp_end else None
            )

        server_ip_address_str: Optional[str] = flow.server_conn.peername[0] if flow.server_conn.peername else None
        network_type: Optional[str] = None
        if server_ip_address_str is not None:
            network_type = 'ipv6' if isinstance(ip_address(server_ip_address_str), IPv6Address) else 'ipv4'

        request_raw_content: Optional[bytes] = flow.request.raw_content
        request_raw_headers = bytes(flow.request.headers)

        request_headers: dict[str, list[str]] = {
            key.replace('-', '_').lower(): (value if isinstance(value, list) else [value])
            for key, value in flow.request.headers.items()
        }

        request_mime_type = magic_from_buffer(buffer=(request_raw_content or b''), mime=True).lower()

        include_decompressed_request_content = False
        decompressed_request_content: Optional[bytes] = None
        if request_mime_type == 'application/gzip':
            try:
                decompressed_request_content: bytes = gzip_decompress(data=request_raw_content)
            except:
                pass
            else:
                decompressed_request_content_mime_type = magic_from_buffer(
                    buffer=(decompressed_request_content or b''),
                    mime=True
                ).lower()

                include_decompressed_request_content = 'octet-stream' not in (decompressed_request_content_mime_type or '')

        parsed_request_url = urlparse(url=flow.request.url)
        query_key_value_pairs: list[tuple[str, str]] = parse_qsl(
            qs=(parsed_request_url.query or ''),
            keep_blank_values=True
        )

        include_request_content: bool = 'octet-stream' not in (request_mime_type or '')

        domain_properties: DomainProperties = self.public_suffix_list_trie.get_domain_properties(domain=flow.request.host)

        user_agent_log_entry: Optional[UserAgentLogEntry] = None
        if user_agent_string := flow.request.headers.get('user-agent'):

            user_agent_log_entry = UserAgentLogEntry(original=user_agent_string)

            try:
                user_agent: UserAgent = user_agents_parse(user_agent_string=user_agent_string)
            except:
                pass
            else:
                user_agent_log_entry.device = (
                    UserAgentDeviceLogEntry(name=user_agent.device.family)
                    if user_agent.device.family != 'Other' else None
                )
                user_agent_log_entry.name = user_agent.browser.family
                user_agent_log_entry.os = UserAgentOSLogEntry(
                    family=user_agent.os.family,
                    version=user_agent.os.version_string
                )
                user_agent_log_entry.version = user_agent.browser.version_string

        return LogEntry(
            http=HttpLogEntry(
                request=RequestLogEntry(
                    bytes=(len(request_raw_headers) + (len(request_raw_content) if request_raw_content is not None else 0)),
                    headers=request_headers or None,
                    method=flow.request.method,
                    mime_type=request_mime_type if request_raw_content else None,
                    mime_type_content_type=[
                        re_sub(pattern=r'; charset=.+$', repl='', string=content_type)
                        for content_type in (request_headers.get('content_type') or [])
                    ] or None,
                    body=BodyLogEntry(
                        bytes=(len(request_raw_content) if request_raw_content is not None else 0),
                        content=(flow.request.get_text(strict=False) or None) if include_request_content else None,
                        decompressed_content=(
                            decompressed_request_content.decode(encoding='utf-8', errors='surrogateescape') or None
                        ) if include_decompressed_request_content else None
                    ),
                    referrer=flow.request.headers.get('referer')
                ),
                response=response_log_entry,
                version=flow.request.http_version.removeprefix('HTTP/')
            ),
            url=UrlLogEntry(
                domain=flow.request.host,
                full=flow.request.url,
                original=flow.request.url,
                path=flow.request.path,
                port=flow.request.port,
                scheme=flow.request.scheme,
                subdomain=domain_properties.subdomain,
                top_level_domain=domain_properties.effective_top_level_domain,
                extension=(
                    (
                        Path(re_sub(pattern=r'\?.+$', repl='', string=parsed_request_url.path)).suffix or ''
                    ).removeprefix('.') or None
                ),
                fragment=parsed_request_url.fragment or None,
                password=parsed_request_url.password,
                username=parsed_request_url.username,
                query=parsed_request_url.query or None,
                query_keys=[key for key, _ in query_key_value_pairs] or None,
                query_values=[value for _, value in query_key_value_pairs] or None,
            ),
            client=ClientLogEntry(
                address=flow.client_conn.peername[0],
                ip=flow.client_conn.peername[0],
                port=flow.client_conn.peername[1]
            ),
            server=ServerLogEntry(
                address=flow.request.host,
                ip=server_ip_address_str,
                port=flow.server_conn.peername[1] if flow.server_conn.peername else None
            ),
            network=NetworkLogEntry(
                protocol=flow.request.scheme,
                transport='tcp',
                type=network_type
            ),
            event=EventLogEntry(
                created=event_created,
                timezone=re_sub(pattern=r'^(.{3})(.{2}).*$', repl=r'\1:\2', string=f'{event_created:%z}'),
                start=datetime.fromtimestamp(flow.request.timestamp_start).astimezone(),
                end=event_end

            ),
            user_agent=user_agent_log_entry
        )

    async def request(self, flow: HTTPFlow) -> None:
        self._log_file.write(json_dumps(asdict(self._build_log_entry(flow=flow)), default=str))

    async def response(self, flow: HTTPFlow) -> None:
        self._log_file.write(json_dumps(asdict(self._build_log_entry(flow=flow)), default=str))


addons = [WebProxyLogger()]
