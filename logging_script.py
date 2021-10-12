from dataclasses import asdict
from typing import Optional
from pathlib import Path
from json import dumps as json_dumps
from urllib.parse import urlparse
from re import sub as re_sub

from mitmproxy.http import HTTPFlow
from public_suffix.trie import PublicSuffixListTrie, PublicSuffixListTrieNode
from public_suffix import DomainProperties

from structures import LogEntry, HttpLogEntry, RequestLogEntry, ResponseLogEntry, BodyLogEntry, UrlLogEntry


class WebProxyLogger:

    def __init__(self):
        self._log_file = Path('http.log').open(mode='a')

        self.public_suffix_list_trie = PublicSuffixListTrie(
            root_node=PublicSuffixListTrieNode.from_public_suffix_list(
                rules=Path('public_suffix_list.dat').read_text().splitlines()
            )
        )

    def response(self, flow: HTTPFlow) -> None:

        request_raw_content: Optional[bytes] = flow.request.raw_content
        request_raw_headers = bytes(flow.request.headers)
        request_mime_type = flow.request.headers.get('content-type')

        parsed_request_url = urlparse(url=flow.request.url)

        response_raw_content: Optional[bytes] = flow.response.raw_content
        response_raw_headers = bytes(flow.response.headers)

        include_request_data = 'octet-stream' not in (request_mime_type or '')

        domain_properties: DomainProperties = self.public_suffix_list_trie.get_domain_properties(domain=flow.request.host)

        self._log_file.write(
            json_dumps(
                asdict(
                    LogEntry(
                        http=HttpLogEntry(
                            request=RequestLogEntry(
                                bytes=(len(request_raw_headers) + (len(request_raw_content) if request_raw_content is not None else 0)),
                                method=flow.request.method,
                                mime_type=request_mime_type,
                                body=BodyLogEntry(
                                    bytes=(len(request_raw_content) if request_raw_content is not None else 0),
                                    content=(flow.request.get_text(strict=False) or None) if include_request_data else None
                                ),
                                referrer=flow.request.headers.get('referer')
                            ),
                            response=ResponseLogEntry(
                                body=BodyLogEntry(
                                    bytes=(len(response_raw_content) if response_raw_content is not None else 0),
                                    content=None
                                ),
                                bytes=(len(response_raw_headers) + (len(response_raw_content) if response_raw_content is not None else 0)),
                                status_code=flow.response.status_code,
                                mime_type=flow.response.headers.get('content-type')
                            ),
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
                            extension=((Path(re_sub(pattern=r'\?.+$', repl='', string=parsed_request_url.path)).suffix or '').removeprefix('.') or None),
                            fragment=parsed_request_url.fragment or None,
                            password=parsed_request_url.password,
                            username=parsed_request_url.username,
                            query=parsed_request_url.query or None
                        )
                    )
                )
            )
        )


addons = [WebProxyLogger()]
