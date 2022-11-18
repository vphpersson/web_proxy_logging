from pathlib import Path
from json import dumps as json_dumps
from logging import Logger, getLogger, INFO
from logging.handlers import SysLogHandler
from ipaddress import ip_address, IPv6Address
from asyncio import get_event_loop
from datetime import datetime
from typing import cast

from mitmproxy.http import HTTPFlow, Request as FlowRequest, Response as FlowResponse
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie
from magic import from_buffer as magic_from_buffer

from ecs_py import Base, Client, Server, Source, Destination, Network, HttpBody, Event
from ecs_tools_py import entry_from_http_message, make_log_handler, merge_ecs_entries
from http_lib.structures.message import Request as HTTPRequest, RequestLine, Response as HTTPResponse, StatusLine


LOG: Logger = getLogger(__name__)

log_handler = make_log_handler(
    base_class=SysLogHandler,
    provider_name='mitm',
    generate_field_names=('event.timezone', 'host.name', 'host.hostname')
)(address='/dev/log')
log_handler.ident = 'mitm '

LOG.addHandler(hdlr=log_handler)
LOG.setLevel(level=INFO)

FLOW_ID_TO_REQUEST: dict[str, Base] = {}


class WebProxyLogger:

    def __init__(self):
        self.public_suffix_list_trie: PublicSuffixListTrie = PublicSuffixListTrie.from_public_suffix_list_file(
            file=Path('public_suffix_list.dat')
        )

    @staticmethod
    def _content_from_http_message_flow(http_message_flow: FlowRequest | FlowResponse) -> str | None:
        if raw_content := http_message_flow.raw_content:
            try:
                body_text = http_message_flow.text
                if len(body_text) < 4096:
                    return body_text
            except ValueError:
                if len(raw_content) < 4096:
                    return raw_content.decode(encoding='charmap')
        else:
            return None

    @staticmethod
    def _content_from_flow(flow: HTTPFlow) -> str | None:
        return WebProxyLogger._content_from_http_message_flow(http_message_flow=flow.response or flow.request)

    def _request_base_from_flow(self, flow: HTTPFlow) -> Base:

        request_flow = flow.request

        request_base_entry = entry_from_http_message(
            http_message=HTTPRequest(
                start_line=RequestLine(
                    http_version=request_flow.http_version,
                    method=request_flow.method,
                    request_target=request_flow.path
                ),
                headers=[
                    (field_name, field_value)
                    for field_name, field_value in request_flow.headers.items(multi=True)
                ]
            )
        )

        server_address: str = flow.server_conn.sni or flow.request.host
        server_address_info = dict()

        try:
            ip_address(address=server_address)
        except ValueError:
            if domain_properties := self.public_suffix_list_trie.get_domain_properties(domain=server_address):
                server_address_info = dict(
                    registered_domain=domain_properties.registered_domain or None,
                    subdomain=domain_properties.subdomain or None,
                    top_level_domain=domain_properties.effective_top_level_domain or None
                )

        if flow.client_conn.peername:
            client_ip_address, client_port = flow.client_conn.peername
            request_base_entry.client = Client(address=client_ip_address, ip=client_ip_address, port=client_port)

        network_type: str | None = None
        if flow.server_conn.peername:
            server_ip_address, server_port = flow.server_conn.peername

            network_type = 'ipv6' if isinstance(ip_address(server_ip_address), IPv6Address) else 'ipv4'

            request_base_entry.server = Server(
                address=server_address,
                ip=server_ip_address,
                port=server_port,
                **server_address_info
            )
            request_base_entry.destination = Destination(
                address=server_address,
                ip=server_ip_address,
                port=server_port,
                **server_address_info
            )

        if flow.server_conn.sockname:
            source_address, source_port = flow.server_conn.sockname
            request_base_entry.source = Source(address=source_address, ip=source_address, port=source_port)

        request_base_entry.network = Network(protocol=flow.request.scheme, transport='tcp', type=network_type)

        if raw_content := request_flow.raw_content:
            request_base_entry.http.request.mime_type = magic_from_buffer(buffer=raw_content)

        if (content := WebProxyLogger._content_from_http_message_flow(http_message_flow=request_flow)) is not None:
            request_base_entry.http.request.body = HttpBody(bytes=len(content), content=content)

        event_entry: Event = cast(
            Event,
            request_base_entry.get_field_value(field_name='event', create_namespaces=True)
        )
        event_entry.start = datetime.fromtimestamp(request_flow.timestamp_start).astimezone()

        return request_base_entry

    async def request(self, flow: HTTPFlow) -> None:
        try:
            base_entry = self._request_base_from_flow(flow=flow)
        except:
            LOG.exception(msg='An error occurred when attempting to parse a flow request.')
        else:
            FLOW_ID_TO_REQUEST[flow.id] = base_entry
            get_event_loop().call_later(
                delay=30,
                callback=lambda: (
                    LOG.info(msg=json_dumps(popped_base_entry.to_dict(), default=str))
                    if (popped_base_entry := FLOW_ID_TO_REQUEST.pop(flow.id, None))
                    else None
                )
            )

    def response(self, flow: HTTPFlow) -> None:
        response_flow = flow.response

        try:
            if not (request_base_entry := FLOW_ID_TO_REQUEST.pop(flow.id, None)):
                request_base_entry = self._request_base_from_flow(flow=flow)

            response_base_entry = entry_from_http_message(
                http_message=HTTPResponse(
                    start_line=StatusLine(
                        http_version=response_flow.http_version,
                        status_code=response_flow.status_code,
                        reason_phrase=response_flow.reason or None
                    ),
                    headers=[
                        (field_name, field_value)
                        for field_name, field_value in response_flow.headers.items(multi=True)
                    ]
                )
            )

            if raw_content := response_flow.raw_content:
                response_base_entry.http.response.mime_type = magic_from_buffer(buffer=raw_content,mime=True).lower()

            if (content := self._content_from_http_message_flow(http_message_flow=response_flow)) is not None:
                response_base_entry.http.response.body = HttpBody(bytes=len(content), content=content)

            if timestamp_end := response_flow.timestamp_end:
                event_entry: Event = cast(
                    Event,
                    request_base_entry.get_field_value(field_name='event', create_namespaces=True)
                )
                event_entry.start = datetime.fromtimestamp(timestamp_end).astimezone()

            base_entry = merge_ecs_entries(request_base_entry, response_base_entry)
        except:
            LOG.exception(msg='An error occurred when attempting to log an HTTP response.')
        else:
            LOG.info(msg=json_dumps(base_entry.to_dict(), default=str))


addons = [WebProxyLogger()]
