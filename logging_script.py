from pathlib import Path
from json import dumps as json_dumps
from logging import Logger, getLogger, INFO
from logging.handlers import SysLogHandler
from ipaddress import ip_address, IPv6Address

from mitmproxy.http import HTTPFlow, Request as FlowRequest
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie

from ecs_py import Base, Client, Server, Source, Destination, Network
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


class WebProxyLogger:

    def __init__(self):
        self.public_suffix_list_trie = PublicSuffixListTrie.from_public_suffix_list_file(
            file=Path('public_suffix_list.dat')
        )

    @staticmethod
    def _request_base_from_flow(request_flow: FlowRequest) -> Base:
        return entry_from_http_message(
                http_message=HTTPRequest(
                    start_line=RequestLine(
                        http_version=request_flow.http_version,
                        method=request_flow.method,
                        request_target=request_flow.path
                    ),
                    headers=[
                        (field_name, field_value)
                        for field_name, field_value in request_flow.headers.items(multi=True)
                    ],
                    body=memoryview(request_flow.raw_content) if request_flow.raw_content else None
                )
            )

    # def request(self, flow: HTTPFlow) -> None:
    #
    #     try:
    #         base_entry = self._request_base_from_flow(request_flow=flow.request)
    #     except:
    #         LOG.exception(msg='An error occurred when attempting to log an HTTP request.')
    #     else:
    #         LOG.info(msg=json_dumps(base_entry.to_dict(), default=str))

    def response(self, flow: HTTPFlow) -> None:
        response_flow = flow.response

        try:
            request_base_entry = self._request_base_from_flow(request_flow=flow.request)

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
                    ],
                    body=memoryview(response_flow.raw_content) if response_flow.raw_content else None
                ),
                include_decompressed_body=True,

                public_suffix_list_trie=self.public_suffix_list_trie
            )

            base_entry = merge_ecs_entries(request_base_entry, response_base_entry)

            if flow.client_conn.peername:
                client_address, client_port = flow.client_conn.peername
                base_entry.client = Client(address=client_address, ip=client_address, port=client_port)

            network_type: str | None = None
            if flow.server_conn.peername:
                server_address, server_port = flow.server_conn.peername

                network_type = 'ipv6' if isinstance(ip_address(server_address), IPv6Address) else 'ipv4'

                base_entry.server = Server(address=flow.request.host, ip=server_address, port=server_port)
                base_entry.destination = Destination(address=flow.request.host, ip=server_address, port=server_port)

            if flow.server_conn.sockname:
                source_address, source_port = flow.server_conn.sockname

                base_entry.source = Source(address=source_address, ip=source_address, port=source_port)

            base_entry.network = Network(protocol=flow.request.scheme, transport='tcp', type=network_type)
        except:
            LOG.exception(msg='An error occurred when attempting to log an HTTP response.')
        else:
            LOG.info(msg=json_dumps(base_entry.to_dict(), default=str))


addons = [WebProxyLogger()]
