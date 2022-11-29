from collections import defaultdict
from asyncio import create_task

from mitmproxy.dns import DNSFlow
from mitmproxy.net.dns.types import A as DNS_A, AAAA as DNS_AAAA
from inotify.adapters import Inotify
from inotify.constants import IN_CLOSE_WRITE
from vyos.configquery import ConfigTreeQuery
from vyos.firewall import nft_update_set_elements


def get_updated_domain_map() -> dict[str, set[str]]:

    config = ConfigTreeQuery()
    domain_group_name_to_domains: dict[str, list[str]] = {
        domain_group_name: domain_group_config['address']
        for domain_group_name, domain_group_config in config.get_config_dict(
            path=['firewall', 'group', 'domain-group'],
            key_mangling=('-', '_'),
            get_first_key=True
        ).items()
    }

    domain_to_group_names: defaultdict[str, set[str]] = defaultdict(set)

    for domain_group_name , domains in domain_group_name_to_domains:
        for domain in domains:
            domain_to_group_names[domain].add(domain_group_name)

    return dict(domain_to_group_names)


class DNSProxy:

    def __int__(self):
        self._domain_to_group_names: dict[str, set[str]] = {}

    async def _monitor_config_changes(self):
        i = Inotify()
        i.add_watch(path_unicode='/opt/vyatta/etc/config/archive/commits', mask=IN_CLOSE_WRITE)

        for _ in i.event_gen(yield_nones=False):
            self._domain_to_group_names = get_updated_domain_map()

    async def running(self):
        create_task(self._monitor_config_changes())

    async def dns_response(self, flow: DNSFlow) -> None:

        domain_to_ip_addresses: defaultdict[str, set[str]] = defaultdict(set)

        for answer in flow.response.answers:
            answer_name: str = answer.name

            if answer_name not in self._domain_to_group_names:
                continue

            ip_address_set: set[str] = domain_to_ip_addresses[answer_name]

            if answer.type == DNS_A:
                ip_address_set.add(str(answer.ipv4_address))
            elif answer.type == DNS_AAAA:
                ip_address_set.add(str(answer.ipv6_address))

        for domain, ip_addresses in domain_to_ip_addresses.items():
            for group_name in self._domain_to_group_names[domain]:
                nft_update_set_elements(group_name=group_name, elements=ip_addresses)


addons = [DNSProxy()]


# for domain_group_name, domains in domain_group_name_to_domains.items():
#     ip_addresses: set[str] = set()
#
#     for domain in domains:
#         try:
#             sockaddr: tuple[str, int] | tuple[str, int, str, str, str]
#             for (_, _, _, sockaddr) in getaddrinfo(host=domain, port=None):
#                 ip_addresses.add(sockaddr[0])
#         except gaierror:
#             pass
#
#     if ip_addresses:
#         nft_update_set_elements(group_name=domain_group_name, elements=ip_addresses)
#
# time.sleep(timeout)
