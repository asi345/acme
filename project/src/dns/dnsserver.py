from typing import List, Tuple

from dnslib import DNSRecord, textwrap
from dnslib.server import DNSLogger, DNSServer
from dnslib.zoneresolver import ZoneResolver


# DNS Server code in __init__ taken from dnslib examples with minor modifications


class ACMEDNS:
    def __init__(self, zone):
        self.resolver = ZoneResolver(textwrap.dedent(zone))
        self.dns_logger = DNSLogger(prefix=False)
        self.server = DNSServer(
            self.resolver, port=10053, address="localhost", logger=self.dns_logger
        )

    def start(self):
        self.server.start_thread()

    def stop(self):
        self.server.stop()

    def update_zone(self, new_zone: str):
        self.stop()
        self.resolver = ZoneResolver(textwrap.dedent(new_zone))
        self.server = DNSServer(
            self.resolver, port=10053, address="localhost", logger=self.dns_logger
        )
        self.start()


def build_dns_challenge_zones(domains: List[Tuple[str, str]],):
    zone = "\n".join([f'{domain}. 60 TXT "{key_auth}"' for domain, key_auth in domains])
    print(zone)
    return zone


def build_http_challenge_zones(domains: List[str], record: str):
    zone = "\n".join([f"{domain}. 60 A {record}" for domain in domains])
    print(zone)
    return zone


def test():
    zone1 = build_http_challenge_zones(["abc.com", "test.com"], record="1.2.3.4")

    s = ACMEDNS(zone1)
    s.start()
    q = DNSRecord.question("abc.com", qtype="A")
    a = q.send("localhost", 10053)
    print(DNSRecord.parse(a))

    zone2 = build_dns_challenge_zones(
        [("abc.com", "TEST_TOKEN1"), ("test.com", "TEST_TOKEN2")]
    )
    s.update_zone(zone2)
    q = DNSRecord.question("abc.com", qtype="TXT")
    a = q.send("localhost", 10053)
    print(DNSRecord.parse(a))

    s.stop()


if __name__ == "__main__":
    test()
