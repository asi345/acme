from typing import List

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


def build_zones(domains: List[str], record: str):
    pass


def test():
    zone1 = """
    abc.def. 60 A 1.2.3.4
    abc.com. 60 A 1.2.3.4
    abc.com. 60 TXT "TEST1"
    """

    s = ACMEDNS(zone1)
    s.start()
    q = DNSRecord.question("abc.com", qtype="A")
    a = q.send("localhost", 10053)
    print(DNSRecord.parse(a))

    zone2 = """
            abc.def. 60 A 4.5.6.7
            abc.com. 60 A 4.5.6.7
            abc.com. 60 TXT "TEST2"
            """
    s.update_zone(zone2)
    q = DNSRecord.question("abc.com", qtype="A")
    a = q.send("localhost", 10053)
    print(DNSRecord.parse(a))

    s.stop()


if __name__ == "__main__":
    test()
