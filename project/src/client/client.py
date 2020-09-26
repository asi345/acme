import json
from hashlib import sha256
from time import sleep
from typing import List, Optional

from dnslib import DNSRecord

from src.client.structs import ACMEOrder, ACMEAccount, ACMEAuthorization, \
    ACMEChallenge, ChallengeType
from src.communication.transport import TransportHelper
from src.dns.dnsserver import build_dns_challenge_zones, ACMEDNS
from src.utils.utils import ACME_ENDPOINT_NEW_ORDER, ACME_ENDPOINT_LIST_ORDER, \
    b64_encode, _b64_encode_bytes


class ACMEClient:
    def __init__(
        self, server,
    ):
        self.server = server
        self.transport = TransportHelper(server=self.server)
        self.dns = None # type: Optional[ACMEDNS]

    def create_order(self, domains: List[str]) -> ACMEOrder:
        resp = self.transport.post(
            url=self.server + ACME_ENDPOINT_NEW_ORDER,
            content={
                "identifiers": [{"type": "dns", "value": domain} for domain in domains]
            },
        )

        return ACMEOrder.from_json(resp.text)

    def get_account(self) -> ACMEAccount:
        resp = self.transport.post_as_get(url=self.transport.account_url)
        return ACMEAccount.from_json(resp.text)

    def list_orders(self) -> List[str]:
        resp = self.transport.post_as_get(url=self.get_account().orders)
        return json.loads(resp.text)["orders"]

    def get_order(self, url) -> ACMEOrder:
        resp = self.transport.post_as_get(url=url)
        return ACMEOrder.from_json(resp.text)

    def get_authorization(self, url) -> ACMEAuthorization:
        resp = self.transport.post_as_get(url=url)
        return ACMEAuthorization.from_json(resp.text)

    def get_challenge(self, url)-> ACMEChallenge:
        resp = self.transport.post_as_get(url=url)
        return ACMEChallenge.from_json(resp.text)

    def get_challenge_status(self, url):
        challenge = self.get_challenge(url)
        return challenge.status

    def dns_challenge(self, domains:List[str]):
        order = self.create_order(domains)
        for auth in order.authorizations:
            # we need to fulfill all authorizations here
            authorization = self.get_authorization(auth)
            domain = authorization.identifier["value"]
            for chal in authorization.challenges:
                if chal.type == ChallengeType.DNS01:
                    key_auth = self.transport.jwk.get_key_authorization(chal.token)
                    b64_key_auth = _b64_encode_bytes(sha256(key_auth.encode("utf-8")).digest()).decode("utf-8")
                    dns_zone = build_dns_challenge_zones([(domain, b64_key_auth)])
                    print(dns_zone)
                    self.dns = ACMEDNS(dns_zone)
                    self.dns.start()

                    q = DNSRecord.question(f"_acme-challenge.{domain}", qtype="TXT")
                    a = q.send("localhost", 10053)
                    print(DNSRecord.parse(a))

                    r = self.transport.post(url=chal.url, content={})
                    print(r.text)
                    sleep(5)
                    print(self.get_challenge_status(chal.url))