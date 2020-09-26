import json
from typing import List

from src.client.structs import ACMEOrder, ACMEAccount, ACMEAuthorization, \
    ACMEChallenge
from src.communication.transport import TransportHelper
from src.utils.utils import ACME_ENDPOINT_NEW_ORDER, ACME_ENDPOINT_LIST_ORDER


class ACMEClient:
    def __init__(
        self, server,
    ):
        self.server = server
        self.transport = TransportHelper(server=self.server)

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
