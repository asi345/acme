import json
import logging
from hashlib import sha256
from pathlib import Path
from time import sleep
from typing import List, Optional, Dict

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPrivateKeyWithSerialization
from cryptography.x509.oid import NameOID
from requests import Response

from src.client.structs import (
    ACMEOrder,
    ACMEAccount,
    ACMEAuthorization,
    ACMEChallenge,
    ChallengeType,
    OrderStatus,
)
from src.communication.transport import TransportHelper
from src.dns.dnsserver import build_dns_challenge_zones, ACMEDNS
from src.utils.utils import (
    ACME_ENDPOINT_NEW_ORDER,
    _b64_encode_bytes,
    write_certfile,
    ACME_ENDPOINT_REVOKE,
)

LOGGER = logging.getLogger(__name__)


class ACMEClient:
    def __init__(
        self, server,
    ):
        self.server = server
        self.transport = TransportHelper(server=self.server)
        self.dns = None  # type: Optional[ACMEDNS]

    @staticmethod
    def _process_response(resp: Response) -> Dict:
        data = resp.json()
        data.update({"url_id": resp.url})
        return data

    def create_order(self, domains: List[str]) -> ACMEOrder:
        resp = self.transport.post(
            url=self.server + ACME_ENDPOINT_NEW_ORDER,
            content={
                "identifiers": [{"type": "dns", "value": domain} for domain in domains]
            },
        )

        # we are interested in the actual location of our order not
        # the newOrder url
        resp.url = resp.headers["Location"]
        return ACMEOrder.from_json(ACMEClient._process_response(resp))

    def get_account(self) -> ACMEAccount:
        resp = self.transport.post_as_get(url=self.transport.account_url)
        return ACMEAccount.from_json(ACMEClient._process_response(resp))

    def list_orders(self) -> List[str]:
        resp = self.transport.post_as_get(url=self.get_account().orders)
        return json.loads(resp.text)["orders"]

    def get_order(self, url) -> ACMEOrder:
        resp = self.transport.post_as_get(url=url)
        return ACMEOrder.from_json(ACMEClient._process_response(resp))

    def get_authorization(self, url) -> ACMEAuthorization:
        resp = self.transport.post_as_get(url=url)
        return ACMEAuthorization.from_json(ACMEClient._process_response(resp))

    def get_challenge(self, url) -> ACMEChallenge:
        resp = self.transport.post_as_get(url=url)
        return ACMEChallenge.from_json(ACMEClient._process_response(resp))

    def get_challenge_status(self, url):
        challenge = self.get_challenge(url)
        return challenge.status

    def create_csr(
        self, domains: List[str], key: RSAPrivateKeyWithSerialization
    ) -> str:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Zurich"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetSec ETHZ"),
                        # x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(domain) for domain in domains]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256(), backend=default_backend(),)
        )

        s = _b64_encode_bytes(
            csr.public_bytes(encoding=serialization.Encoding.DER)
        ).decode("utf-8")

        return s

    def dns_challenge(self, domains: List[str]) -> ACMEOrder:
        order = self.create_order(domains)
        self.dns = ACMEDNS()
        for auth in order.authorizations:
            # we need to fulfill all authorizations here
            authorization = self.get_authorization(auth)
            domain = authorization.identifier["value"]
            for chal in authorization.challenges:
                if chal.type == ChallengeType.DNS01:
                    key_auth = self.transport.jwk.get_key_authorization(chal.token)
                    b64_key_auth = _b64_encode_bytes(
                        sha256(key_auth.encode("utf-8")).digest()
                    ).decode("utf-8")
                    dns_zone = build_dns_challenge_zones([(domain, b64_key_auth)])
                    self.dns.update_zone(dns_zone)

                    # Querrying DNS records for debugging here
                    # q = DNSRecord.question(f"_acme-challenge.{domain}", qtype="TXT")
                    # a = q.send("localhost", 10053)
                    # LOGGER.debug(DNSRecord.parse(a))

                    # notify ACME server that DNS is ready
                    self.transport.post(url=chal.url, content={})
                    sleep(5)
                    LOGGER.info(
                        f"Challenge status for {domain}:{self.get_challenge_status(chal.url)}"
                    )

        # stop DNS server after challenges were performed
        self.dns.stop()
        # update order object and return
        return self.get_order(order.url_id)

    def finalize(self, order: ACMEOrder, b64_csr: str) -> ACMEOrder:
        resp = self.transport.post(url=order.finalize, content={"csr": b64_csr})
        LOGGER.debug(resp.text)
        resp.url = resp.headers["Location"]
        return ACMEOrder.from_json(ACMEClient._process_response(resp))

    def download_cert(self, order: ACMEOrder, cert_filename: str) -> Path:
        for _ in range(3):
            order = self.get_order(order.url_id)
            if order.status == OrderStatus.VALID:
                break
            else:
                # wait until the server is ready
                sleep(2)
        resp = self.transport.post_as_get(url=order.certificate)
        LOGGER.debug(resp.text)

        return write_certfile(resp.content, filename=cert_filename)

    def revoke_cert(self, cert_path: Path):
        cert = x509.load_pem_x509_certificate(
            cert_path.open("rb").read(), backend=default_backend()
        )
        LOGGER.debug("Sending revoke request certificate...")
        resp = self.transport.post(
            self.server + ACME_ENDPOINT_REVOKE,
            content={
                "certificate": _b64_encode_bytes(
                    cert.public_bytes(serialization.Encoding.DER)
                ).decode("utf-8")
            },
        )
