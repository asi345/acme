import json
import logging
from typing import Optional, Dict

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from requests import Response

from src.client.jwf import JWK, JWSProtectedHeader, JWSPayload, JWSBody
from src.utils.utils import (
    ACME_ENDPOINT_REGISTER,
    SRC_DIR,
    get_private_key,
    ACME_ENDPOINT_NONCE,
)

LOGGER = logging.getLogger(__name__)


ACME_DOMAIN = "localhost"
ACME_PORT = "14000"
ACME_SERVER = f"https://{ACME_DOMAIN}:{ACME_PORT}/"


class TransportHelper:
    def __init__(
        self, server: str, private_key: RSAPrivateKeyWithSerialization = None,
    ):
        self.server = server
        self.last_nonces = set()
        self.session = requests.Session()
        self.session.verify = str(SRC_DIR / "pebble.minica.pem")
        self.account_url = None
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = get_private_key()
        self.jwk = None
        self.kid = "2"  # TODO: replace with uuid

        LOGGER.info("Registering for new ACME account.")
        self._register()

    def _register(self):
        if not self.account_url:
            # account does not exist yet
            # TODO: ask the server whether it exists already
            registration_url = self.server + ACME_ENDPOINT_REGISTER

            registration_payload = {
                "termsOfServiceAgreed": True,
                "contact": [
                    "mailto:certificates@example.org",
                    "mailto:admin@example.org",
                ],
            }

            self.jwk = JWK("RSA", "RS256", self.private_key, kid=self.kid)
            protected_header = JWSProtectedHeader(
                "RS256", self.nonce, registration_url, jwk=self.jwk
            )
            r = self.post(
                registration_url,
                registration_payload,
                protected_header_override=protected_header,
            )

            self.account_url = r.headers["Location"]

    def _post(self, url: str, b64_header, b64_payload, b64_signature) -> Response:
        header = {"Content-Type": "application/jose+json"}
        r = self.session.post(
            url,
            data=json.dumps(
                {
                    "protected": f"{b64_header}",
                    "payload": f"{b64_payload}",
                    "signature": f"{b64_signature}",
                }
            ),
            headers=header,
        )
        print(r.status_code)
        print(r.headers)
        print(r.content.decode("utf-8"))
        r.raise_for_status()

        self.last_nonces.add(r.headers["Replay-Nonce"])

        return r

    def _get_protected_header(self, url: str) -> JWSProtectedHeader:
        return JWSProtectedHeader(
            "RS256", self.nonce, url, jwk=self.jwk, kid=self.account_url
        )

    def post(
        self,
        url: str,
        content: Optional[Dict],
        protected_header_override: JWSProtectedHeader = None,
    ) -> Response:
        """
        Create valid ACME post request content consisting of protected header,
        payload and signature.
        :param url
        :param content:
        :param protected_header_override: protected header to use instead of normal one
        :return: Response
        """
        if protected_header_override:
            proteced_header = protected_header_override
        else:
            proteced_header = self._get_protected_header(url)

        payload = JWSPayload(content)
        body = JWSBody(proteced_header, payload)
        print(body.to_json())
        return self._post(url, *body.get_request_elements())

    def get(self):
        pass

    def post_get(self, url: str, protected_header_override: JWSProtectedHeader = None):
        return self.post(url, content=None, protected_header_override=protected_header_override)

    def _get_nonce(self) -> None:
        assert self.server.endswith("/")
        r = self.session.get(self.server + ACME_ENDPOINT_NONCE)
        r.raise_for_status()
        self.last_nonces.add(r.headers["Replay-Nonce"])

    @property
    def nonce(self):
        if not self.last_nonces:
            self._get_nonce()
        return self.last_nonces.pop()


if __name__ == "__main__":
    # private_key = get_private_key()
    #
    # jwk = JWK("RSA", "RS256", private_key, kid="1")
    # header = JWSProtectedHeader(
    #     "RS256", get_nonce(ACME_SERVER), ACME_SERVER + ACME_ENDPOINT_REGISTER, jwk
    # )
    # payload = JWSPayload(
    #     payload_data=
    # )
    # body = JWSBody(header, payload)
    #
    # b64_header, b64_payload, b64_sig = body.get_request_elements()

    trans = TransportHelper(ACME_SERVER)
    r = trans.post(url="https://localhost:14000/list-orderz/1", content={})
