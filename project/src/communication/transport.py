import json
import logging
from typing import Optional, Dict

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from requests import Response, HTTPError
from requests.exceptions import SSLError

from src.communication.jwf import JWSProtectedHeader, JWK, JWSPayload, JWSBody
from src.utils.exceptions import BAD_NONCE_RESPONSE
from src.utils.utils import (
    ACME_ENDPOINT_NONCE,
    ACME_ENDPOINT_REGISTER,
    get_private_key,
    SRC_DIR,
    ACME_ENDPOINT_DIR,
)


LOGGER = logging.getLogger(__name__)


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
            self.private_key, self.private_key_path = get_private_key()
        self.jwk = None
        self.kid = "2"  # TODO: replace with uuid

        LOGGER.info("Registering for new ACME account.")
        self._verify_server_cert()
        self._register()

    def _verify_server_cert(self):
        LOGGER.info("Verifying ACME server certificate...")
        try:
            resp = self.get(url=self.server + ACME_ENDPOINT_DIR)
            LOGGER.debug(resp.text)
        except SSLError as e:
            LOGGER.critical(
                f"SSL Verification for {self.server} failed. Terminating..."
            )
            exit(0)

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
        LOGGER.debug(f"Status code for {url} is {r.status_code}")
        LOGGER.debug(f"Headers: {r.headers}")
        LOGGER.debug(f"Content: {r.text}")

        if "Replay-Nonce" in r.headers:
            new_nonce = r.headers["Replay-Nonce"]
            LOGGER.debug(f"New nonce from response: {new_nonce}")
            self.last_nonces.add(new_nonce)

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
        retry_count: int = 0,
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
        try:
            r = self._post(url, *body.get_request_elements())
            r.raise_for_status()
            return r
        except HTTPError as e:
            if retry_count >= 3:
                raise ConnectionError(f"Max retries exceeded for {url}")

            if r.status_code == 404:
                raise ConnectionError(f"404 Page not found for {url}")

            r_content = json.loads(r.text)
            if r_content["type"] == BAD_NONCE_RESPONSE:
                # retry request once
                error_nonce = r.headers["Replay-Nonce"]
                LOGGER.debug(
                    f"Error due to wrong nonce. Retrying with nonce from response: {error_nonce}"
                )
                proteced_header.nonce = error_nonce
                LOGGER.warning(f"Request for {url} retrying now...")
                return self.post(url, content, proteced_header, retry_count + 1)

    def get(self, url: str) -> Response:
        return self.session.get(url)

    def post_as_get(
        self, url: str, protected_header_override: JWSProtectedHeader = None
    ):
        return self.post(
            url, content=None, protected_header_override=protected_header_override
        )

    def _get_nonce(self) -> None:
        assert self.server.endswith("/")
        r = self.session.get(self.server + ACME_ENDPOINT_NONCE)
        r.raise_for_status()
        nonce = r.headers["Replay-Nonce"]
        LOGGER.debug(f"Nonce received: {nonce}")
        self.last_nonces.add(nonce)

    @property
    def nonce(self):
        if not self.last_nonces:
            self._get_nonce()
        return self.last_nonces.pop()
