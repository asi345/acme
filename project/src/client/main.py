import json

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization

from src.client.jwf import JWK, JWSProtectedHeader, JWSPayload, JWSBody
from src.utils.utils import ACME_ENDPOINT_REGISTER, SRC_DIR, get_private_key, get_nonce

ACME_DOMAIN = "localhost"
ACME_PORT = "14000"
ACME_SERVER = f"https://{ACME_DOMAIN}:{ACME_PORT}/"


class TransportHelper:
    def __init__(
        self,
        server: str,
        signing_algo: str,
        private_key: RSAPrivateKeyWithSerialization,
    ):
        self.server = server
        self.signing_algo = signing_algo
        self.nonces = list()
        self.private_key = private_key
        self.public_key = private_key.public_key()

    def _convert_to_jws(self, payload, new_account: bool = False):
        if not self.nonces:
            self._get_new_nonce()

        alg_header = {"alg": self.signing_algo}
        nonce_header = {"nonce": self.nonces.pop()}
        jws_header = {
            "payload": payload,
        }
        if new_account:
            jws_header["kid"] = self.public_key

    def _get_new_nonce(self):
        pass

    def post(self):
        pass

    def get(self):
        pass


if __name__ == "__main__":
    private_key = get_private_key()

    jwk = JWK("RSA", "RS256", private_key, kid="1")
    header = JWSProtectedHeader(
        "RS256", get_nonce(ACME_SERVER), ACME_SERVER + ACME_ENDPOINT_REGISTER, jwk
    )
    payload = JWSPayload(
        payload_data={
            "termsOfServiceAgreed": True,
            "contact": ["mailto:certificates@example.org", "mailto:admin@example.org"],
        }
    )
    body = JWSBody(header, payload)

    b64_header, b64_payload, b64_sig = body.get_request_elements()
    t = {
        "protected": f"{b64_header}",
        "payload": f"{b64_payload}",
        "signature": f"{b64_sig}",
    }

    header = {"Content-Type": "application/jose+json"}
    rp = requests.post(
        ACME_SERVER + ACME_ENDPOINT_REGISTER,
        data=json.dumps(t),
        verify=str(SRC_DIR / "pebble.minica.pem"),
        headers=header,
    )
    print(rp.status_code)
    print(rp.headers)
    print(rp.content.decode("utf-8"))
