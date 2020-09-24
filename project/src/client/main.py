import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from jose import jws

from src.utils.utils import DATA_DIR

ACME_SERVER = "localhost"
ACME_PORT = "14000"


def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    with (DATA_DIR / "private.pem").open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    b"passphrase"
                ),
            )
        )
    with (DATA_DIR / "public.pem").open("wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    message = b"A message I want to sign"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    print(base64.urlsafe_b64encode(signature))
    print(public_key)

    public_key.verify(
        signature=signature,
        data=message,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256(),
    )


"""
{
     "protected": base64url({
       "alg": "ES256",
       "jwk": {...},
       "nonce": "6S8IqOGY7eL2lsGoTZYifg",
       "url": "https://example.com/acme/new-account"
     }),
     "payload": base64url({
       "termsOfServiceAgreed": true,
       "contact": [
         "mailto:cert-admin@example.org",
         "mailto:admin@example.org"
       ]
     }),
     "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
}
"""


def test_jwt():
    private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
    public_key = private_key.public_key()

    print()

    protected_headers_dict = {
        "alg": "ES256",
        "jwk": {...},
        "nonce": "bKYkcJpvMPArZ3QEIUg2bw",
        "url": "https://0.0.0.0:14000/nonce-plz",
    }
    payload_dict = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:cert-admin@example.org", "mailto:admin@example.org"],
    }
    base64.b64encode()
    complete_payload = {}


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
    # generate_private_key()
    test_jwt()
