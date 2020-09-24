import binascii
import json
import uuid
from dataclasses import dataclass, field

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKeyWithSerialization,
    RSAPublicKeyWithSerialization,
    RSAPublicNumbers,
)

from src.utils.utils import b64_encode, DATA_DIR, SRC_DIR, _b64_encode_bytes


class JWFBaseClass:
    _data = dict()

    def _to_data(self):
        raise NotImplemented

    @property
    def data(self):
        self._to_data()
        return self._data

    @data.setter
    def data(self, value: dict):
        self._data = value

    def to_json(self) -> str:
        return json.dumps(self.data)

    def to_b64json(self, encoding: str = "utf-8") -> str:
        return b64_encode(self.to_json())


@dataclass
class JWK(JWFBaseClass):
    """
    JSON Web Key
    """

    key_type: str = field()
    curve: str = field()
    private_key: RSAPrivateKeyWithSerialization = field()
    kid: str = field(default=str(uuid.uuid4()))

    @property
    def public_key(self) -> RSAPublicKeyWithSerialization:
        return self.private_key.public_key()

    @property
    def public_numbers(self) -> RSAPublicNumbers:
        return self.public_key.public_numbers()

    def _to_data(self) -> None:
        exponent = f"{self.public_key.public_numbers().e:x}"
        modulus = f"{self.public_key.public_numbers().n:x}"

        if len(exponent) % 2:
            # if exponent is not an even number of hex digits make it even by prepending a 0
            exponent = f"0{exponent}"

        if len(modulus) % 2:
            # if exponent is not an even number of hex digits make it even by prepending a 0
            modulus = f"0{modulus}"

        self.data = {
            "kty": self.key_type,
            "n": _b64_encode_bytes(binascii.unhexlify(modulus)).decode("utf-8"),
            "e": _b64_encode_bytes(binascii.unhexlify(exponent)).decode("utf-8"),
            "kid": self.kid,
            "alg": "RS256",
        }


@dataclass
class JWSProtectedHeader(JWFBaseClass):
    algorithm: str = field()
    nonce: str = field()
    url: str = field()
    jwk: JWK = field()

    def _to_data(self) -> None:
        self.data = {
            "alg": self.algorithm,
            "nonce": self.nonce,
            "url": self.url,
            "jwk": self.jwk.data,
        }


class JWSPayload(JWFBaseClass):
    payload_data = dict()

    def _to_data(self):
        self.data = self.payload_data


@dataclass
class JWSBody(JWFBaseClass):
    header: JWSProtectedHeader = field()
    payload: JWSPayload = field()
    signature: str = field(default=None)

    def _to_data(self):
        tmp = dict()
        tmp.update(header.data)
        tmp.update(payload.data)
        tmp.update({"signature": self._create_signature()})
        self.data = tmp

    def header_payload_b64json(self, encoding: str = "utf-8") -> str:
        return f"{self.header.to_b64json(encoding)}.{self.payload.to_b64json(encoding)}"

    def _create_signature(self):
        signature = self.header.jwk.private_key.sign(
            data=self.header_payload_b64json(encoding="utf-8").encode("utf-8"),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256(),
        )

        b64_sig = _b64_encode_bytes(signature)

        # this only works if we do not remove trailing '==' signs
        # self.header.jwk.public_key.verify(
        #     signature=base64.urlsafe_b64decode(b64_sig),
        #     data=self.header_payload_b64json(encoding="utf-8").encode("utf-8"),
        #     padding=padding.PKCS1v15(),
        #     algorithm=hashes.SHA256(),
        # )

        return b64_sig.decode("utf-8")

    def to_b64json(self, encoding: str = "utf-8") -> str:
        return f"{self.header_payload_b64json('utf-8')}.{self._create_signature()}"


if __name__ == "__main__":
    # private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
    if not (DATA_DIR / "private.pem").exists():
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        with (DATA_DIR / "private.pem").open("wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        with (DATA_DIR / "private.pem").open("rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    # print(
    #     private_key.public_key()
    #     .public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #     )
    #     .decode("utf-8")
    # )
    # print(
    #     private_key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.PKCS8,
    #         encryption_algorithm=serialization.NoEncryption(),
    #     ).decode("utf-8")
    # )

    r = requests.get(
        "https://localhost:14000/nonce-plz", verify=str(SRC_DIR / "pebble.minica.pem")
    )
    nonce = r.headers["Replay-Nonce"]
    print(nonce)

    jwk = JWK("RSA", "RS256", private_key, kid="1")

    # print(jwk.to_json())

    header = JWSProtectedHeader(
        "RS256", nonce, "https://localhost:14000/sign-me-up", jwk
    )
    payload = JWSPayload()
    payload.payload_data = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:certificates@example.org", "mailto:admin@example.org"],
    }
    body = JWSBody(header, payload)
    jws = body.to_b64json()

    print(body.to_json())

    print(jws)

    header, payload, sig = jws.split(".")

    t = {"protected": f"{header}", "payload": f"{payload}", "signature": f"{sig}"}

    header = {"Content-Type": "application/jose+json"}
    rp = requests.post(
        "https://localhost:14000/sign-me-up",
        data=json.dumps(t),
        verify=str(SRC_DIR / "pebble.minica.pem"),
        headers=header,
    )
    print(rp.status_code)
    print(rp.content.decode("utf-8"))

    print(json.dumps(t))
    print()
