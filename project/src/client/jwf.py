import binascii
import json
import uuid
from dataclasses import dataclass, field
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKeyWithSerialization,
    RSAPublicKeyWithSerialization,
    RSAPublicNumbers,
)

from src.utils.exceptions import MissingJWKandKID
from src.utils.utils import (
    b64_encode,
    _b64_encode_bytes,
)


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
    algorithm: str = field()
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
            # if exponent is not an even number of hex digits make it even
            # by prepending 0
            exponent = f"0{exponent}"

        if len(modulus) % 2:
            # if exponent is not an even number of hex digits make it even
            # by prepending 0
            modulus = f"0{modulus}"

        self.data = {
            "kty": self.key_type,
            "n": _b64_encode_bytes(binascii.unhexlify(modulus)).decode("utf-8"),
            "e": _b64_encode_bytes(binascii.unhexlify(exponent)).decode("utf-8"),
            "kid": self.kid,
            "alg": self.algorithm,
        }


@dataclass
class JWSProtectedHeader(JWFBaseClass):
    algorithm: str = field()
    nonce: str = field()
    url: str = field()
    kid: str = field(default=None)
    jwk: JWK = field(default=None)

    def _to_data(self) -> None:
        if not self.kid and not self.jwk:
            raise MissingJWKandKID(
                "JWS Protected header requires JWK or KID, but got none."
            )
        if self.kid:
            # if a kid is present use this one
            self.data = {
                "alg": self.algorithm,
                "nonce": self.nonce,
                "url": self.url,
                "kid": self.kid,
            }
            return

        if self.jwk:
            self.data = {
                "alg": self.algorithm,
                "nonce": self.nonce,
                "url": self.url,
                "jwk": self.jwk.data,
            }



@dataclass
class JWSPayload(JWFBaseClass):
    payload_data: dict = field(default_factory=dict())

    def _to_data(self):
        self.data = self.payload_data


@dataclass
class JWSBody(JWFBaseClass):
    header: JWSProtectedHeader = field()
    payload: JWSPayload = field()
    signature: str = field(default=None)

    def _to_data(self):
        tmp = dict()
        tmp.update(self.header.data)
        tmp.update(self.payload.data)
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

    def get_request_elements(self) -> List[str]:
        """
        :return: triple of header, payload and signature in base64
        """
        return self.to_b64json().split(".")
