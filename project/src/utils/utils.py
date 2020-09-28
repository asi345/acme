import base64
import logging
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization

LOGGER = logging.getLogger(__name__)

SRC_DIR = Path(__file__).parent.parent.parent.resolve()
DATA_DIR = SRC_DIR / "data"
PRIVATE_KEY_DIR = DATA_DIR / "priv"
CERT_DIR = DATA_DIR / "cert"
LOG_DIR = SRC_DIR / "logs"

ACME_ENDPOINT_DIR = "dir"
ACME_ENDPOINT_NONCE = "nonce-plz"
ACME_ENDPOINT_REGISTER = "sign-me-up"
ACME_ENDPOINT_NEW_ORDER = "order-plz"
ACME_ENDPOINT_REVOKE = "revoke-cert"
ACME_ENDPOINT_KEY_CHANGE = "rollover-account-key"
ACME_ENDPOINT_ACCOUNT = "my-account"
ACME_ENDPOINT_LIST_ORDER = "list-orderz"
ACME_ENDPOINT_ORDER = "my-order"
ACME_ENDPOINT_CHALLENGE = "chalZ"


def _b64_encode_bytes(data: bytes, drop_padding=True) -> bytes:
    if drop_padding:
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    else:
        return base64.urlsafe_b64encode(data)


def b64_encode(data: str, drop_padding=True) -> str:
    return _b64_encode_bytes(data.encode("utf-8"), drop_padding).decode("utf-8")


def _b64_decode_bytes(data: bytes) -> bytes:
    return base64.urlsafe_b64decode(data)


def b64_decode(data: str) -> str:
    return _b64_decode_bytes(data.encode("utf-8")).decode("utf-8")


def get_private_key(
    force_new: bool = False, filename: str = "private.pem"
) -> Tuple[RSAPrivateKeyWithSerialization, Path]:
    """
    Generate a private RSA key and save it in the data dir.
    :param force_new: If set to True a new key will be generated even if one exists already.
    :param filename: Filename to save or load private key to or from
    :return: generated or loaded private key
    """
    if not PRIVATE_KEY_DIR.exists():
        PRIVATE_KEY_DIR.mkdir(parents=True)

    if not filename.endswith(".pem"):
        filename = f"{filename}.pem"

    private_key_path = (PRIVATE_KEY_DIR / filename).resolve()

    if force_new or not private_key_path.exists():
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        with private_key_path.open("wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        with private_key_path.open("rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    return private_key, private_key_path


def write_certfile(data: bytes, filename: str) -> Path:
    if not CERT_DIR.exists():
        CERT_DIR.mkdir(parents=True)

    if not filename.endswith(".pem"):
        filename = f"{filename}.pem"

    cert_path = (CERT_DIR / filename).resolve()
    with cert_path.open("wb") as f:
        f.write(data)

    return cert_path
