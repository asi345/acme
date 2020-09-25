import base64
import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)

SRC_DIR = Path(__file__).parent.parent.parent.resolve()
DATA_DIR = SRC_DIR / "data"

ACME_ENDPOINT_NONCE = "nonce-plz"
ACME_ENDPOINT_REGISTER = "sign-me-up"
ACME_ENDPOINT_ORDER = "order-plz"
ACME_ENDPOINT_REVOKE = "revoke-cert"
ACME_ENDPOINT_KEY_CHANGE = "rollover-account-key"
ACME_ENDPOINT_ACCOUNT = "my-account"
ACME_ENDPOINT_LIST_ORDER = "list-orderz"


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
