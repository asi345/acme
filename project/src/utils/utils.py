import base64
import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)

SRC_DIR = Path(__file__).parent.parent.parent.resolve()
DATA_DIR = SRC_DIR / "data"


def _b64_encode_bytes(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def b64_encode(data: str, drop_padding=True) -> str:
    return _b64_encode_bytes(data.encode("utf-8")).decode("utf-8")
