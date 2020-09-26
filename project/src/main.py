import json
import logging

from src.communication.transport import TransportHelper
from src.logger import _setup_logger
from src.utils.utils import ACME_ENDPOINT_ORDER


LOGGER = logging.getLogger("src.main")

ACME_DOMAIN = "pebble"
ACME_PORT = "14000"
ACME_SERVER = f"https://{ACME_DOMAIN}:{ACME_PORT}/"


def main():
    trans = TransportHelper(ACME_SERVER)
    r = trans.post_as_get(url=ACME_SERVER + "list-orderz/1")
    ro = trans.post(
        url=ACME_SERVER + ACME_ENDPOINT_ORDER,
        content={
            "identifiers": [
                {"type": "dns", "value": "www.example.org"},
                {"type": "dns", "value": "example.org"},
            ],
            "notBefore": "2016-01-01T00:04:00+04:00",
            "notAfter": "2016-01-08T00:04:00+04:00",
        },
    )

    data = json.loads(ro.text)
    trans.post_as_get(data["authorizations"][0])
    key_auth = trans.jwk.get_key_authorization("123")
    print(key_auth)



if __name__ == "__main__":
    _setup_logger(logging.DEBUG)
    main()
