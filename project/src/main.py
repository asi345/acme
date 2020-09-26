import argparse
import logging

from src.client.client import ACMEClient
from src.logger import _setup_logger

LOGGER = logging.getLogger("src.main")


def setup_parser():
    parser = argparse.ArgumentParser(prog="acme-client")

    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument(
        "--dir",
        type=str,
        help="DIR_URL is the directory URL of the ACME server that should be used.",
    )
    parser.add_argument(
        "--record",
        type=str,
        help="IPv4_ADDRESS is the IPv4 address which must be returned by your "
        "DNS server for all A-record queries.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        action="append",
        help="DOMAIN  is the domain for  which to request the certificate.",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="If present, your application should immediately revoke the certificate after obtaining it.",
    )

    return parser


def main():
    p = setup_parser()
    args = p.parse_args()
    print(args)

    ACME_SERVER = args.dir.strip("dir")
    LOGGER.info(f"ACME_SERVER set to {ACME_SERVER}")

    client = ACMEClient(server=ACME_SERVER)
    orders = client.list_orders()
    print(orders)
    new_order = client.create_order(args.domain)
    order = client.get_order(orders[0])
    authorization_urls = order.authorizations
    auth = client.get_authorization(authorization_urls[0])
    challenge = client.get_challenge(auth.challenges[0].url)

    # data = json.loads(ro.text)
    # trans.post_as_get(data["authorizations"][0])
    # key_auth = trans.jwk.get_key_authorization("123")
    # print(key_auth)


if __name__ == "__main__":
    _setup_logger(logging.INFO)
    main()
