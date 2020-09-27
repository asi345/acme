import argparse
import logging
import threading

from src.client.client import ACMEClient
from src.dns.dnsserver import ACMEDNS, build_http_challenge_zones
from src.httpservers.certdemoserver import start_demo_server
from src.httpservers.shutdownserver import start_shutdown_server
from src.logger import _setup_logger
from src.utils.utils import get_private_key, CERT_DIR, PRIVATE_KEY_DIR
from django.utils.text import slugify

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
    for order in orders:
        LOGGER.info(client.get_order(order))
    ready_order = client.dns_challenge(args.domain)
    cert_key, key_path = get_private_key(force_new=True, filename=slugify(ready_order.url_id))
    b64_csr = client.create_csr(args.domain, key=cert_key)
    finalized_order = client.finalize(ready_order, b64_csr)
    cert_path = client.download_cert(finalized_order, slugify(ready_order.url_id))

    dnsserver = ACMEDNS(build_http_challenge_zones(args.domain, args.record))
    dnsserver.start()

    shutdown_thread = threading.Thread(target=start_shutdown_server)
    demo_thread = threading.Thread(target=start_demo_server, args=(cert_path, key_path, args.domain[0]))

    shutdown_thread.start()
    demo_thread.start()

    demo_thread.join()
    shutdown_thread.join()


    # orders = client.list_orders()
    # print(orders)
    # new_order = client.create_order(args.domain)
    # order = client.get_order(orders[0])
    # authorization_urls = order.authorizations
    # auth = client.get_authorization(authorization_urls[0])
    # challenge = client.get_challenge(auth.challenges[0].url)

    # data = json.loads(ro.text)
    # trans.post_as_get(data["authorizations"][0])
    # key_auth = trans.jwk.get_key_authorization("123")
    # print(key_auth)


if __name__ == "__main__":
    _setup_logger(logging.DEBUG)
    main()
