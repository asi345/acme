import logging
from typing import List, Optional, Tuple, Dict

import flask
from flask import Flask, abort

CHALLENGE_TOKENS = dict()  # type:  Dict[str]

LOGGER = logging.getLogger(__name__)


def create_challenge_app(tokens: List[Dict[str, str]]):
    app = Flask(__name__)

    global CHALLENGE_TOKENS
    for token in tokens:
        CHALLENGE_TOKENS.update(token)

    @app.route("/.well-known/acme-challenge/<string:token>", methods=["GET"])
    def token_reply(token: str):
        if token not in CHALLENGE_TOKENS:
            abort(404, "Token not found in challenge list")
        else:
            resp = flask.Response(CHALLENGE_TOKENS[token])
            resp.headers["Content-Type"] = "application/octet-stream"
            return resp

    return app


def start_challenge_server(host="0.0.0.0", tokens: List[Dict[str, str]] = None):
    if tokens:
        LOGGER.debug(f"Starting HTTP challenge server with tokens {tokens}")
        app = create_challenge_app(tokens)
        app.run(host=host, port=5002)
    else:
        raise ValueError("Requires list of tokens to deploy challenge server.")
