BAD_NONCE_RESPONSE = "urn:ietf:params:acme:error:badNonce"
ALREADY_REVOKED_RESPONSE = "urn:ietf:params:acme:error:alreadyRevoked"


class MissingJWKandKID(Exception):
    pass
