# Notes for the ACME project

## Pebble Server

The following endpoints are available:

```
keyChange: "https://0.0.0.0:14000/rollover-account-key"
newAccount: "https://0.0.0.0:14000/sign-me-up"
newNonce: "https://0.0.0.0:14000/nonce-plz"
newOrder: "https://0.0.0.0:14000/order-plz"
revokeCert: "https://0.0.0.0:14000/revoke-cert"
```

## ACME Protocol

### Account Creation

1. create asymmetric key pair
2. CSR (Certificate Signing Request) is signed with the generated private key
3. Receive `Account Object`?

About the signing of the JWS requests:

```
For newAccount requests, and for revokeCert requests authenticated by
a certificate key, there MUST be a "jwk" field.  This field MUST
contain the public key corresponding to the private key used to sign
the JWS.
```

`ES256` is an elliptic curve signing algorithm with SHA256 for hashing. [Example in Cryptography lib](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curve-signature-algorithms)

Example Payload to create new account:

```
{
     "protected": base64url({
       "alg": "ES256",
       "jwk": {...},
       "nonce": "6S8IqOGY7eL2lsGoTZYifg",
       "url": "https://example.com/acme/new-account"
     }),
     "payload": base64url({
       "termsOfServiceAgreed": true,
       "contact": [
         "mailto:cert-admin@example.org",
         "mailto:admin@example.org"
       ]
     }),
     "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
}
```

## JWT

[High level tutorial JWT](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3)

![JWS Token](https://miro.medium.com/max/1050/1*sz6bIndG2bTBGcZ8ocmM5Q.png)

Signature is computed over JOSE header and payload after they were base64 encoded and joint with a dot.

Signed with the private key corresponding to the advertised public key.

According to RFC8555 the JWS Protected Header must include:

1. `alg`
2. `nonce`
3. `url`
4. `jwk` or `kid`

According to RFC7517 a jwk should look like this:

```
{
    "kty":"EC",
    "crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "kid":"Public key used in JWS spec Appendix A.3 example"
}
```
