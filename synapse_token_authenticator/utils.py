from base64 import b64encode
from urllib.parse import urljoin

import requests
from jwcrypto.jwk import JWKSet


class OpenIDProviderMetadata:
    """
    Wrapper around OpenID Provider Metadata values
    """

    def __init__(self, issuer: str, configuration: dict):
        self.issuer = issuer
        self.introspection_endpoint: str = configuration["introspection_endpoint"]
        self.jwks_uri: str = configuration["jwks_uri"]
        self.id_token_signing_alg_values_supported: list[str] = configuration[
            "id_token_signing_alg_values_supported"
        ]

    async def get_configuration(issuer, client) -> dict:
        return await client.get_json(
            urljoin(issuer, "/.well-known/openid-configuration"),
        )

    def jwks(self) -> JWKSet:
        """
        Signing keys used to validate signatures from the OpenID Provider
        """
        response = requests.get(self.jwks_uri, proxies={"http": "", "https": ""})
        response.raise_for_status()

        return JWKSet.from_json(response.text)


def basic_auth(username: str, password: str) -> dict[bytes, bytes]:
    authorization = b64encode(
        b":".join((username.encode("latin1"), password.encode("latin1")))
    )
    return {b"Authorization": [b"Basic " + authorization]}
