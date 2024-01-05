import requests
from urllib.parse import urljoin
from jwcrypto.jwk import JWKSet


class OpenIDProviderMetadata:
    """
    Wrapper around OpenID Provider Metadata values
    """

    def __init__(self, issuer: str):
        response = requests.get(urljoin(issuer, "/.well-known/openid-configuration"))
        response.raise_for_status()

        configuration = response.json()

        self.issuer = issuer
        self.introspection_endpoint: str = configuration["introspection_endpoint"]
        self.jwks_uri: str = configuration["jwks_uri"]
        self.id_token_signing_alg_values_supported: list[str] = configuration[
            "id_token_signing_alg_values_supported"
        ]

    def jwks(self) -> JWKSet:
        """
        Signing keys used to validate signatures from the OpenID Provider
        """
        response = requests.get(self.jwks_uri)
        response.raise_for_status()

        return JWKSet.from_json(response.text)
