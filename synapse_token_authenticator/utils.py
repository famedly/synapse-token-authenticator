from base64 import b64encode
from urllib.parse import urljoin


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


async def get_oidp_metadata(issuer, client) -> OpenIDProviderMetadata:
    config = await client.get_json(
        urljoin(issuer, "/.well-known/openid-configuration"),
    )
    return OpenIDProviderMetadata(issuer, config)


def basic_auth(username: str, password: str) -> dict[bytes, bytes]:
    authorization = b64encode(
        b":".join((username.encode("utf8"), password.encode("utf8")))
    )
    return {b"Authorization": [b"Basic " + authorization]}
