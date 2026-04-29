import json
from urllib.parse import urljoin

from jwcrypto.jwk import JWKSet
from twisted.web import resource

from synapse_token_authenticator.config import OIDCConfig


class LoginMetadataResource(resource.Resource):
    def __init__(self, oidc_config: OIDCConfig):
        self.issuer = oidc_config.issuer
        self.metadata_url = urljoin(
            oidc_config.issuer, "/.well-known/openid-configuration"
        )
        self.organization_id = oidc_config.organization_id
        self.project_id = oidc_config.project_id

    def render_GET(self, request) -> bytes:
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return json.dumps(
            {
                "issuer": self.issuer,
                "issuer-metadata": self.metadata_url,
                "organization-id": self.organization_id,
                "project-id": self.project_id,
            }
        ).encode("utf-8")


class PublicKeysResource(resource.Resource):
    def __init__(self, keys: JWKSet):
        self.keys = keys.export(private_keys=False).encode("utf-8")

    def render_GET(self, request) -> bytes:
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return self.keys


class MetadataResource(resource.Resource):
    def __init__(self, resource: object) -> None:
        self.resource = resource

    def render_GET(self, request) -> bytes:
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return json.dumps(self.resource).encode("utf-8")
