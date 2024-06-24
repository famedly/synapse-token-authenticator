from base64 import b64encode
from urllib.parse import urljoin
from typing import List, Optional, Any
import json
from twisted.web import resource


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
        urljoin(issuer, ".well-known/openid-configuration"),
    )
    return OpenIDProviderMetadata(issuer, config)


def basic_auth(username: str, password: str) -> dict[bytes, list[bytes]]:
    authorization = b64encode(
        b":".join((username.encode("utf8"), password.encode("utf8")))
    )
    return {b"Authorization": [b"Basic " + authorization]}


def bearer_auth(token: str) -> dict[bytes, list[bytes]]:
    return {b"Authorization": [b"Bearer " + token.encode("utf8")]}


def if_not_none(f):
    return lambda x: (f(x) if x is not None else None)


def all_list_elems_are_equal_return_the_elem(list_):
    filtered_list = list(filter(lambda x: x is not None, list_))
    if len(filtered_list) == 0:
        return None
    val = filtered_list[0]
    if not all(i == val for i in filtered_list):
        raise Exception(f"Elements in {filtered_list} are not equal")
    return val


def get_path_in_dict(path: str | List[str], d: Any) -> Optional[Any]:
    if isinstance(path, str):
        path = [path]
    r = d
    for p in path:
        if not isinstance(r, dict):
            return None
        r = r.get(p)
    return r


def validate_scopes(required_scopes: str | List[str], provided_scopes: str) -> bool:
    if isinstance(required_scopes, str):
        required_scopes = required_scopes.split()
    provided_scopes_list = provided_scopes.split()
    return all(scope in provided_scopes_list for scope in required_scopes)


class MetadataResource(resource.Resource):
    def __init__(self, resource: object):
        self.resource = resource

    def render_GET(self, request):
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return json.dumps(self.resource).encode("utf-8")
