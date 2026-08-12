from typing import Any
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict


class OpenIDProviderMetadata(BaseModel):
    """OpenID Provider Metadata from `/.well-known/openid-configuration`."""

    model_config = ConfigDict(extra="ignore")

    issuer: str
    introspection_endpoint: str
    jwks_uri: str
    id_token_signing_alg_values_supported: list[str]


async def get_oidp_metadata(issuer: str, client) -> OpenIDProviderMetadata:
    config = await client.get_json(
        urljoin(issuer, ".well-known/openid-configuration"),
    )
    return OpenIDProviderMetadata.model_validate({**config, "issuer": issuer})


def all_list_elems_are_equal_return_the_elem(list_):
    filtered_list = list(filter(lambda x: x is not None, list_))
    if len(filtered_list) == 0:
        return None
    val = filtered_list[0]
    if not all(i == val for i in filtered_list):
        msg = f"Elements in {filtered_list} are not equal"
        raise Exception(msg)
    return val


def get_path_in_dict(path: str | list[str] | list[list[str]], d: Any) -> Any | None:
    # first make the path input either a list[str] or list[list[str]]
    list_path: list[str] | list[list[str]] = [path] if isinstance(path, str) else path
    # use the result to always generate a list[list[str]] type
    if len(list_path) == 0 or isinstance(list_path[0], str):
        normalized_path: list[list[str]] = [
            [s for s in list_path if isinstance(s, str)]
        ]
    else:
        normalized_path = [list(p) for p in list_path if isinstance(p, list)]

    for p in normalized_path:
        r = d
        for segment in p:
            if not isinstance(r, dict):
                break
            r = r.get(segment)
        else:
            if r is not None:
                return r
    return None


def validate_scopes(required_scopes: str | list[str], provided_scopes: str) -> bool:
    if isinstance(required_scopes, str):
        required_scopes = required_scopes.split()
    provided_scopes_list = provided_scopes.split()
    return all(scope in provided_scopes_list for scope in required_scopes)
