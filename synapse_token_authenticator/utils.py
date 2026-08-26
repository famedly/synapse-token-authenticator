from typing import Any
from urllib.parse import urljoin


class ClaimsMismatchError(Exception):
    """Claims mismatch error."""


class OpenIDProviderMetadata:
    """Selected fields from an OpenID Provider Metadata document."""

    def __init__(self, issuer: str, configuration: dict):
        self.issuer = issuer
        self.introspection_endpoint: str = configuration["introspection_endpoint"]
        self.jwks_uri: str = configuration["jwks_uri"]
        self.id_token_signing_alg_values_supported: list[str] = configuration[
            "id_token_signing_alg_values_supported"
        ]


async def get_oidp_metadata(issuer, client) -> OpenIDProviderMetadata:
    """Fetch and parse openid-configuration for issuer."""
    config = await client.get_json(
        urljoin(issuer, ".well-known/openid-configuration"),
    )
    return OpenIDProviderMetadata(issuer, config)


def if_not_none(f):
    return lambda x: (f(x) if x is not None else None)


def all_list_elems_are_equal_return_the_elem(list_):
    """Return the shared non-None value, or None if every entry is absent.

    None entries are ignored. When at least one value is present, every
    non-None value must be equal; otherwise an Exception is raised.
    """
    filtered_list = list(filter(lambda x: x is not None, list_))
    if len(filtered_list) == 0:
        return None
    val = filtered_list[0]
    if not all(i == val for i in filtered_list):
        raise ClaimsMismatchError(f"Elements in {filtered_list} are not equal")
    return val


def get_path_in_dict(path: str | list[str] | list[list[str]], d: Any) -> Any | None:
    """Look up a value in dict using one or more fallback key paths.

    path may be a dotted path ("foo" or ["foo", "bar"]) or a list of
    alternative paths ([["a", "b"], ["c", "d"]]). Paths are tried in order;
    the first non-None result wins.
    """
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
    """Return whether every required_scope appears in provided_scopes.

    Both arguments accept space-separated scope strings; required_scopes may
    also be a pre-split list.
    """
    if isinstance(required_scopes, str):
        required_scopes = required_scopes.split()
    provided_scopes_list = provided_scopes.split()
    return all(scope in provided_scopes_list for scope in required_scopes)


def get_claim_from_validation(
    claims: dict,
    validation_config: Any,
    path: str,
) -> Any | None:
    """Read a claim using a path stored on validation_config.

    Args:
        claims: Parsed JWT or introspection payload.
        validation_config: Config object with path attributes (e.g. OAuth
            JwtValidationConfig). returns None if it's None.
        path: Name of the config attribute holding the lookup path (e.g.
            "localpart_path", "displayname_path"). The attribute value
            is passed to `get_path_in_dict`.

    Returns:
        The resolved claim value, or None when the config, path attribute,
        or claim itself is missing.
    """
    if validation_config is None:
        return None

    claim_path = getattr(validation_config, path, None)
    if claim_path is None:
        return None
    return get_path_in_dict(claim_path, claims)


def get_reconciled_claim(
    jwt_claims: dict,
    introspection_claims: dict,
    jwt_validation: Any,
    introspection_validation: Any,
    path: str,
) -> Any | None:
    """Require JWT and introspection to agree on a configured claim path.

    Each side resolves path via `get_claim_from_validation`. None values
    are ignored. If any non-None values remain they must be equal.

    Args:
        jwt_claims: Parsed JWT payload.
        introspection_claims: Parsed token introspection response.
        jwt_validation: JWT validation config, or None.
        introspection_validation: Introspection validation config, or None.
        path: Config attribute name for the claim path (e.g.
            "displayname_path").

    Returns:
        The agreed value, or None when neither side provides one.

    Raises:
        Exception: When non-None values from both sides differ.
    """
    return all_list_elems_are_equal_return_the_elem(
        [
            get_claim_from_validation(jwt_claims, jwt_validation, path),
            get_claim_from_validation(
                introspection_claims, introspection_validation, path
            ),
        ]
    )


def get_reconcile_claim_paths(
    jwt_claims: dict,
    introspection_claims: dict,
    path: str,
) -> Any | None:
    """Require JWT and introspection to agree on a fixed top-level claim key.

    Unlike `get_reconciled_claim`, path is read
    directly from each payload (e.g. "sub", "iss").

    Returns:
        The agreed value, or None when neither payload contains path.

    Raises:
        Exception: When both payloads contain path but with different values.
    """
    return all_list_elems_are_equal_return_the_elem(
        [
            get_path_in_dict(path, jwt_claims),
            get_path_in_dict(path, introspection_claims),
        ]
    )
