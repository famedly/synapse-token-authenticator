# Synapse Token Authenticator

[![PyPI - Version](https://img.shields.io/pypi/v/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)

Synapse Token Authenticator is a synapse auth provider which allows for token authentication (and optional registration) using JWTs (Json Web Tokens) and OIDC.

-----

**Table of Contents**

* [Installation](#installation)
* [Configuration](#configuration)
    * [OAuthConfig](#oauthconfig)
    * [JwtValidationConfig](#jwtvalidationconfig)
    * [IntrospectionValidationConfig](#introspectionvalidationconfig)
    * [NotifyOnRegistration](#notifyonregistration)
    * [Path](#path)
    * [BasicAuth](#basicauth)
    * [BearerAuth](#bearerauth)
    * [HttpAuth](#httpauth)
    * [Validator](#validator)
    * [Exist](#exist)
    * [Not](#not)
    * [Equal](#equal)
    * [MatchesRegex](#matchesregex)
    * [AnyOf](#anyof)
    * [AllOf](#allof)
    * [In](#in)
    * [ListAllOf](#listallof)
    * [ListAnyOf](#listanyof)
* [Usage](#usage)
    * [JWT Authentication](#jwt-authentication)
    * [OIDC Authentication](#oidc-authentication)
* [Testing](#testing)
* [Releasing](#releasing)
* [License](#license)

## Installation

```console
pip install synapse-token-authenticator
```

## Configuration
Here are the available configuration options:
```yaml
jwt:
  # provide only one of secret, keyfile
  secret: symetrical secret
  keyfile: path to asymetrical keyfile

  # Algorithm of the tokens, defaults to HS512 (optional)
  algorithm: HS512
  # Allow registration of new users, defaults to false (optional)
  allow_registration: false
  # Require tokens to have an expiry set, defaults to true (optional)
  require_expiry: true
oidc:
  # Include trailing slash
  issuer: "https://idp.example.com/"
  client_id: "<IDP client id>"
  client_secret: "<IDP client secret>"
  # Zitadel Organization ID, used for masking. (Optional)
  organization_id: 1234
  # Zitadel Project ID, used for validating the audience of the returned token.
  project_id: 5678
  # Limits access to specified clients. Allows any client if not set (optional)
  allowed_client_ids: ['2897827328738@project_name']
  # Allow registration of new users, defaults to false (optional)
  allow_registration: false
epa:
  # see ePaConfig section
oauth:
  # see OAuthConfig section
```
It is recommended to have `require_expiry` set to `true` (default). As for `allow_registration`, it depends on usecase: If you only want to be able to log in *existing* users, leave it at `false` (default). If nonexistant users should be simply registered upon hitting the login endpoint, set it to `true`.

### OAuthConfig
| Parameter                  | Type                                                                         |
| -------------------------- | ---------------------------------------------------------------------------- |
| `jwt_validation`           | [`JwtValidationConfig`](#jwtvalidationconfig) (optional)                     |
| `introspection_validation` | [`IntrospectionValidationConfig`](#introspectionvalidationconfig) (optional) |
| `username_type`            | One of `'fq_uid'`, `'localpart'`, `'user_id'` (optional)                     |
| `notify_on_registration`   | [`NotifyOnRegistration`](#notifyonregistration) (optional)                   |
| `expose_metadata_resource` | Any (optional)                                                               |
| `registration_enabled`     | Bool (defaults to `false`)                                                   |

At least one of `jwt_validation` or `introspection_validation` must be defined.

`username_type` specifies the role of `identifier.user`:
- `'fq_uid'` — must be fully qualified username, e.g. `@alice:example.test`
- `'localpart'` — must be localpart, e.g. `alice`
- `'user_id'` — could be localpart or fully qualified username
- `null` — the username is ignored, it will be source from the token or introspection response

If `notify_on_registration` is set then `notify_on_registration.url` will be called when a new user is registered with this body:
```json
{
    "localpart": "alice",
    "fully_qualified_uid": "@alice:example.test",
    "displayname": "Alice",
},
```

`expose_metadata_resource` must be an object with `name` field. The object will be exposed at `/_famedly/login/{expose_metadata_resource.name}`.

`jwt_validation` and `introspection_validation` contain a bunch of `*_path` optional fields. Each of these, if specified will be used to source either localpart, user id, fully qualified user id, admin permission, or email from jwt claims and introspection response. They values are going to be compared for equality, if they differ, authentication would fail. Be careful with these, as it is possible to configure in such a way that authentication would always fail, or, if `username_type` is `null`, no user id data can be sourced, thus also leading to failure.


### JwtValidationConfig
[RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)

| Parameter          | Type                                                      |
|--------------------|-----------------------------------------------------------|
| `validator`        | [`Validator`](#validator) (defaults to [`Exist`](#exist)) |
| `require_expiry`   | Bool (defaults to `false`)                                |
| `localpart_path`   | [`Path`](#path) (optional)                                |
| `user_id_path`     | [`Path`](#path) (optional)                                |
| `fq_uid_path`      | [`Path`](#path) (optional)                                |
| `displayname_path` | [`Path`](#path) (optional)                                |
| `admin_path`       | [`Path`](#path) (optional)                                |
| `email_path`       | [`Path`](#path) (optional)                                |
| `required_scopes`  | Space separated string or a list of strings (optional)    |
| `jwk_set`          | [JWKSet](https://datatracker.ietf.org/doc/html/rfc7517#section-5) or [JWK](https://datatracker.ietf.org/doc/html/rfc7517#section-4) (optional) |
| `jwk_file`         | String (optional)                                         |
| `jwks_endpoint`    | String (optional)                                         |

Either `jwk_set` or `jwk_file` or `jwks_endpoint` must be specified.

### IntrospectionValidationConfig
[RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
| Parameter          | Type                                                      |
| ------------------ | --------------------------------------------------------- |
| `endpoint`         | String                                                    |
| `validator`        | [`Validator`](#validator) (defaults to [`Exist`](#exist)) |
| `auth`             | [`HttpAuth`](#httpauth) (optional)                        |
| `localpart_path`   | [`Path`](#path) (optional)                                |
| `user_id_path`     | [`Path`](#path) (optional)                                |
| `fq_uid_path`      | [`Path`](#path) (optional)                                |
| `displayname_path` | [`Path`](#path) (optional)                                |
| `admin_path`       | [`Path`](#path) (optional)                                |
| `email_path`       | [`Path`](#path) (optional)                                |
| `required_scopes`  | Space separated string or a list of strings (optional)    |

Keep in mind, that default validator will always pass. According to the [spec](https://datatracker.ietf.org/doc/html/rfc7662), you probably want at least
```yaml
type: in
path: 'active'
validator:
  type: equal
  value: true
```
or
```yaml
['in', 'active', ['equal', true]]
```

### NotifyOnRegistration:
| Parameter            | Type                               |
| -------------------- | ---------------------------------- |
| `url`                | String                             |
| `auth`               | [`HttpAuth`](#HttpAuth) (optional) |
| `interrupt_on_error` | Bool (defaults to `true`)          |

### Path
A path is either a string or a list of strings. A path is used to get a value inside a nested dictionary/object.

#### Examples
- `'foo'` is an existing path in `{'foo': 3}`, resulting in value `3`
- `['foo']` is an existing path in `{'foo': 3}`, resulting in value `3`
- `['foo', 'bar']` is an existing path in `{'foo': {'bar': 3}}`, resulting in value `3`

### BasicAuth
| Parameter  | Type   |
| ---------- | ------ |
| `username` | String |
| `password` | String |

### BearerAuth
| Parameter | Type   |
| --------- | ------ |
| `token`   | String |

### HttpAuth
Authentication options, always optional
| Parameter | Type                    |
| --------- | ----------------------- |
| `type`    | `'basic'` \| `'bearer'` |

Possible options: [`BasicAuth`](#BasicAuth), [`BearerAuth`](#BearerAuth),

### Validator
A validator is any of these types:
    [`Exist`](#Exist),
    [`Not`](#Not),
    [`Equal`](#Equal),
    [`MatchesRegex`](#MatchesRegex),
    [`AnyOf`](#AnyOf),
    [`AllOf`](#AllOf),
    [`In`](#In),
    [`ListAnyOf`](#ListAnyOf),
    [`ListAllOf`](#ListAllOf)

Each validator has `type` field

### Exist
Validator that always returns true.

#### Examples
```yaml
{'type': 'exist'}
```
or
```yaml
['exist']
```

### Not
Validator that inverses the result of the inner validator.

| Parameter   | Type                      |
| ----------- | ------------------------- |
| `validator` | [`Validator`](#Validator) |

#### Examples
```yaml
{'type': 'not', 'validator': 'exist'}
```
or
```yaml
['not', 'exist']
```

### Equal
Validator that checks for equality with the specified constant.

| Parameter | Type  |
| --------- | ----- |
| `value`   | `Any` |

#### Examples
```yaml
{'type': 'equal', 'value': 3}
```
or
```yaml
['equal', 3]
```

### MatchesRegex
Validator that checks if a value is a string and matches the specified regex.

| Parameter                                  | Type   | Description                 |
| ------------------------------------------ | ------ | --------------------------- |
| `regex`                                    | `str`  | Python regex syntax         |
| `full_match` (optional, `true` by default) | `bool` | Full match or partial match |

#### Examples
```yaml
{'type': 'regex', 'regex': 'hello.'}
```
or
```yaml
['regex', 'hello.', false]
```

### AnyOf
Validator that checks if **any** of the inner validators pass.


| Parameter    | Type                              |
| ------------ | --------------------------------- |
| `validators` | List of [`Validator`](#Validator) |

#### Examples
```yaml
type: any_of
validators:
  - ['in', 'foo', ['equal', 3]]
  - ['in', 'bar' ['exist']]
```
or
```yaml
['any_of', [['in', 'bar' ['exist']], ['in', 'foo', ['equal', 3]]]]
```

### AllOf
Validator that checks if **all** of the inner validators pass.

| Parameter    | Type                              |
| ------------ | --------------------------------- |
| `validators` | List of [`Validator`](#Validator) |

#### Examples
```yaml
type: all_of
validators:
  - ['exist']
  - ['in', 'foo', ['equal', 3]]
```
or
```yaml
['all_of', [['exist'], ['in', 'foo', ['equal', 3]]]]
```

### In
Validator that modifies the context for the inner validator, *going inside* a dict key.
If the validated object is not a dict, or doesn't have specified `path`, validation fails.

| Parameter   | Type                                                                |
| ----------- | ------------------------------------------------------------------- |
| `path`      | [`Path`](#Path)                                                     |
| `validator` | [`Validator`](#Validator) (optional, defaults to [`Exist`](#Exist)) |

#### Examples
```yaml
['in', ['foo', 'bar'], ['equal', 3]]
```

### ListAllOf
Validator that checks if the value is a list and **all** of its elements satisfy the specified validator.

| Parameter   | Type                      |
| ----------- | ------------------------- |
| `validator` | [`Validator`](#Validator) |

#### Examples
```yaml
type: list_all_of
validator:
  type: regex
  regex: 'ab..'
```
or
```yaml
['list_all_of', ['regex', 'ab..']]
```

### ListAnyOf
Validator that checks if the value is a list and if **any** of its elements satisfy the specified validator.

| Parameter   | Type                      |
| ----------- | ------------------------- |
| `validator` | [`Validator`](#Validator) |

#### Examples
```yaml
type: list_all_of
validator:
  type: equal
  value: 3
```
or
```yaml
['list_any_of', ['equal', 3]]
```

### ePaConfig

| Parameter                  | Type                                                                      |
| -------------------------- | --------------------------------------------------------------------------|
| `iss`                      | String                                                                    |
| `resource_id`              | String                                                                    |
| `registration_enabled`     | Bool (defaults to `false`)                                                |
| `expose_metadata_resource` | Any (optional)                                                            |
| `validator`                | [`Validator`](#validator) (defaults to [`Exist`](#exist))                 |
| `jwk_set`                  | [JWKSet](https://datatracker.ietf.org/doc/html/rfc7517#section-5) or [JWK](https://datatracker.ietf.org/doc/html/rfc7517#section-4) (optional) |
| `jwk_file`                 | String (optional)                                                         |
| `jwks_endpoint`            | String (optional)                                                         |
| `enc_jwk_file`             | String (optional)                                                         |
| `enc_jwk`                  | [JWK](https://datatracker.ietf.org/doc/html/rfc7517#section-4) (optional) |
| `enc_jwks_endpoint`        | String (optional) (defaults to `/.well-known/jwks.json`)                  |
| `displayname_path`         | [`Path`](#path) (optional)                                                |
| `localpart_path`           | [`Path`](#path) (optional)                                                |

Either `jwk_set` or `jwk_file` or `jwks_endpoint` must be specified and either `enc_jwk` or `enc_jwk_file` must be specified.

`resource_id` is an id for the synapse token authenticator. The same id must be present on the claim `aud` of the received token.

`iss` is the expected issuer of the token and this will be checked against the claim `iss` of the token.

`enc_jwks_endpoint` is the endpoint where the synapse token authenticator will publish the public keys for encrypting the JWEs. The full path of the endpoint will be `https://<homeserver>/<enc_jwks_endpoint>`. This endpoint will contain only a [JWKSet](https://datatracker.ietf.org/doc/html/rfc7517#section-5) in json format and the JWKSet will have only one key in it.

## Usage

### JWT Authentication
First you have to generate a JWT with the correct claims. The `sub` claim is the localpart or full mxid of the user you want to log in as. Be sure that the algorithm and secret match those of the configuration. An example of the claims is as follows:
```json
{
  "sub": "alice",
  "exp": 1516239022
}
```

Next you need to post this token to the `/login` endpoint of synapse. Be sure that the `type` is `com.famedly.login.token` and that `identifier.user` is, again, either the localpart or the full mxid. For example the post body could look as following:
```json
{
  "type": "com.famedly.login.token",
  "identifier": {
    "type": "m.id.user",
    "user": "alice"
  },
  "token": "<jwt here>"
}
```
### OIDC Authentication

First, the user needs to obtain an Access token and an ID token from the IDP:
```http
POST https://idp.example.org/oauth/v2/token

```

Next, the client needs to use these tokens and construct a payload to the login endpoint:

```jsonc
{
  "type": "com.famedly.login.token.oidc",
  "identifier": {
    "type": "m.id.user",
    "user": "alice" // The user's localpart, extracted from the localpart in the ID token returned by the IDP
  },
  "token": "<opaque access here>" // The access token returned by the IDP
}
```

### ePa Authentication

First the user needs to obtain an access token from the idp. This token need to be signed and later encrypted ([JWE](https://datatracker.ietf.org/doc/html/rfc7516)).

Next, the client needs to use these tokens and construct a payload to the login endpoint:

```jsonc
{
  "type": "com.famedly.login.token.epa",
  "identifier": {
    "type": "m.id.user",
    "user": "alice" // The user's localpart, extracted from the localpart in the ID token returned by the IDP
  },
  "token": "<jwe here>" // The access token returned by the IDP
}
```

## Testing

The tests uses twisted's testing framework trial, with the development
enviroment managed by hatch. Running the tests and generating a coverage report
can be done like this:

```console
hatch run cov
```

## Releasing

After tagging a new version, manually create a Github release based on the tag. This will publish the package on PyPI.

## License

`synapse-token-authenticator` is distributed under the terms of the
[AGPL-3.0](https://spdx.org/licenses/AGPL-3.0-only.html) license.
