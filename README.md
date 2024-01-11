# Synapse Token Authenticator

[![PyPI - Version](https://img.shields.io/pypi/v/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)

Synapse Token Authenticator is a synapse auth provider which allows for token authentication (and optional registration) using JWTs (Json Web Tokens) and OIDC.

-----

**Table of Contents**

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Releasing](#releasing)
- [License](#license)

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
  issuer: "https://idp.example.com"
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
```
It is recommended to have `require_expiry` set to `true` (default). As for `allow_registration`, it depends on usecase: If you only want to be able to log in *existing* users, leave it at `false` (default). If nonexistant users should be simply registered upon hitting the login endpoint, set it to `true`.

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
```json
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
