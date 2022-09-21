# Synapse Token Authenticator

[![PyPI - Version](https://img.shields.io/pypi/v/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/synapse-token-authenticator.svg)](https://pypi.org/project/synapse-token-authenticator)

Synapse Token Authenticator is a synapse auth provider which allows for token authentication (and optional registration) using JWTs (Json Web Tokens).

-----

**Table of Contents**

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [License](#license)

## Installation

**TODO**: requires publishing on pypi.
```console
pip install synapse-token-authenticator
```

## Configuration
Here are the available configuration options:
```yaml
# provide only one of secret, keyfile
secret: symetrical secret
keyfile: path to asymetrical keyfile

# Algorithm of the tokens, defaults to HS512
#algorithm: HS512
# Allow registration of new users using these tokens, defaults to false
#allow_registration: false
# Require tokens to have an expiracy set, defaults to true
#require_expiracy: true
```
It is recommended to have `require_expiracy` set to `true` (default). As for `allow_registration`, it depends on usecase: If you only want to be able to log in *existing* users, leave it at `false` (default). If nonexistant users should be simply registered upon hitting the login endpoint, set it to `true`.

## Usage
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

## Testing

The tests uses twisted's testing framework trial, with the development
enviroment managed by hatch. Running the tests and generating a coverage report
can be done like this:

```console
hatch run cov
```

## License

`synapse-token-authenticator` is distributed under the terms of the
[AGPL-3.0](https://spdx.org/licenses/AGPL-3.0-only.html) license.
