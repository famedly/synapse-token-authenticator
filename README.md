# Synapse Token Authenticator
Synapse Token Authenticator is a synapse auth provider which allows for token authentication (and optional registration) using JWTs (Json Web Tokens).

## Installation
You have to make sure that `token_authenticator.py` is in the python path, so that synapse can find it. Additionally you also have to make sure that `jwcrypto` is installed (`pip install jwcrypto`).

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

## Test
```bash
trial tests/test_simple.py
```
