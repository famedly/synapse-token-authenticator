Run `pip install jwcrypto`

```json
{
  "type": "com.famedly.login.token",
  "identifier": {
    "type": "m.id.user",
    "user": "localpart"
  },
  "token": "<jwt here>"
}
```

JWT needs claim `sub` as localpart or fully qualified mxid

config options:

```yaml
# provide only one of secret, keyfile
secret: symetrical secret
keyfile: path to asymetrical keyfile

# algorithm: HS512
# allow_registration: false
# require_expiracy: true
```
