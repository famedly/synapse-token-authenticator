from jwcrypto.jwk import JWKSet
from twisted.web import resource


class PublicKeysResource(resource.Resource):
    def __init__(self, keys: JWKSet):
        self.keys = keys.export(private_keys=False).encode("utf-8")

    def render_GET(self, request):
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return self.keys
