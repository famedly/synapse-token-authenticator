import json

from twisted.web import resource


class MetadataResource(resource.Resource):
    def __init__(self, resource: object):
        self.resource = resource

    def render_GET(self, request):
        request.setHeader(b"content-type", b"application/json")
        request.setHeader(b"access-control-allow-origin", b"*")
        return json.dumps(self.resource).encode("utf-8")
