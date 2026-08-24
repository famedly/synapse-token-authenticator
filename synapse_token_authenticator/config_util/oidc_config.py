from synapse_token_authenticator.config_util.base import BaseConfigModel


class OIDCConfig(BaseConfigModel):
    issuer: str
    client_id: str
    client_secret: str
    project_id: str
    organization_id: str
    allowed_client_ids: str | None = None
    allow_registration: bool = False
