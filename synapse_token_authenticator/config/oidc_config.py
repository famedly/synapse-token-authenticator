from synapse_token_authenticator.config.base import BaseConfigModel


class OIDCConfig(BaseConfigModel):
    issuer: str
    client_id: str
    client_secret: str
    project_id: str
    organization_id: str
    allowed_client_ids: list[str] | None = None
    allow_registration: bool = False
