from pydantic import BaseModel, ConfigDict


class OIDCConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    issuer: str
    client_id: str
    client_secret: str
    project_id: str
    organization_id: str
    allowed_client_ids: str | None = None
    allow_registration: bool = False
