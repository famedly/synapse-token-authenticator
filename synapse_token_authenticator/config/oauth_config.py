from typing import Any, Self

from pydantic import (
    Field,
    model_validator,
)

from synapse_token_authenticator.config.base import (
    BaseConfigModel,
    ClaimsMapping,
    JwkSource,
    UsernameType,
)
from synapse_token_authenticator.config.http_auth import HttpAuthField, NoAuth


class JwtValidationConfig(ClaimsMapping, JwkSource):
    require_expiry: bool = False


class IntrospectionValidationConfig(ClaimsMapping):
    auth: HttpAuthField = Field(default_factory=NoAuth)
    endpoint: str


class NotifyOnRegistration(BaseConfigModel):
    url: str
    auth: HttpAuthField = Field(default_factory=NoAuth)
    interrupt_on_error: bool = True


class OAuthConfig(BaseConfigModel):
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: UsernameType | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    check_external_id: bool = True

    @model_validator(mode="after")
    def validate(self) -> Self:
        if not (self.jwt_validation or self.introspection_validation):
            raise ValueError(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        return self
