from pydantic import (
    ConfigDict,
    field_validator,
)
from pydantic.dataclasses import dataclass


# To prevent breaking changes, we allow extra fields.
@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str
    project_id: str | int
    organization_id: str | int
    allowed_client_ids: list[str] | None = None
    allow_registration: bool = False

    @field_validator("project_id", "organization_id", mode="before")
    @classmethod
    def coerce_int_to_str(cls, value: int | str) -> str:
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            return value

    @field_validator("allowed_client_ids", mode="before")
    @classmethod
    def coerce_allowed_client_ids(
        cls, value: list[str] | str | None
    ) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value.split()
        return value
