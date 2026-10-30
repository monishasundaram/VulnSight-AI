from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_id: UUID
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    profile: Literal["quick", "standard", "advanced"] = "standard"
    authorization_confirmed: Literal[True]
    zap_passive_authorized: bool = False

    @field_validator("name")
    @classmethod
    def name_is_not_whitespace(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Name must contain non-whitespace characters")
        return value.strip() if value is not None else value
