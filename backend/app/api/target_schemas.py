from typing import Literal

from pydantic import BaseModel, Field, field_validator


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=1, max_length=2048)
    description: str = Field(default="", max_length=4000)
    owner_reference: str = Field(default="", max_length=160)
    allowed_hostnames: list[str] = Field(min_length=1, max_length=20)
    scope_notes: str = Field(default="", max_length=4000)
    authorization_confirmed: Literal[True]

    @field_validator("name")
    @classmethod
    def name_has_visible_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Name must contain non-whitespace characters")
        return value.strip()


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    description: str | None = Field(default=None, max_length=4000)
    owner_reference: str | None = Field(default=None, max_length=160)
    allowed_hostnames: list[str] | None = Field(default=None, min_length=1, max_length=20)
    scope_notes: str | None = Field(default=None, max_length=4000)
    enabled: bool | None = None
    authorization_confirmed: bool | None = None
