from typing import Literal

from pydantic import BaseModel, ConfigDict


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["pdf", "json"]
