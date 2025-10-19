from __future__ import annotations

from pydantic import BaseModel, Field


class ScriptLoadRequest(BaseModel):
    name: str = Field(..., description="Unique name for the script inside ZAP")
    script_type: str = Field(..., description="ZAP script type (e.g., 'standalone', 'proxy')")
    script_engine: str = Field(..., description="ZAP script engine (e.g., 'ECMAScript', 'Python')")
    content: str = Field(..., description="Full script content")
    description: str | None = Field(default=None, description="Optional description for the script")


class ScriptRunRequest(BaseModel):
    name: str = Field(..., description="Name of the stored ZAP script to execute")
