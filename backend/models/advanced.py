from typing import Literal, Optional
from pydantic import BaseModel, Field


class AdvancedReconRequest(BaseModel):
    domain: str = Field(..., description="Target domain for advanced reconnaissance")


class AttackPathRequest(BaseModel):
    domain: str = Field(..., description="Target domain for attack path modeling")


class AdvancedReconInsight(BaseModel):
    asset: Optional[str] = Field(None, description="Related asset or subdomain, if applicable")
    signals: list[str] = Field(default_factory=list, description="Signals or cues discovered for this asset")
    recommended_actions: list[str] = Field(default_factory=list, description="Suggested follow-up actions")
    confidence: Literal["low", "medium", "high"] = Field("low", description="Confidence level of the insight")
    score: int = Field(0, ge=0, le=100, description="Relative priority score (0-100)")


class AttackPathStep(BaseModel):
    step: int = Field(..., description="Step number in the modeled path")
    description: str = Field(..., description="Narrative description of this step")
    asset: Optional[str] = Field(None, description="Asset primarily impacted in this step")
    evidence: Optional[str] = Field(None, description="Supporting evidence or observation for this step")


class AttackPath(BaseModel):
    name: str = Field(..., description="Name of the modeled attack path")
    risk: Literal["low", "medium", "high"] = Field("medium", description="Estimated risk level if the path succeeds")
    narrative: str = Field(..., description="High-level summary of the attack path")
    steps: list[AttackPathStep] = Field(..., description="Ordered steps describing the modeled attack flow")
