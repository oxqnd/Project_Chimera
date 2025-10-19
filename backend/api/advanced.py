from fastapi import APIRouter, HTTPException

from ..core.advanced_features import generate_advanced_recon, generate_attack_paths
from ..models.advanced import (
    AdvancedReconRequest,
    AttackPathRequest,
    AdvancedReconInsight,
    AttackPath,
)

router = APIRouter()


@router.post("/advanced/recon", response_model=list[AdvancedReconInsight])
def run_advanced_recon(request: AdvancedReconRequest):
    try:
        insights = generate_advanced_recon(request.domain.strip())
        if not insights:
            raise HTTPException(status_code=404, detail="No assets found for the requested domain.")
        return insights
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/advanced/attack-paths", response_model=list[AttackPath])
def run_attack_path_modeling(request: AttackPathRequest):
    try:
        paths = generate_attack_paths(request.domain.strip())
        if not paths:
            raise HTTPException(status_code=404, detail="No assets or findings available for modeling.")
        return paths
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
