from typing import Any

from fastapi import APIRouter, HTTPException

from ..core.scanner import (
    list_zap_scripts,
    load_zap_script,
    remove_zap_script,
    run_zap_script,
)
from ..models.zap import ScriptLoadRequest, ScriptRunRequest

router = APIRouter()


@router.get("/zap/scripts")
def get_scripts() -> Any:
    try:
        return list_zap_scripts()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/zap/scripts/load")
def load_script(request: ScriptLoadRequest) -> Any:
    try:
        return load_zap_script(
            script_name=request.name,
            script_type=request.script_type,
            script_engine=request.script_engine,
            script_content=request.content,
            description=request.description,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/zap/scripts/run")
def run_script(request: ScriptRunRequest) -> Any:
    try:
        return run_zap_script(request.name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/zap/scripts/{name}")
def delete_script(name: str) -> Any:
    try:
        return remove_zap_script(name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
