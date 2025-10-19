from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .db.database import init_db
from .api import scan, orchestrate, advanced, auth, zap_scripts

app = FastAPI(
    title="Project Chimera API",
    description="API for the LLM-powered Threat Orchestration Platform",
    version="0.1.0"
)

@app.on_event("startup")
async def startup_event():
    init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API 라우터 포함
app.include_router(scan.router, prefix="/api")
app.include_router(orchestrate.router, prefix="/api")
app.include_router(advanced.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(zap_scripts.router, prefix="/api")

@app.get("/")
def read_root():
    return {"message": "Welcome to Project Chimera API"}
