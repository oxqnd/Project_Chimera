from pydantic import BaseModel

class ScanRequest(BaseModel):
    domain: str

class ZapScanRequest(BaseModel):
    target: str

class NmapScanRequest(BaseModel):
    target: str