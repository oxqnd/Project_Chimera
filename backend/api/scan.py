from fastapi import APIRouter, HTTPException
from ..models.scan import ScanRequest, ZapScanRequest, NmapScanRequest
from ..core.scanner import run_subfinder, run_zap_scan, run_nmap
from ..db.database import get_db_connection

router = APIRouter()

@router.post("/scan")
def start_subdomain_scan(scan_request: ScanRequest):
    try:
        subdomains = run_subfinder(scan_request.domain)
        conn = get_db_connection()
        cursor = conn.cursor()
        for sub in subdomains:
            cursor.execute("INSERT OR IGNORE INTO assets (domain, subdomain) VALUES (?, ?)", (scan_request.domain, sub))
        conn.commit()
        conn.close()
        return {"subdomains": subdomains}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/zap")
def start_zap_scan(scan_request: ZapScanRequest):
    try:
        findings = run_zap_scan(scan_request.target)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM assets WHERE subdomain = ?", (scan_request.target,))
        asset_id_row = cursor.fetchone()
        if not asset_id_row:
            cursor.execute("INSERT INTO assets (domain, subdomain) VALUES (?, ?)", (scan_request.target, scan_request.target))
            asset_id = cursor.lastrowid
        else:
            asset_id = asset_id_row["id"]
        
        for finding in findings:
            cursor.execute("INSERT INTO vulnerabilities (asset_id, finding, severity) VALUES (?, ?, ?)", 
                           (asset_id, finding['finding'], finding['severity']))
        conn.commit()
        conn.close()
        return {"vulnerabilities": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/nmap")
def start_nmap_scan(scan_request: NmapScanRequest):
    try:
        open_ports = run_nmap(scan_request.target)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM assets WHERE subdomain = ?", (scan_request.target,))
        asset_id_row = cursor.fetchone()
        if not asset_id_row:
            # This case should ideally not happen if discovery is run first, but as a fallback:
            cursor.execute("INSERT INTO assets (domain, subdomain) VALUES (?, ?)", (scan_request.target, scan_request.target))
            conn.commit()
            asset_id = cursor.lastrowid
        else:
            asset_id = asset_id_row["id"]

        for port_info in open_ports:
            cursor.execute("INSERT INTO vulnerabilities (asset_id, finding, severity) VALUES (?, ?, ?)",
                           (asset_id, f"Open Port: {port_info}", "info"))
        conn.commit()
        conn.close()
        return {"open_ports": open_ports}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
