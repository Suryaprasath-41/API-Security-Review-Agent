import os
import logging
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List

from app.config import UPLOAD_DIR, REPORT_DIR
from app.database import (
    init_db, 
    save_specification, 
    get_all_scans, 
    get_scan, 
    get_scan_findings, 
    get_scan_reports
)
from app.agents.graph import run_security_scan

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize FastAPI App
app = FastAPI(
    title="API Security Review Agent Backend",
    description="Automated OpenAPI/Swagger Security Review framework.",
    version="1.0.0"
)

# Enable CORS for local dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB on Startup
@app.on_event("startup")
def startup_event():
    logger.info("Initializing database schemas...")
    init_db()

@app.get("/")
def read_root():
    return {"message": "API Security Review Agent Backend is online and running."}

@app.post("/scan", response_model=Dict[str, Any])
async def upload_and_scan_spec(file: UploadFile = File(...)):
    """
    Uploads an OpenAPI specification file, saves it, and runs
    the LangGraph Security Agent workflow.
    """
    # Verify file extension
    filename = file.filename
    if not (filename.endswith(".json") or filename.endswith(".yaml") or filename.endswith(".yml")):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file format. Upload only OpenAPI specifications in JSON or YAML formats."
        )

    # Save spec file
    upload_path = Path(UPLOAD_DIR) / filename
    try:
        with open(upload_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save specification file: {e}")

    # Register spec in Database
    try:
        spec_id = save_specification(
            filename=filename,
            content_type=file.content_type or "application/octet-stream",
            file_path=str(upload_path)
        )
    except Exception as e:
        logger.error(f"Failed to save spec metadata to DB: {e}")
        raise HTTPException(status_code=500, detail="Database write failure.")

    # Trigger LangGraph Workflow synchronously for immediate display
    try:
        scan_id = run_security_scan(
            file_path=str(upload_path),
            filename=filename,
            spec_id=spec_id
        )
    except Exception as e:
        logger.error(f"Scan failed for spec_id {spec_id}: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Security scan agent encountered an error: {str(e)}"
        )

    return {
        "message": "Scan completed successfully",
        "scan_id": scan_id,
        "filename": filename
    }

@app.get("/scans", response_model=List[Dict[str, Any]])
def list_scans():
    """Lists all scans run in the history."""
    try:
        return get_all_scans()
    except Exception as e:
        logger.error(f"Error retrieving scans: {e}")
        raise HTTPException(status_code=500, detail="Database read failure.")

@app.get("/scans/{scan_id}", response_model=Dict[str, Any])
def read_scan_details(scan_id: int):
    """Retrieves metadata of a specific scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@app.get("/scans/{scan_id}/findings", response_model=List[Dict[str, Any]])
def read_scan_findings(scan_id: int):
    """Retrieves all vulnerability findings for a specific scan."""
    # Check if scan exists
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return get_scan_findings(scan_id)

@app.get("/scans/{scan_id}/reports", response_model=List[Dict[str, Any]])
def read_scan_reports(scan_id: int):
    """Retrieves report file records for a specific scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return get_scan_reports(scan_id)

@app.get("/reports/download")
def download_report_file(path: str):
    """Downloads a Markdown or PDF report by its system absolute path."""
    resolved_path = Path(path)
    if not resolved_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    
    # Confirm security check: prevent directory traversal outside report dir
    try:
        resolved_path.relative_to(Path(REPORT_DIR).parent)
    except ValueError:
        raise HTTPException(status_code=403, detail="Unauthorized path request.")
        
    return FileResponse(
        path=str(resolved_path), 
        filename=resolved_path.name,
        media_type="application/octet-stream"
    )
