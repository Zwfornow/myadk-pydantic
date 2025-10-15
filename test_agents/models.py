from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field, validator


class ScanRequest(BaseModel):
    ip_address: str
    scan_type: str = Field("quick", description="quick, full, port")

    @validator("scan_type")
    def validate_scan_type(cls, v: str) -> str:
        allowed = {"quick", "full", "port"}
        if v not in allowed:
            raise ValueError(f"unsupported scan_type: {v}. allowed: {', '.join(allowed)}")
        return v


class ScanData(BaseModel):
    ip_address: str
    scan_type: str
    open_ports: List[int]
    vulnerabilities: List[str]
    risk_level: str
    recommendations: List[str]
    scan_timestamp: str


class ScanResult(BaseModel):
    status: str
    report: Optional[str] = None
    data: Optional[ScanData] = None
    error_message: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "status": "success",
                "report": "...",
                "data": {
                    "ip_address": "192.168.1.1",
                    "scan_type": "quick",
                    "open_ports": [22, 80],
                    "vulnerabilities": ["SSH open"],
                    "risk_level": "medium",
                    "recommendations": ["close telnet"],
                    "scan_timestamp": "2025-10-15 12:00:00",
                }
            }
        }
