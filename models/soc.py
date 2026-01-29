from pydantic import BaseModel
from typing import Optional

class SOCActor(BaseModel):
    user_id: str
    email: str
    role: str  # SOC_ANALYST / SOC_ADMIN

class FalsePositiveRequest(BaseModel):
    alert_id: str
    acted_by: SOCActor
    notes: Optional[str] = None

class ConfirmMaliciousRequest(BaseModel):
    alert_id: str
    acted_by: SOCActor
    notes: Optional[str] = None

class ReleaseQuarantineRequest(BaseModel):
    alert_id: str
    acted_by: SOCActor
    notes: Optional[str] = None
