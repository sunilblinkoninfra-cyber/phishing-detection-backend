from enum import Enum
from pydantic import BaseModel
from typing import Dict, List

class EmailCategory(str, Enum):
    COLD = "COLD"
    WARM = "WARM"
    HOT  = "HOT"

class Decision(str, Enum):
    ALLOW      = "ALLOW"
    BLOCK      = "BLOCK"
    QUARANTINE = "QUARANTINE"

class EmailDecision(BaseModel):
    email_id   : str
    risk_score : int
    category   : EmailCategory
    decision   : Decision
    findings   : Dict[str, object]
