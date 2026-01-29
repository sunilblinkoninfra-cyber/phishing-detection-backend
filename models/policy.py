from pydantic import BaseModel

class RiskPolicy(BaseModel):
    cold_threshold: int = 40
    warm_threshold: int = 75
    weights: dict
