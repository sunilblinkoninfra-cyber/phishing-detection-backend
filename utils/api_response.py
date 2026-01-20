from fastapi.responses import JSONResponse
from typing import Any, Optional


def success_response(
    data: Optional[Any] = None,
    status_code: int = 200
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": True,
            "data": data,
            "error": None
        }
    )


def error_response(
    message: str,
    status_code: int = 400
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "data": None,
            "error": message
        }
    )
