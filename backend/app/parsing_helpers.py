from fastapi import HTTPException
from .routers.common import parse_target


def parse_target_simple(value: str) -> dict:
    try:
        return parse_target(value)
    except HTTPException as e:
        raise ValueError(e.detail)
