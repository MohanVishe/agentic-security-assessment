"""The shapes of the request bodies the API accepts."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_url: str
    scope_notes: str = Field(default="", max_length=2000)
    test_username: str = Field(default="", max_length=200)
    test_password: str = Field(default="", max_length=200)
    # True: the Planner's plan waits for a person to approve or change it before any scanner runs.
    review_plan: bool = False


class AuthorizationRequest(BaseModel):
    confirmed: bool
    authorized_by: str = Field(default="", max_length=200)


class PlanApproval(BaseModel):
    tools: list[str] = Field(max_length=20)  # the tools the reviewer wants to run


class Event(BaseModel):
    agent: str = Field(max_length=40)
    message: str = Field(max_length=2000)
    data: dict = Field(default_factory=dict)
