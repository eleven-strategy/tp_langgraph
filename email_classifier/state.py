"""
Part 1 -- State Schema
======================

In LangGraph, the **state** is the data structure that flows through the graph.
Every node reads from it and returns partial updates to it.

The state is defined as a Pydantic BaseModel. Each field has a type and a default
value. When a node returns {"threat_level": "dangerous"}, LangGraph merges that
into the current state, updating only that field.

TODO: fill in the three missing fields marked below.
Look at the existing fields for examples of how to declare them.
"""

from typing import Optional
from pydantic import BaseModel, Field


class EmailState(BaseModel):
    # -- Email metadata --
    # TODO: declare email_id as a str with a default of ""
    subject: str = ""
    body: str = ""
    sender: str = ""
    urls: list[str] = Field(default_factory=list)
    # TODO: declare has_attachments as a bool with a default of False

    # -- Analysis results (filled in by graph nodes) --
    url_check_result: Optional[dict] = None
    # TODO: declare content_analysis as an Optional[dict] with a default of None
    threat_level: str = ""
    response: str = ""
