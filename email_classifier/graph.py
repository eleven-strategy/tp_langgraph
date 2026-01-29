"""
Part 3 -- Graph Declaration
===========================

A LangGraph **graph** connects nodes with edges to form a workflow.

Key concepts:
  - StateGraph(StateClass)       -- create a graph bound to a state schema
  - graph.add_node(name, fn)     -- register a node function
  - graph.set_entry_point(name)  -- which node runs first
  - graph.add_edge(a, b)         -- after node a, always go to node b
  - graph.add_conditional_edges(
        source,                  -- the node whose output we inspect
        routing_fn,              -- a function that returns the next node name
        path_map                 -- dict mapping return values -> node names
    )
  - END                          -- special constant meaning "stop the graph"
  - graph.compile()              -- finalize and return a runnable graph

TODO: complete the three TODOs in build_email_classifier() below.
"""

from langgraph.graph import StateGraph, END
from email_classifier.state import EmailState
from email_classifier.nodes import (
    check_urls,
    analyze_content,
    classify_email,
    generate_response,
)


# ---------- Routing function (provided) ----------

def route_after_analysis(state: dict) -> str:
    """Decide the next node after analyze_content.

    If the URL check already found malicious URLs, skip classification
    and go straight to generate_response. Otherwise, go to classify_email.
    """
    if not state.get("url_check_result", {}).get("safe", True):
        return "generate_response"
    return "classify_email"


# ---------- Graph builder ----------

def build_email_classifier():
    """Build and compile the email classifier graph.

    The graph looks like this:

        check_urls ──> analyze_content ──?──> classify_email ──> generate_response ──> END
                                         │                              ▲
                                         └── (malicious URLs) ─────────┘
    """
    workflow = StateGraph(EmailState)

    # -- Nodes --
    workflow.add_node("check_urls", check_urls)
    workflow.add_node("analyze_content", analyze_content)
    # TODO: add the "classify_email" node
    workflow.add_node("generate_response", generate_response)

    # -- Entry point --
    workflow.set_entry_point("check_urls")

    # -- Edges --
    workflow.add_edge("check_urls", "analyze_content")

    workflow.add_conditional_edges(
        "analyze_content",
        route_after_analysis,
        {
            "classify_email": "classify_email",
            "generate_response": "generate_response",
        },
    )

    # TODO: add a normal edge from "classify_email" to "generate_response"

    workflow.add_edge("generate_response", END)

    return workflow.compile()
