"""
Part 3 -- Graph Declaration
===========================

A LangGraph **graph** connects nodes with edges to form a workflow.

Key concepts:
  - StateGraph(StateClass)       -- create a graph bound to a state schema
  - graph.add_node(name, fn)     -- register a node function
  - graph.add_edge(START, name)  -- set which node runs first
  - graph.add_edge(a, b)         -- after node a, always go to node b
  - graph.add_conditional_edges(
        source,                  -- the node whose output we inspect
        routing_fn,              -- a function that returns the next node name
        path_map                 -- dict mapping return values -> node names
    )
  - START                        -- special constant: the graph's entry point
  - END                          -- special constant: stop the graph
  - graph.compile()              -- finalize and return a runnable graph

TODO: complete the two TODOs in build_email_classifier() below.
"""

from langgraph.graph import StateGraph, START, END
from email_classifier.state import EmailState
from email_classifier.nodes import (
    check_urls,
    analyze_content,
    generate_response,
)


# ---------- Routing function (provided) ----------

def route_after_urls(state: EmailState) -> str:
    """Decide the next node after check_urls.

    If malicious URLs were found, skip straight to generate_response
    (threat_level is already set to "dangerous" by check_urls).
    Otherwise, continue to analyze_content.
    """
    if state.url_check_result and not state.url_check_result["safe"]:
        return "generate_response"
    return "analyze_content"


# ---------- Graph builder ----------

def build_email_classifier():
    """Build and compile the email classifier graph.

    The graph looks like this:

        check_urls ──?──> analyze_content ──> generate_response ──> END
                     │                                ▲
                     └── (malicious URLs) ────────────┘
    """
    workflow = StateGraph(EmailState)

    # -- Nodes --
    workflow.add_node("check_urls", check_urls)
    # TODO: add the "analyze_content" node
    workflow.add_node("generate_response", generate_response)

    # -- Edges --
    workflow.add_edge(START, "check_urls")

    workflow.add_conditional_edges(
        "check_urls",
        route_after_urls,
        {
            "analyze_content": "analyze_content",
            "generate_response": "generate_response",
        },
    )

    # TODO: add a normal edge from "analyze_content" to "generate_response"

    workflow.add_edge("generate_response", END)

    return workflow.compile()
