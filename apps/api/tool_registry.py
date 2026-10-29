"""Single source of truth for every tool and its security metadata.

  action            read | create | write | delete | send | execute
                    (create = new file in the sandbox, never overwrites)
  sensitivity       0..1 base impact if misused
  untrusted_output  result may contain attacker-controlled text -> taints the run
  privileged        never auto-executed
  data_class        what kind of data the tool's OUTPUT is: public | internal | confidential.
                    The run/conversation remembers the most sensitive class it has
                    touched, and egress (email) is judged against that.
"""
from typing import Any

TOOLS: dict[str, dict[str, Any]] = {
    "file_reader": {
        "description": "Read a file: workspace samples (report.txt, project_notes.md, vendor_invoice.txt), files the user uploaded (uploads/<chat>/name) or files you created (outputs/<chat>/name). Supports txt, md, csv, json, pdf, docx, xlsx.",
        "action": "read", "sensitivity": 0.2, "untrusted_output": True, "privileged": False,
        "data_class": "internal",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path relative to the workspace, e.g. report.txt or uploads/<chat>/notes.pdf"}},
            "required": ["path"]},
    },
    "create_document": {
        "description": "Create a NEW file for the user (md, txt, csv, json, docx, xlsx). Use this to deliver summaries, reports and exports. For xlsx/csv give CSV text. Never overwrites anything.",
        "action": "create", "sensitivity": 0.25, "untrusted_output": False, "privileged": False,
        "parameters": {"type": "object", "properties": {
            "filename": {"type": "string", "description": "e.g. report_summary.docx"},
            "content": {"type": "string", "description": "Text/markdown content, or CSV text for xlsx/csv."}},
            "required": ["filename", "content"]},
    },
    "modify_file_copy": {
        "description": "Edit a COPY of an existing file (the original is never changed). Text/docx: append_text and/or find/replace. xlsx/csv: cell_updates like {\"B2\": 5} and/or append_rows.",
        "action": "create", "sensitivity": 0.35, "untrusted_output": False, "privileged": False,
        "parameters": {"type": "object", "properties": {
            "source_path": {"type": "string"},
            "output_name": {"type": "string", "description": "Optional name for the edited copy."},
            "append_text": {"type": "string"},
            "find": {"type": "string"},
            "replace": {"type": "string"},
            "cell_updates": {"type": "object", "description": "xlsx only: {\"A1\": value} or {\"Sheet1!A1\": value}"},
            "append_rows": {"type": "array", "items": {"type": "array"}, "description": "xlsx/csv rows to add"}},
            "required": ["source_path"]},
    },
    "web_fetch": {
        "description": "Fetch readable text from a web page. Well-known sites are allowed; unknown sites need human review; paste/exfiltration sites are blocked.",
        "action": "read", "sensitivity": 0.3, "untrusted_output": True, "privileged": False,
        "data_class": "public",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    "weather_lookup": {
        "description": "Current weather and up to a 5-day daily forecast for a city (OpenWeather API).",
        "action": "read", "sensitivity": 0.1, "untrusted_output": False, "privileged": False,
        "data_class": "public",
        "parameters": {"type": "object", "properties": {
            "city": {"type": "string"},
            "days": {"type": "integer", "description": "Forecast days, 1-5 (default 1)"}},
            "required": ["city"]},
    },
    "database_query": {
        "description": "Run ONE read-only SELECT on the business database. Tables: customers(id,name,email,company,plan,region,created_at), orders(id,customer_id,product,amount,status,created_at), tickets(id,customer_id,subject,status,priority,created_at), notes(id,author,content,created_at).",
        "action": "read", "sensitivity": 0.35, "untrusted_output": True, "privileged": False,
        "data_class": "confidential",
        "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
    },
    "database_writer": {
        "description": "Insert, update or delete a row in the business database. Writable: tickets, notes, orders (insert/update); tickets, notes (delete). update/delete need the row id.",
        "action": "write", "sensitivity": 0.6, "untrusted_output": False, "privileged": False,
        "parameters": {"type": "object", "properties": {
            "table": {"type": "string"},
            "operation": {"type": "string", "description": "insert | update | delete (default insert)"},
            "id": {"type": "integer", "description": "Row id for update/delete"},
            "values": {"type": "object", "description": "Column/value pairs"}},
            "required": ["table"]},
    },
    "email_sender": {
        "description": "Send a real email (Gmail). Can attach files you created in this chat (outputs/...).",
        "action": "send", "sensitivity": 0.7, "untrusted_output": False, "privileged": False,
        "parameters": {"type": "object", "properties": {
            "to": {"type": "string", "description": "Recipient address(es), comma separated"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
            "attachments": {"type": "array", "items": {"type": "string"}, "description": "Paths of files you created"}},
            "required": ["to", "subject", "body"]},
    },
    "handoff_to_agent": {
        "description": "Delegate the rest of the task to another agent when a step needs a tool you don't have. Give the agent's exact name and clear instructions, including paths of files you created.",
        "action": "delegate", "sensitivity": 0.05, "untrusted_output": False, "privileged": False,
        "parameters": {"type": "object", "properties": {
            "agent": {"type": "string", "description": "Exact agent name"},
            "instructions": {"type": "string", "description": "What that agent should do next"}},
            "required": ["agent", "instructions"]},
    },
    "admin_shell": {
        "description": "Execute a privileged administrative shell command.",
        "action": "execute", "sensitivity": 1.0, "untrusted_output": False, "privileged": True,
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
    },
}


def get_tool(tool_name: str) -> dict[str, Any] | None:
    return TOOLS.get(tool_name)


def resolve_action(tool_name: str, arguments: dict[str, Any]) -> str:
    """Some tools' real action depends on the arguments."""
    tool = TOOLS.get(tool_name)
    if tool is None:
        return "unknown"
    if tool_name == "database_writer" and str(arguments.get("operation", "")).lower() == "delete":
        return "delete"
    return tool["action"]


def list_tools() -> list[dict[str, Any]]:
    return [{"name": name, **definition} for name, definition in TOOLS.items()]


def get_ollama_tools(names: list[str] | None = None) -> list[dict[str, Any]]:
    selected = names if names is not None else list(TOOLS.keys())
    return [
        {"type": "function", "function": {
            "name": n, "description": TOOLS[n]["description"], "parameters": TOOLS[n]["parameters"]}}
        for n in selected if n in TOOLS
    ]
