"""
Azure Function (Python v2 programming model) that exposes the scorer over HTTP.
The Sentinel playbook POSTs the incident's entities here and gets back a verdict.

Request body:
  { "entities": [ ...Sentinel relatedEntities... ],
    "protectedDomains": ["contoso.com"] }            # optional
Response:
  { "score": 85, "verdict": "malicious", "signals": [...], "sender": "...", "subject": "..." }
"""
import json
import logging
import os

import azure.functions as func

from triage import email_from_sentinel_entities, score_email

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

DEFAULT_PROTECTED = {d.strip().lower() for d in
                     os.environ.get("PROTECTED_DOMAINS", "contoso.com").split(",") if d.strip()}


@app.route(route="score", methods=["POST"])
def score(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Body must be JSON", status_code=400)

    entities = body.get("entities") or []
    protected = {d.lower() for d in body.get("protectedDomains") or []} or DEFAULT_PROTECTED

    email = email_from_sentinel_entities(entities)
    if email is None:
        # Not an email incident: tell the playbook to leave it for a human.
        result = {"score": None, "verdict": "no_mail_entity", "signals": []}
    else:
        r = score_email(email, protected)
        result = {**r.as_dict(), "sender": email.sender_address, "subject": email.subject}

    # Log the decision (not the content) for auditability.
    logging.info("triage verdict=%s score=%s signals=%s",
                 result["verdict"], result["score"], ",".join(result["signals"]))
    return func.HttpResponse(json.dumps(result), mimetype="application/json")
