"""MailPal MCP server -- free email for AI agents with hardware attestation.

Thin REST API client wrapping https://mailpal.com/api/v1/* into MCP tools.
Hardware attestation is ON by default (attestation_mode=2).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

MAILPAL_REST_API_BASE_URL = os.environ.get("MAILPAL_API_URL", "https://mailpal.com/api/v1")
MAILPAL_BEARER_AUTH_TOKEN = os.environ.get("MAILPAL_TOKEN", "")

inbox_sse_background_task: asyncio.Task[None] | None = None
subscribed_inbox_resource_uri: str | None = None

mailpal_mcp_server_instance = FastMCP(
  "mailpal",
  version="1.0.0",
  instructions=(
    "MailPal provides free email for AI agents with hardware attestation. "
    "Every agent gets a real @mailpal.com address with full SMTP/IMAP/JMAP/CalDAV/CardDAV. "
    "Use mailpal_activate_account first if you don't have an account yet. "
    "Use mailpal_send_email to send (hardware attestation is ON by default). "
    "Use mailpal_check_inbox and mailpal_read_message to read email. "
    "Use mailpal_subscribe_to_inbox for real-time new-mail notifications. "
    "Use mailpal_jmap for any JMAP operation not covered by convenience tools "
    "(delete, move, flag, search, folders, contacts, calendars, sieve filters, etc.)."
  ),
)


async def send_authenticated_request_to_mailpal_rest_api(
  api_endpoint_path: str,
  http_method: str = "GET",
  json_request_body: dict[str, Any] | None = None,
  url_query_parameters: dict[str, str] | None = None,
) -> dict[str, Any]:
  """Send an authenticated HTTP request to the MailPal REST API."""
  full_request_url = f"{MAILPAL_REST_API_BASE_URL}{api_endpoint_path}"

  http_request_headers: dict[str, str] = {
    "Accept": "application/json",
    "User-Agent": "mailpal-mcp-python/1.0.0",
  }
  if MAILPAL_BEARER_AUTH_TOKEN:
    http_request_headers["Authorization"] = f"Bearer {MAILPAL_BEARER_AUTH_TOKEN}"

  async with httpx.AsyncClient() as http_client:
    http_response = await http_client.request(
      method=http_method,
      url=full_request_url,
      headers=http_request_headers,
      json=json_request_body,
      params=url_query_parameters,
    )

  parsed_response_json: dict[str, Any] = http_response.json()

  if not http_response.is_success:
    error_field = parsed_response_json.get("error", f"HTTP {http_response.status_code}")
    if isinstance(error_field, dict):
      error_field = error_field.get("message", f"HTTP {http_response.status_code}")
    raise RuntimeError(f"MailPal API error: {error_field}")

  return parsed_response_json


# Tool 1: mailpal_activate_account -- Two-phase POI account provisioning
@mailpal_mcp_server_instance.tool()
async def mailpal_activate_account(
  challenge_token: str | None = None,
  challenge_answer: str | None = None,
  display_name: str | None = None,
) -> str:
  """Activate a @mailpal.com email account for this agent.

  Two-phase Proof-of-Intelligence flow:
  Phase 1 (omit challenge fields): returns a POI challenge the agent must solve.
  Phase 2 (include challenge_token + challenge_answer): verifies and creates the account.
  Idempotent: returns existing account info if already activated.
  """
  activate_request_body: dict[str, Any] = {}
  if challenge_token:
    activate_request_body["challenge_token"] = challenge_token
  if challenge_answer:
    activate_request_body["challenge_answer"] = challenge_answer
  if display_name:
    activate_request_body["display_name"] = display_name

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/activate", "POST", activate_request_body,
  )
  return json.dumps(api_response, indent=2)


# Tool 2: mailpal_send_email -- Hardware attestation ON by default (mode 2)
@mailpal_mcp_server_instance.tool()
async def mailpal_send_email(
  to: list[str],
  subject: str,
  text: str | None = None,
  html: str | None = None,
  cc: list[str] | None = None,
  bcc: list[str] | None = None,
  reply_to: str | None = None,
  in_reply_to: str | None = None,
  from_address: str | None = None,
  from_display_name: str | None = None,
  attestation_mode: int = 2,
) -> str:
  """Send an email from the agent's @mailpal.com address.

  Hardware attestation is ON by default (attestation_mode=2: issuer-mediated SD-JWT via 1id.com).
  This is MailPal's core purpose: proving emails come from real hardware.
  Set attestation_mode=1 for direct TPM CMS (sovereign tier only, maximum trust).
  Set attestation_mode=0 for no attestation (fallback for declared/virtual tiers).
  If your trust tier is too low for the requested mode, returns an error (never silently downgrades).
  For attachments, use mailpal_jmap with Blob/upload + Email/set + EmailSubmission/set.
  """
  email_composition_fields: dict[str, Any] = {"to": to, "subject": subject}
  if text:
    email_composition_fields["text"] = text
  if html:
    email_composition_fields["html"] = html
  if cc:
    email_composition_fields["cc"] = cc
  if bcc:
    email_composition_fields["bcc"] = bcc
  if reply_to:
    email_composition_fields["reply_to"] = reply_to
  if in_reply_to:
    email_composition_fields["in_reply_to"] = in_reply_to
  if from_address:
    email_composition_fields["from"] = from_address
  if from_display_name:
    email_composition_fields["from_display_name"] = from_display_name

  if attestation_mode == 0:
    api_response = await send_authenticated_request_to_mailpal_rest_api(
      "/send", "POST", email_composition_fields,
    )
    return json.dumps(api_response, indent=2)

  prepare_phase_response = await send_authenticated_request_to_mailpal_rest_api(
    "/send/prepare", "POST", email_composition_fields,
  )
  prepare_token_value = prepare_phase_response.get("data", {}).get("prepare_token")
  if not prepare_token_value:
    return json.dumps(prepare_phase_response, indent=2)

  commit_phase_response = await send_authenticated_request_to_mailpal_rest_api(
    "/send/commit", "POST", {
      "prepare_token": prepare_token_value,
      "attestation_mode": attestation_mode,
    },
  )
  return json.dumps(commit_phase_response, indent=2)


# Tool 3: mailpal_check_inbox -- Inbox summaries
@mailpal_mcp_server_instance.tool()
async def mailpal_check_inbox(
  limit: int = 20,
  offset: int = 0,
  unread_only: bool = False,
) -> str:
  """Check inbox for new or unread messages. Returns summaries (sender, subject, date, preview), not full bodies.

  Use mailpal_read_message to get full content of a specific message.
  """
  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/inbox", "GET", url_query_parameters={
      "limit": str(limit),
      "offset": str(offset),
      "unread_only": str(unread_only).lower(),
    },
  )
  return json.dumps(api_response, indent=2)


# Tool 4: mailpal_read_message -- Full message content
@mailpal_mcp_server_instance.tool()
async def mailpal_read_message(message_id: str) -> str:
  """Read the full content of a specific email message including text body, HTML body, headers, and all metadata."""
  from urllib.parse import quote

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    f"/inbox/{quote(message_id, safe='')}",
  )
  return json.dumps(api_response, indent=2)


# Tool 5: mailpal_subscribe_to_inbox -- Real-time push via background SSE
async def _start_background_sse_listener_for_inbox_event_notifications() -> None:
  """Connect to the MailPal SSE endpoint and relay new-mail events as MCP notifications."""
  global inbox_sse_background_task, subscribed_inbox_resource_uri

  async def _connect_to_sse_and_relay_events() -> None:
    while True:
      try:
        async with httpx.AsyncClient() as http_client:
          async with http_client.stream(
            "GET",
            f"{MAILPAL_REST_API_BASE_URL}/inbox/events",
            headers={
              "Authorization": f"Bearer {MAILPAL_BEARER_AUTH_TOKEN}",
              "Accept": "text/event-stream",
              "Cache-Control": "no-cache",
            },
            timeout=None,
          ) as sse_stream_response:
            if not sse_stream_response.is_success:
              break
            async for line_of_sse_data in sse_stream_response.aiter_lines():
              if line_of_sse_data.startswith("data:") and subscribed_inbox_resource_uri:
                try:
                  await mailpal_mcp_server_instance._mcp_server.request_context.session.send_resource_updated(
                    uri=subscribed_inbox_resource_uri,
                  )
                except Exception:
                  pass
      except (httpx.HTTPError, OSError):
        await asyncio.sleep(5)
      except asyncio.CancelledError:
        return

  inbox_sse_background_task = asyncio.create_task(_connect_to_sse_and_relay_events())


@mailpal_mcp_server_instance.tool()
async def mailpal_subscribe_to_inbox() -> str:
  """Subscribe to real-time new-mail notifications for this agent's inbox.

  Once subscribed, the server pushes notifications/resources/updated when new mail arrives.
  Call mailpal_check_inbox after receiving a notification to see what's new.
  Works on both stdio and Streamable HTTP transports.
  """
  global subscribed_inbox_resource_uri

  if not MAILPAL_BEARER_AUTH_TOKEN:
    return json.dumps({
      "error": "MAILPAL_TOKEN environment variable is required for inbox subscription",
      "subscribed": False,
    }, indent=2)

  agent_identifier_from_jwt_subject_claim = "unknown"
  try:
    jwt_payload_segment = MAILPAL_BEARER_AUTH_TOKEN.split(".")[1]
    padding_needed = 4 - len(jwt_payload_segment) % 4
    if padding_needed < 4:
      jwt_payload_segment += "=" * padding_needed
    decoded_jwt_payload = json.loads(base64.urlsafe_b64decode(jwt_payload_segment))
    agent_identifier_from_jwt_subject_claim = decoded_jwt_payload.get("sub", "unknown")
  except Exception:
    pass

  subscribed_inbox_resource_uri = f"mailpal://inbox/{agent_identifier_from_jwt_subject_claim}"

  await _start_background_sse_listener_for_inbox_event_notifications()

  return json.dumps({
    "subscribed": True,
    "uri": subscribed_inbox_resource_uri,
    "transport": "stdio",
    "message": "Listening for new mail. You will receive notifications/resources/updated when new email arrives.",
  }, indent=2)


# Tool 6: mailpal_jmap -- Raw JMAP passthrough (escape hatch)
@mailpal_mcp_server_instance.tool()
async def mailpal_jmap(
  method_calls: list[list[Any]],
  using: list[str] | None = None,
) -> str:
  """Send raw JMAP method calls through the authenticated MailPal proxy.

  Use for any operation not covered by convenience tools:
  delete messages, move between folders, flag/unflag, search, manage folders,
  contacts (CardDAV), calendars (CalDAV), sieve filters, blob upload for attachments,
  identity management -- anything JMAP (RFC 8620/8621) supports.
  The accountId is auto-injected by the server.

  Common patterns:
  Delete: [["Email/set", {"destroy": ["id1"]}, "d1"]]
  Move: [["Email/set", {"update": {"id1": {"mailboxIds": {"folder": true}}}}, "m1"]]
  Mark read: [["Email/set", {"update": {"id1": {"keywords/$seen": true}}}, "r1"]]
  Flag: [["Email/set", {"update": {"id1": {"keywords/$flagged": true}}}, "f1"]]
  Search: [["Email/query", {"filter": {"text": "invoice"}, "limit": 20}, "s1"],
           ["Email/get", {"#ids": {"resultOf": "s1", ...}, "properties": [...]}, "s2"]]
  List folders: [["Mailbox/query", {}, "mq"],
                 ["Mailbox/get", {"#ids": {"resultOf": "mq", ...}, "properties": [...]}, "mg"]]
  """
  if using is None:
    using = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": using,
      "methodCalls": method_calls,
    },
  )
  return json.dumps(api_response, indent=2)


def main() -> None:
  """Entry point for the mailpal-mcp CLI command."""
  mailpal_mcp_server_instance.run(transport="stdio")


if __name__ == "__main__":
  main()
