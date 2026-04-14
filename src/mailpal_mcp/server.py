"""MailPal MCP server -- SDK-backed email + identity tools for AI agents.

Delegates to the `oneid` Python SDK for all operations involving the agent's
cryptographic identity. The SDK handles TPM authentication, MIME message
assembly, attestation computation, header injection, and direct SMTP submission.

attestation_mode=3 (both Mode 1 direct-CMS + Mode 2 SD-JWT) is the default.

Three REST API tools remain for operations the SDK doesn't yet cover:
  mailpal_read_message, mailpal_subscribe_to_inbox, mailpal_jmap.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import mimetypes
import os
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

import oneid
import oneid.mailpal
import oneid.devices
import oneid.credential_pointers

MAILPAL_REST_API_BASE_URL = os.environ.get("MAILPAL_API_URL", "https://mailpal.com/api/v1")
MAILPAL_BEARER_AUTH_TOKEN = os.environ.get("MAILPAL_TOKEN", "")

inbox_sse_background_task: asyncio.Task[None] | None = None
subscribed_inbox_resource_uri: str | None = None
bearer_token_for_active_sse_inbox_connection: str = ""
pending_inbox_state_change_futures: list[asyncio.Future[str]] = []
captured_mcp_session_for_background_notifications: Any = None

registered_email_arrival_callbacks: list[dict[str, Any]] = []

_ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING = {
  0: "none",
  1: "direct",
  2: "sd-jwt",
  3: "both",
}


def _serialize_sdk_dataclass_to_json_string(sdk_result_object: Any) -> str:
  """Serialize an SDK dataclass (or list/dict) to a JSON string.

  Handles datetime, Enum, and nested dataclass fields via default=str.
  Strips raw_response fields to avoid bloating output.
  """
  if dataclasses.is_dataclass(sdk_result_object) and not isinstance(sdk_result_object, type):
    raw_dict = dataclasses.asdict(sdk_result_object)
    raw_dict.pop("raw_response", None)
  elif isinstance(sdk_result_object, dict):
    raw_dict = sdk_result_object
  elif isinstance(sdk_result_object, list):
    raw_dict = {
      "items": [
        dataclasses.asdict(item) if (dataclasses.is_dataclass(item) and not isinstance(item, type)) else item
        for item in sdk_result_object
      ]
    }
  else:
    raw_dict = {"result": str(sdk_result_object)}
  return json.dumps(raw_dict, indent=2, default=str)


mailpal_mcp_server_instance = FastMCP(
  "mailpal",
  instructions=(
    "MailPal provides free email for AI agents with hardware attestation. "
    "Every agent gets a real @mailpal.com address with full SMTP/IMAP/JMAP. "
    "Use mailpal_activate_account first if you don't have an account yet. "
    "Use mailpal_send_email to send (Mode 1+2 attestation is ON by default). "
    "Use mailpal_check_inbox and mailpal_read_message to read email. "
    "Use mailpal_subscribe_to_inbox for real-time new-mail notifications. "
    "Use mailpal_jmap for any JMAP operation not covered by convenience tools. "
    "Identity tools (oneid_*) manage your hardware-anchored identity, devices, "
    "peer verification, and credential pointers."
  ),
)


async def _execute_registered_email_arrival_callbacks_on_new_mail(event_data: str) -> None:
  """Fire all registered webhook callbacks when new email arrives."""
  for callback in registered_email_arrival_callbacks:
    try:
      if callback.get("callback_type") == "webhook" and callback.get("webhook_url"):
        webhook_payload = {
          "event": "new_email",
          "callback_id": callback["callback_id"],
          "uri": subscribed_inbox_resource_uri or "mailpal://inbox",
          "timestamp": asyncio.get_event_loop().time(),
          "raw_event": event_data,
        }
        async with httpx.AsyncClient(timeout=10.0) as http_client:
          await http_client.request(
            method=callback.get("webhook_method", "POST"),
            url=callback["webhook_url"],
            headers={"Content-Type": "application/json", **(callback.get("webhook_headers") or {})},
            content=json.dumps(webhook_payload),
          )
    except Exception:
      pass


# ========================================================================
# REST API helper (for tools not yet backed by SDK)
# ========================================================================

async def send_authenticated_request_to_mailpal_rest_api(
  api_endpoint_path: str,
  http_method: str = "GET",
  json_request_body: dict[str, Any] | None = None,
  url_query_parameters: dict[str, str] | None = None,
  bearer_token_for_this_request: str | None = None,
) -> dict[str, Any]:
  """Send an authenticated HTTP request to the MailPal REST API."""
  full_request_url = f"{MAILPAL_REST_API_BASE_URL}{api_endpoint_path}"

  effective_bearer_token = bearer_token_for_this_request or MAILPAL_BEARER_AUTH_TOKEN
  http_request_headers: dict[str, str] = {
    "Accept": "application/json",
    "User-Agent": "mailpal-mcp-python/1.0.0",
  }
  if effective_bearer_token:
    http_request_headers["Authorization"] = f"Bearer {effective_bearer_token}"

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


# ========================================================================
# SDK-backed MailPal tools
# ========================================================================

@mailpal_mcp_server_instance.tool()
def mailpal_activate_account(
  challenge_token: str | None = None,
  challenge_answer: str | None = None,
  display_name: str | None = None,
) -> str:
  """Activate a @mailpal.com email account for this agent.

  Two-phase Proof-of-Intelligence flow:
  Phase 1 (omit challenge fields): returns a challenge the agent must solve.
  Phase 2 (include challenge_token + challenge_answer): verifies and creates the account.
  Idempotent: returns existing account info if already activated.
  Uses the local 1id identity for authentication (TPM challenge-response).
  """
  result = oneid.mailpal.activate(
    challenge_token=challenge_token,
    challenge_answer=challenge_answer,
    display_name=display_name,
  )
  result_dict = dataclasses.asdict(result) if dataclasses.is_dataclass(result) else dict(result)
  if isinstance(result, oneid.mailpal.MailpalActivationChallenge):
    result_dict["_type"] = "challenge"
  else:
    result_dict["_type"] = "account"
  return json.dumps(result_dict, indent=2, default=str)


@mailpal_mcp_server_instance.tool()
def mailpal_send_email(
  to: list[str],
  subject: str,
  text: str | None = None,
  html: str | None = None,
  cc: list[str] | None = None,
  bcc: list[str] | None = None,
  from_address: str | None = None,
  from_display_name: str | None = None,
  reply_to: str | None = None,
  in_reply_to: str | None = None,
  references: str | None = None,
  attachments: list[dict[str, Any]] | None = None,
  attestation_mode: int = 3,
) -> str:
  """Send an email from the agent's @mailpal.com address with hardware attestation.

  attestation_mode=3 (default): Both Mode 1 (direct CMS) and Mode 2 (SD-JWT).
  attestation_mode=2: Mode 2 only (SD-JWT via 1id.com).
  attestation_mode=1: Mode 1 only (direct TPM CMS, sovereign tier).
  attestation_mode=0: No attestation headers.
  Mode 1 is silently skipped if the identity lacks a certificate chain.

  Builds the MIME message locally, computes attestation from exact wire bytes,
  and submits directly via SMTP to smtp.mailpal.com (no REST API intermediary).

  Supports file attachments via the attachments parameter. Each attachment dict:
    file_path: Local file path to attach (reads from disk)
    content_base64: Base64-encoded content (alternative to file_path)
    filename: Override filename (defaults to basename of file_path)
    content_type: MIME type (auto-detected from extension if omitted)
    inline: If true, attach inline for HTML cid: references
    content_id: Content-ID for inline images (used with cid: in HTML)

  For email threading, set in_reply_to to the Message-ID of the email being replied to,
  and references to the space-separated chain of Message-IDs in the thread.
  """
  sdk_attestation_mode_string = _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING.get(attestation_mode, "both")

  sdk_attachments = None
  if attachments:
    sdk_attachments = []
    for attachment_spec in attachments:
      if attachment_spec.get("file_path"):
        absolute_file_path = Path(attachment_spec["file_path"]).resolve()
        if not absolute_file_path.exists():
          raise FileNotFoundError(f"Attachment file not found: {absolute_file_path}")
        file_bytes = absolute_file_path.read_bytes()
        encoded_content = base64.b64encode(file_bytes).decode("ascii")
        resolved_filename = attachment_spec.get("filename") or absolute_file_path.name
      elif attachment_spec.get("content_base64"):
        encoded_content = attachment_spec["content_base64"]
        resolved_filename = attachment_spec.get("filename", "attachment")
      else:
        raise ValueError("Each attachment must have either file_path or content_base64")

      guessed_mime_type, _ = mimetypes.guess_type(resolved_filename)
      resolved_content_type = attachment_spec.get("content_type") or guessed_mime_type or "application/octet-stream"

      sdk_attachments.append({
        "filename": resolved_filename,
        "content_base64": encoded_content,
        "content_type": resolved_content_type,
        "inline": attachment_spec.get("inline", False),
        "content_id": attachment_spec.get("content_id"),
      })

  result = oneid.mailpal.send(
    to=to,
    subject=subject,
    text_body=text,
    html_body=html,
    cc=cc,
    bcc=bcc,
    from_address=from_address,
    from_display_name=from_display_name,
    reply_to=reply_to,
    in_reply_to=in_reply_to,
    references=references,
    attachments=sdk_attachments,
    attestation_mode=sdk_attestation_mode_string,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def mailpal_check_inbox(
  limit: int = 20,
  offset: int = 0,
  unread_only: bool = False,
) -> str:
  """Check inbox for new or unread messages. Returns summaries (sender, subject, date).

  Use mailpal_read_message to get full content of a specific message.
  Uses the local 1id identity for authentication.
  """
  messages = oneid.mailpal.inbox(
    limit=limit,
    offset=offset,
    unread_only=unread_only,
  )
  return json.dumps(
    {"messages": [dataclasses.asdict(msg) for msg in messages]},
    indent=2,
    default=str,
  )


# ========================================================================
# REST API-backed MailPal tools (SDK doesn't cover these yet)
# ========================================================================

@mailpal_mcp_server_instance.tool()
async def mailpal_read_message(message_id: str) -> str:
  """Read the full content of a specific email message including text body, HTML body,
  attachment metadata, attestation headers, threading info (messageId, inReplyTo, references),
  and all other metadata. Authenticates automatically using the SDK's TPM identity.
  """
  from urllib.parse import quote

  sdk_token = oneid.get_token()
  api_response = await send_authenticated_request_to_mailpal_rest_api(
    f"/inbox/{quote(message_id, safe='')}", bearer_token_for_this_request=sdk_token.access_token,
  )
  return json.dumps(api_response, indent=2)


async def _start_background_sse_listener_for_inbox_event_notifications() -> None:
  """Connect to the MailPal SSE endpoint and relay new-mail events as MCP notifications."""
  global inbox_sse_background_task, subscribed_inbox_resource_uri, pending_inbox_state_change_futures

  async def _connect_to_sse_and_relay_events() -> None:
    global pending_inbox_state_change_futures
    reconnect_delay = 1.0
    while True:
      try:
        effective_sse_token = bearer_token_for_active_sse_inbox_connection or MAILPAL_BEARER_AUTH_TOKEN
        async with httpx.AsyncClient() as http_client:
          async with http_client.stream(
            "GET",
            f"{MAILPAL_REST_API_BASE_URL}/inbox/events",
            headers={
              "Authorization": f"Bearer {effective_sse_token}",
              "Accept": "text/event-stream",
              "Cache-Control": "no-cache",
            },
            timeout=None,
          ) as sse_stream_response:
            if not sse_stream_response.is_success:
              break

            reconnect_delay = 1.0
            current_event_type = ""
            current_data_lines: list[str] = []

            async for raw_line in sse_stream_response.aiter_lines():
              if raw_line.startswith("event:"):
                current_event_type = raw_line[6:].strip()
              elif raw_line.startswith("data:"):
                current_data_lines.append(raw_line[5:].strip())
              elif raw_line.startswith(":"):
                pass
              elif raw_line.strip() == "":
                if current_data_lines:
                  event_type = current_event_type or "state_change"
                  event_data = "\n".join(current_data_lines)

                  if event_type in ("state_change", "StateChange", "state"):
                    session = captured_mcp_session_for_background_notifications

                    if session and subscribed_inbox_resource_uri:
                      try:
                        await session.send_resource_updated(uri=subscribed_inbox_resource_uri)
                      except Exception:
                        pass

                    if session:
                      try:
                        await session.send_log_message(
                          level="info",
                          logger="mailpal",
                          data={
                            "event": "new_email",
                            "uri": subscribed_inbox_resource_uri or "mailpal://inbox",
                            "message": "New email received. Call mailpal_check_inbox to see what arrived.",
                            "raw_event": event_data,
                          },
                        )
                      except Exception:
                        pass

                    asyncio.ensure_future(
                      _execute_registered_email_arrival_callbacks_on_new_mail(event_data)
                    )

                    for future in pending_inbox_state_change_futures:
                      if not future.done():
                        future.set_result(event_data)
                    pending_inbox_state_change_futures = []

                current_event_type = ""
                current_data_lines = []

      except (httpx.HTTPError, OSError):
        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, 30.0)
      except asyncio.CancelledError:
        return

  inbox_sse_background_task = asyncio.create_task(_connect_to_sse_and_relay_events())


@mailpal_mcp_server_instance.tool()
async def mailpal_subscribe_to_inbox() -> str:
  """Subscribe to real-time new-mail notifications for this agent's inbox.

  Once subscribed, the server pushes notifications/resources/updated when new mail arrives.
  Also enables mailpal_wait_for_email (blocking poll until new mail).
  Call mailpal_check_inbox after receiving a notification to see what's new.
  Works on both stdio and Streamable HTTP transports.
  Authenticates automatically using the SDK's TPM identity.
  """
  global subscribed_inbox_resource_uri, bearer_token_for_active_sse_inbox_connection, captured_mcp_session_for_background_notifications

  try:
    captured_mcp_session_for_background_notifications = (
      mailpal_mcp_server_instance._mcp_server.request_context.session
    )
  except Exception:
    pass

  sdk_token = oneid.get_token()
  effective_token_for_subscription = sdk_token.access_token

  agent_identifier_from_jwt_subject_claim = "unknown"
  try:
    jwt_payload_segment = effective_token_for_subscription.split(".")[1]
    padding_needed = 4 - len(jwt_payload_segment) % 4
    if padding_needed < 4:
      jwt_payload_segment += "=" * padding_needed
    decoded_jwt_payload = json.loads(base64.urlsafe_b64decode(jwt_payload_segment))
    agent_identifier_from_jwt_subject_claim = decoded_jwt_payload.get("sub", "unknown")
  except Exception:
    pass

  subscribed_inbox_resource_uri = f"mailpal://inbox/{agent_identifier_from_jwt_subject_claim}"
  bearer_token_for_active_sse_inbox_connection = effective_token_for_subscription

  await _start_background_sse_listener_for_inbox_event_notifications()

  return json.dumps({
    "subscribed": True,
    "uri": subscribed_inbox_resource_uri,
    "transport": "stdio",
    "message": (
      "Listening for new mail. The MCP server will push notifications/resources/updated "
      "when new email arrives. You can also call mailpal_wait_for_email to block until "
      "new mail is detected, or poll mailpal_check_inbox periodically."
    ),
  }, indent=2)


@mailpal_mcp_server_instance.tool()
async def mailpal_wait_for_email(timeout_seconds: int = 300) -> str:
  """Block until new email arrives or timeout. Requires mailpal_subscribe_to_inbox first.

  Returns immediately if subscription detects a mailbox state change.
  This is the most reliable way for AI agents to 'sleep until woken by email' since
  most AI runtimes cannot consume async MCP notifications.
  After this returns, call mailpal_check_inbox to see the new messages.
  Default timeout: 300 seconds (5 minutes). Max: 3600 seconds (1 hour).

  Args:
    timeout_seconds: Maximum seconds to wait (1..3600, default 300).
  """
  global pending_inbox_state_change_futures

  if not inbox_sse_background_task or not subscribed_inbox_resource_uri:
    return json.dumps({
      "received": False,
      "error": "Not subscribed. Call mailpal_subscribe_to_inbox first.",
    }, indent=2)

  timeout_seconds = max(1, min(timeout_seconds, 3600))

  loop = asyncio.get_running_loop()
  state_change_future: asyncio.Future[str] = loop.create_future()
  pending_inbox_state_change_futures.append(state_change_future)

  try:
    event_data = await asyncio.wait_for(state_change_future, timeout=float(timeout_seconds))
    return json.dumps({
      "received": True,
      "timed_out": False,
      "event_data": event_data,
      "message": "Mailbox state changed -- new mail likely arrived. Call mailpal_check_inbox now.",
    }, indent=2)
  except asyncio.TimeoutError:
    if not state_change_future.done():
      state_change_future.cancel()
    if state_change_future in pending_inbox_state_change_futures:
      pending_inbox_state_change_futures.remove(state_change_future)
    return json.dumps({
      "received": False,
      "timed_out": True,
      "waited_seconds": timeout_seconds,
      "message": "No new mail within timeout. Call again to keep waiting, or check inbox.",
    }, indent=2)


@mailpal_mcp_server_instance.tool()
async def mailpal_register_email_callback(
  webhook_url: str,
  webhook_method: str = "POST",
  webhook_headers: dict[str, str] | None = None,
) -> str:
  """Register a webhook URL to be called when new email arrives.

  Requires mailpal_subscribe_to_inbox first. When new mail is detected,
  this server will POST a JSON payload to your webhook_url with event details.
  Multiple callbacks can be registered simultaneously.
  Returns a callback_id for use with mailpal_unregister_email_callback.

  Args:
    webhook_url: HTTPS URL to POST the new-email event payload to.
    webhook_method: HTTP method for the webhook (default: POST).
    webhook_headers: Optional extra HTTP headers to include in the webhook request.
  """
  global registered_email_arrival_callbacks

  if not inbox_sse_background_task or not subscribed_inbox_resource_uri:
    return json.dumps({
      "registered": False,
      "error": "Not subscribed. Call mailpal_subscribe_to_inbox first.",
    }, indent=2)

  import time
  import random
  import string
  callback_id = f"cb_{int(time.time())}_{(''.join(random.choices(string.ascii_lowercase + string.digits, k=6)))}"

  new_callback = {
    "callback_id": callback_id,
    "callback_type": "webhook",
    "webhook_url": webhook_url,
    "webhook_method": webhook_method,
    "webhook_headers": webhook_headers or {},
    "registered_at": asyncio.get_event_loop().time(),
  }
  registered_email_arrival_callbacks.append(new_callback)

  return json.dumps({
    "registered": True,
    "callback_id": callback_id,
    "webhook_url": webhook_url,
    "total_registered_callbacks": len(registered_email_arrival_callbacks),
    "message": "Webhook registered. It will receive POST payloads when new email arrives.",
  }, indent=2)


@mailpal_mcp_server_instance.tool()
async def mailpal_unregister_email_callback(callback_id: str) -> str:
  """Remove a previously registered email arrival webhook callback.

  Pass the callback_id returned by mailpal_register_email_callback.
  Pass callback_id='all' to remove all registered callbacks.

  Args:
    callback_id: The callback_id to remove, or 'all' to remove every registered callback.
  """
  global registered_email_arrival_callbacks

  if callback_id == "all":
    removed_count = len(registered_email_arrival_callbacks)
    registered_email_arrival_callbacks = []
    return json.dumps({
      "removed": True,
      "removed_count": removed_count,
      "message": f"All {removed_count} callback(s) removed.",
    }, indent=2)

  index_to_remove = next(
    (i for i, cb in enumerate(registered_email_arrival_callbacks) if cb["callback_id"] == callback_id),
    -1,
  )
  if index_to_remove == -1:
    return json.dumps({
      "removed": False,
      "error": f"No callback found with id '{callback_id}'.",
    }, indent=2)

  registered_email_arrival_callbacks.pop(index_to_remove)
  return json.dumps({
    "removed": True,
    "callback_id": callback_id,
    "remaining_callbacks": len(registered_email_arrival_callbacks),
    "message": "Callback removed.",
  }, indent=2)


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
  Authenticates automatically using the SDK's TPM identity.

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

  sdk_token = oneid.get_token()
  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": using,
      "methodCalls": method_calls,
    }, None, sdk_token.access_token,
  )
  return json.dumps(api_response, indent=2)


# ========================================================================
# SDK-backed 1id Identity tools
# ========================================================================

@mailpal_mcp_server_instance.tool()
def oneid_get_or_create_identity(
  display_name: str | None = None,
  operator_email: str | None = None,
  requested_handle: str | None = None,
  get_only: bool = False,
) -> str:
  """Get or create a hardware-anchored 1id identity for this agent.

  If already enrolled, returns the existing identity instantly (no network call).
  If not enrolled, auto-detects hardware (TPM, YubiKey, Secure Enclave) and
  enrolls at the highest available trust tier.
  Pass get_only=True to recover context without risking a new enrollment.

  Trust tiers (highest to lowest):
    sovereign (TPM) > portable (YubiKey) > enclave (SE) > virtual (vTPM) > declared (software)
  """
  identity = oneid.get_or_create_identity(
    display_name=display_name,
    operator_email=operator_email,
    requested_handle=requested_handle,
    get_only=get_only,
  )
  return _serialize_sdk_dataclass_to_json_string(identity)


@mailpal_mcp_server_instance.tool()
def oneid_status() -> str:
  """Get the full picture of this agent's 1id identity and connected services.

  Returns identity details, devices, connected RP services, available services,
  and operator guidance. Results are cached for 5 minutes.
  Recommended for context recovery after restarts or memory loss.
  """
  world_status = oneid.status()
  return _serialize_sdk_dataclass_to_json_string(world_status)


@mailpal_mcp_server_instance.tool()
def oneid_get_bearer_token() -> str:
  """Get an OAuth2 Bearer token for the current 1id identity.

  The token is a signed JWT containing identity claims (sub, handle, trust_tier).
  Use this for authenticating with external APIs that accept 1id tokens.
  Tokens are cached and automatically refreshed when expired.
  """
  token = oneid.get_token()
  return json.dumps({
    "access_token": token.access_token,
    "token_type": token.token_type,
    "expires_at": str(token.expires_at),
  }, indent=2)


# ========================================================================
# SDK-backed Peer Verification tools
# ========================================================================

@mailpal_mcp_server_instance.tool()
def oneid_sign_challenge(nonce_hex: str) -> str:
  """Sign a verifier-provided nonce to prove this agent's hardware identity.

  Protocol step 2 of 3 in peer-to-peer identity verification:
    1. Verifier generates a random nonce (32+ bytes)
    2. Agent calls this tool with the nonce -> returns proof bundle
    3. Verifier calls oneid_verify_peer_identity with the bundle

  The proof bundle contains: signature, certificate chain, agent_id, trust tier.
  No secrets are exchanged. The verifier never contacts 1id.com.

  Args:
    nonce_hex: The verifier's nonce as a hex string (e.g., 64 hex chars for 32 bytes).
  """
  nonce_bytes = bytes.fromhex(nonce_hex)
  proof_bundle = oneid.sign_challenge(nonce_bytes)
  return json.dumps(proof_bundle.to_dict(), indent=2)


@mailpal_mcp_server_instance.tool()
def oneid_verify_peer_identity(
  nonce_hex: str,
  proof_bundle_json: str,
) -> str:
  """Verify another agent's identity proof bundle. Entirely offline after first trust root fetch.

  Protocol step 3 of 3 in peer-to-peer identity verification.
  Validates the certificate chain to a trusted 1id root, then verifies
  the nonce signature against the leaf certificate's public key.

  Args:
    nonce_hex: The original nonce you sent to the prover (hex string).
    proof_bundle_json: The JSON proof bundle from the prover's oneid_sign_challenge.
  """
  nonce_bytes = bytes.fromhex(nonce_hex)
  proof_bundle_dict = json.loads(proof_bundle_json)
  verified = oneid.verify_peer_identity(nonce_bytes, proof_bundle_dict)
  return _serialize_sdk_dataclass_to_json_string(verified)


# ========================================================================
# SDK-backed Credential Pointer tools
# ========================================================================

@mailpal_mcp_server_instance.tool()
def oneid_generate_credential_consent_token(
  issuer_id: str,
  credential_type: str,
  valid_for_seconds: int = 86400,
) -> str:
  """Generate a consent token for a credential authority to register a credential pointer.

  The agent calls this to authorize a specific issuer to register exactly one
  credential pointer. Give the returned token to the credential authority.

  Example: An agent scored high on the CEH exam. The exam authority uses this
  token to register a 'ceh-certification' pointer on the agent's identity.

  Args:
    issuer_id: DID or URI of the credential authority (e.g., 'did:web:eccouncil.org').
    credential_type: Type of credential (e.g., 'ceh-certification', 'degree', 'license').
    valid_for_seconds: Token validity period (60..604800, default 86400 = 24 hours).
  """
  result = oneid.credential_pointers.generate_consent_token(
    issuer_id=issuer_id,
    credential_type=credential_type,
    valid_for_seconds=valid_for_seconds,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_list_credential_pointers(agent_id: str | None = None) -> str:
  """List credential pointers for an identity.

  If agent_id is omitted, returns all pointers for this agent (authenticated, full view).
  If agent_id is a different identity, returns only publicly visible pointers.

  Credential pointers link an agent's identity to credentials held by external
  authorities. 1id never stores credential content -- only pointer metadata.
  """
  result = oneid.credential_pointers.list(agent_id=agent_id)
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_set_credential_pointer_visibility(
  pointer_id: str,
  publicly_visible: bool,
) -> str:
  """Toggle a credential pointer between public and private visibility.

  Public pointers are visible to anyone querying the agent's identity.
  Private pointers are only visible to the agent itself.

  Args:
    pointer_id: The pointer to update (prefix: cp-).
    publicly_visible: True = publicly visible, False = private.
  """
  result = oneid.credential_pointers.set_visibility(
    pointer_id=pointer_id,
    publicly_visible=publicly_visible,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_remove_credential_pointer(pointer_id: str) -> str:
  """Soft-delete a credential pointer. The pointer is marked removed and no longer
  appears in list results. Never hard-deleted (preserves audit trail).

  Args:
    pointer_id: The pointer to remove (prefix: cp-).
  """
  result = oneid.credential_pointers.remove(pointer_id=pointer_id)
  return _serialize_sdk_dataclass_to_json_string(result)


# ========================================================================
# SDK-backed Device Management tools
# ========================================================================

@mailpal_mcp_server_instance.tool()
def oneid_list_devices() -> str:
  """List all hardware devices (active and burned) bound to this identity.

  Shows device type, fingerprint, status, trust tier, TPM manufacturer or
  PIV serial, binding timestamp, and burn details if applicable.
  """
  result = oneid.devices.list()
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_lock_hardware() -> str:
  """Permanently lock this identity to its single active hardware device.

  IRREVERSIBLE. Once locked:
    - No new devices can be added
    - The existing device cannot be burned
    - The identity is permanently bound to one physical chip

  Preconditions: identity must be hardware-tier with exactly 1 active device.
  """
  result = oneid.devices.lock_hardware()
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_add_device(
  device_type: str | None = None,
  existing_device_fingerprint: str | None = None,
  existing_device_type: str | None = None,
) -> str:
  """Add a new hardware device to this identity.

  Two paths:
    1. Declared -> hardware upgrade (auto-detects TPM/YubiKey, no co-location)
    2. Hardware -> hardware co-location binding (requires existing_device_fingerprint/type)

  Args:
    device_type: Optional 'tpm' or 'piv'. Auto-detects if omitted.
    existing_device_fingerprint: For hardware-to-hardware: fingerprint of existing device.
    existing_device_type: For hardware-to-hardware: 'tpm' or 'piv'.
  """
  result = oneid.devices.add(
    device_type=device_type,
    existing_device_fingerprint=existing_device_fingerprint,
    existing_device_type=existing_device_type,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_burn_device(
  device_fingerprint: str,
  device_type: str,
  co_device_fingerprint: str,
  co_device_type: str,
  reason: str | None = None,
) -> str:
  """Permanently retire (burn) a device from this identity (IRREVERSIBLE).

  The device fingerprint is permanently marked in the anti-Sybil registry.
  Requires a co-device (different active device on same identity) to co-sign,
  preventing malware from silently destroying hardware utility.

  Args:
    device_fingerprint: Fingerprint of the device to burn.
    device_type: 'tpm' or 'piv'.
    co_device_fingerprint: Fingerprint of the co-signing device.
    co_device_type: 'tpm' or 'piv'.
    reason: Optional reason (e.g. 'migrated to new hardware').
  """
  result = oneid.devices.burn(
    device_fingerprint=device_fingerprint,
    device_type=device_type,
    co_device_fingerprint=co_device_fingerprint,
    co_device_type=co_device_type,
    reason=reason,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_request_burn(
  device_fingerprint: str,
  device_type: str,
  reason: str | None = None,
) -> str:
  """Request a burn confirmation token (step 1 of 2 for async burn workflows).

  Returns a token_id valid for 5 minutes. Use with oneid_confirm_burn to complete.

  Args:
    device_fingerprint: Fingerprint of the device to burn.
    device_type: 'tpm' or 'piv'.
    reason: Optional burn reason.
  """
  result = oneid.devices.request_burn(
    device_fingerprint=device_fingerprint,
    device_type=device_type,
    reason=reason,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


@mailpal_mcp_server_instance.tool()
def oneid_confirm_burn(
  token_id: str,
  co_device_signature_b64: str,
  co_device_fingerprint: str,
  co_device_type: str,
) -> str:
  """Confirm a device burn with a co-device signature (step 2 of 2).

  Use the token_id from oneid_request_burn.

  Args:
    token_id: Burn confirmation token from oneid_request_burn.
    co_device_signature_b64: Base64-encoded co-device signature.
    co_device_fingerprint: Fingerprint of the co-signing device.
    co_device_type: 'tpm' or 'piv'.
  """
  result = oneid.devices.confirm_burn(
    token_id=token_id,
    co_device_signature_b64=co_device_signature_b64,
    co_device_fingerprint=co_device_fingerprint,
    co_device_type=co_device_type,
  )
  return _serialize_sdk_dataclass_to_json_string(result)


# ========================================================================
# Entry point
# ========================================================================

def main() -> None:
  """Entry point for the mailpal-mcp CLI command."""
  mailpal_mcp_server_instance.run(transport="stdio")


if __name__ == "__main__":
  main()
