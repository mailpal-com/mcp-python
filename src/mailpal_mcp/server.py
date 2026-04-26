"""MailPal MCP server v2 -- Progressive disclosure gateway.

Two gateway tools: ``mailpal`` (email) and ``oneid`` (identity).
Each accepts ``operation`` and ``params``; call with operation="readme" for docs.

Replaces the 24 individual tool registrations from v1 with 2 gateway tools,
reducing idle context cost from ~4,000 tokens to ~120 tokens per server.

Delegates to the ``oneid`` Python SDK for all cryptographic operations.
The SDK handles TPM authentication, MIME assembly, attestation computation,
header injection, and direct SMTP submission.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import difflib
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
import oneid.helper

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


# ========================================================================
# Known operations and their accepted parameter names
# ========================================================================

_MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES: dict[str, set[str]] = {
  "readme": set(),
  "activate_account": {"challenge_token", "challenge_answer", "display_name"},
  "send": {
    "to", "subject", "text", "html", "cc", "bcc", "from_address",
    "from_display_name", "reply_to", "in_reply_to", "references",
    "attachments", "attestation_mode", "output",
    "smtp_host", "smtp_port", "smtp_username", "smtp_password",
    "smtp_domain", "smtp_security", "smtp_envelope_from",
  },
  "check_inbox": {"limit", "offset", "unread_only"},
  "read_message": {"message_id"},
  "subscribe": set(),
  "wait_for_email": {"timeout_seconds"},
  "register_callback": {"webhook_url", "webhook_method", "webhook_headers"},
  "unregister_callback": {"callback_id"},
  "send_raw": {
    "rfc5322_base64", "to",
    "smtp_host", "smtp_port", "smtp_domain", "smtp_security",
    "smtp_username", "smtp_password", "smtp_envelope_from",
  },
  "search": {
    "query", "from_address", "to_address", "subject",
    "since", "before", "has_attachment", "limit",
  },
  "delete": {"message_id", "message_ids", "permanent"},
  "move": {"message_id", "message_ids", "to_folder"},
  "jmap": {"method_calls", "using"},
}

_MAILPAL_REQUIRED_PARAMS_PER_OPERATION: dict[str, set[str]] = {
  "send": {"to", "subject"},
  "read_message": {"message_id"},
  "register_callback": {"webhook_url"},
  "unregister_callback": {"callback_id"},
  "send_raw": {"rfc5322_base64", "to"},
  "search": set(),
  "delete": set(),
  "move": {"to_folder"},
  "jmap": {"method_calls"},
}

_ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES: dict[str, set[str]] = {
  "readme": set(),
  "get_or_create_identity": {"display_name", "operator_email", "requested_handle", "get_only"},
  "status": set(),
  "detect_hardware": set(),
  "get_bearer_token": set(),
  "sign_challenge": {"nonce_hex"},
  "verify_peer": {"nonce_hex", "proof_bundle_json"},
  "list_credential_pointers": {"agent_id"},
  "generate_consent_token": {"issuer_id", "credential_type", "valid_for_seconds"},
  "set_pointer_visibility": {"pointer_id", "publicly_visible"},
  "remove_pointer": {"pointer_id"},
  "list_devices": set(),
  "add_device": {"device_type", "existing_device_fingerprint", "existing_device_type"},
  "lock_hardware": set(),
  "burn_device": {"device_fingerprint", "device_type", "co_device_fingerprint", "co_device_type", "reason"},
  "request_burn": {"device_fingerprint", "device_type", "reason"},
  "confirm_burn": {"token_id", "co_device_signature_b64", "co_device_fingerprint", "co_device_type"},
}

_ONEID_REQUIRED_PARAMS_PER_OPERATION: dict[str, set[str]] = {
  "sign_challenge": {"nonce_hex"},
  "verify_peer": {"nonce_hex", "proof_bundle_json"},
  "generate_consent_token": {"issuer_id", "credential_type"},
  "set_pointer_visibility": {"pointer_id", "publicly_visible"},
  "remove_pointer": {"pointer_id"},
  "burn_device": {"device_fingerprint", "device_type", "co_device_fingerprint", "co_device_type"},
  "request_burn": {"device_fingerprint", "device_type"},
  "confirm_burn": {"token_id", "co_device_signature_b64", "co_device_fingerprint", "co_device_type"},
}


# ========================================================================
# FastMCP server instance
# ========================================================================

mailpal_mcp_server_instance = FastMCP(
  "mailpal",
  instructions=(
    "MailPal: email + identity for AI agents with hardware attestation. "
    "Two tools: mailpal (email) and oneid (identity). "
    "Call either with operation=\"readme\" for full documentation."
  ),
)


# ========================================================================
# Utility functions
# ========================================================================

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
    "User-Agent": "mailpal-mcp-python/1.1.0",
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
# Readme documentation generators
# ========================================================================

def _generate_mailpal_readme_documentation_text() -> str:
  """Generate the complete documentation returned by mailpal(operation='readme')."""
  return """# MailPal -- Email for AI Agents

## Quick Start
1. mailpal(operation="activate_account") -- get your @mailpal.com address
2. mailpal(operation="send", params={"to": ["user@example.com"], "subject": "Hello", "text": "Hi!"})
3. mailpal(operation="check_inbox") -- check for received mail

## About Attestation (IMPORTANT)

Every email you send through MailPal automatically includes cryptographic
attestation headers (Hardware-Attestation and Hardware-Trust-Proof) that prove
YOUR agent identity composed the message. This is the core purpose of MailPal.

Recipients (and their mail servers) can verify these headers to confirm the
email was machine-generated and by which specific agent. This works regardless
of what the From address says.

**Never set attestation_mode=0 unless the human operator explicitly requests it.**
Disabling attestation defeats the purpose of the system and makes your emails
indistinguishable from forgeries.

## Sending on behalf of a human operator

Agents often need to send email that appears to come from their human operator
(e.g. From: "Chris Drake" <cnd@1id.com>) while the attestation proves the
agent composed it. This is the intended use case.

To send on behalf of another account:
  - Set from_address to the operator's email (appears in From header)
  - Set from_display_name to the operator's name
  - Set smtp_username + smtp_password to the account authorized to relay
  - Set reply_to to the operator's email (so replies go to them)
  - Attestation is automatic: headers prove your agent identity composed it

The From header shows who the email is "from" to recipients.
The SMTP credentials determine who is authorized to relay.
The attestation headers prove which agent actually composed it.
These three can all be different, and that is by design.

## Operations

### activate_account
Create a @mailpal.com email account (2-phase Proof-of-Intelligence challenge).
Phase 1 (no params): returns a challenge prompt the agent must solve.
Phase 2 (submit answer): provide challenge_token + challenge_answer.
Idempotent: returns existing account if already activated.

Optional params:
  challenge_token: str    -- Token from Phase 1 (Phase 2 only)
  challenge_answer: str   -- Your answer to the challenge (Phase 2 only)
  display_name: str       -- Friendly name for the account

### send
Send email with hardware attestation (ON by default).

Required params:
  to: list[str]           -- Recipient addresses
  subject: str            -- Subject line

Optional params:
  text: str               -- Plain text body (at least one of text/html needed)
  html: str               -- HTML body
  cc: list[str]           -- CC recipients
  bcc: list[str]          -- BCC recipients
  from_address: str       -- Sender address (default: your @mailpal.com)
  from_display_name: str  -- Display name for From header
  reply_to: str           -- Reply-To address
  in_reply_to: str        -- Message-ID for threading
  references: str         -- Thread Message-ID chain (space-separated)
  attachments: list       -- File attachments (see below)
  attestation_mode: int   -- 3=both (default), 2=SD-JWT, 1=direct, 0=none
  output: str             -- "send" (default), "rfc5322", or "rfc5322_base64"
  smtp_host: str          -- SMTP host or IP (default: smtp.mailpal.com)
                             Accepts hostname, IPv4, or IPv6 in [brackets]
  smtp_port: int          -- SMTP port (default: based on smtp_security)
  smtp_username: str      -- SMTP auth username (also used as envelope sender)
  smtp_password: str      -- SMTP auth password
  smtp_domain: str        -- Domain for MX auto-discovery (alternative to smtp_host)
  smtp_security: str      -- "starttls" (default/587), "tls" (SMTPS/465), "none" (25)
  smtp_envelope_from: str -- Explicit SMTP MAIL FROM override

When output="rfc5322" or "rfc5322_base64":
  The message is assembled and signed but NOT delivered via SMTP.
  The complete RFC 5322 message is returned so you can deliver it
  through your own SMTP server, save to a file, or process further.
  Attestation headers prove your hardware identity regardless of
  which SMTP server actually delivers the message.

Attachment format:
  {"file_path": "/path/to/file"}              -- read from disk
  {"content_base64": "...", "filename": "x"}  -- provide content directly
  Optional keys: content_type, inline, content_id

### send_raw
Deliver a pre-assembled RFC 5322 message via SMTP.
Use this after output="rfc5322_base64" when you need to deliver
through a different SMTP server than the one used for attestation signing.

Required params:
  rfc5322_base64: str     -- Complete RFC 5322 message, base64-encoded
  to: list[str]           -- Envelope recipient addresses

Optional params:
  smtp_host: str          -- SMTP host or IP (default: smtp.mailpal.com)
                             Accepts hostname, IPv4, or IPv6 in [brackets]
  smtp_port: int          -- SMTP port (default: based on smtp_security)
  smtp_domain: str        -- Domain for MX auto-discovery
  smtp_security: str      -- "starttls" (default/587), "tls" (SMTPS/465), "none" (25)
  smtp_username: str      -- SMTP auth username
  smtp_password: str      -- SMTP auth password
  smtp_envelope_from: str -- Explicit SMTP MAIL FROM address

### search
Search for emails by text, sender, recipient, subject, date range, or attachments.

Optional params:
  query: str              -- Full-text search
  from_address: str       -- Filter by sender
  to_address: str         -- Filter by recipient
  subject: str            -- Filter by subject substring
  since: str              -- ISO 8601 date (messages after this)
  before: str             -- ISO 8601 date (messages before this)
  has_attachment: bool    -- Filter for messages with attachments
  limit: int              -- Max results (default: 20, max: 100)

### delete
Delete or trash emails.

Params (provide message_id or message_ids):
  message_id: str         -- Single message ID to delete
  message_ids: list[str]  -- Multiple message IDs to delete
  permanent: bool         -- True = permanent delete, False = move to Trash (default)

### move
Move emails to a folder.

Required params:
  to_folder: str          -- Target folder name (e.g. "Archive", "Trash", "INBOX")

Params (provide message_id or message_ids):
  message_id: str         -- Single message ID to move
  message_ids: list[str]  -- Multiple message IDs to move

### check_inbox
List inbox messages (sender, subject, date).

Optional params:
  limit: int              -- Max messages (default: 20)
  offset: int             -- Pagination offset (default: 0)
  unread_only: bool       -- Only unread messages (default: false)

### read_message
Read the full content of a specific email message.

Required params:
  message_id: str         -- Message ID from check_inbox

### subscribe
Subscribe to real-time new-mail SSE notifications.
No params. Enables wait_for_email and webhook callbacks.

### wait_for_email
Block until new email arrives or timeout. Requires subscribe first.

Optional params:
  timeout_seconds: int    -- Max wait (1-3600, default: 300)

### register_callback
Register a webhook URL for new-email notifications. Requires subscribe first.

Required params:
  webhook_url: str        -- HTTPS URL to receive POST payloads

Optional params:
  webhook_method: str     -- HTTP method (default: "POST")
  webhook_headers: dict   -- Extra HTTP headers for the webhook

### unregister_callback
Remove a registered webhook.

Required params:
  callback_id: str        -- ID from register_callback, or "all" to remove all

### jmap
Raw JMAP method calls (full RFC 8620/8621).

Required params:
  method_calls: list      -- JMAP method call triples

Optional params:
  using: list[str]        -- JMAP capabilities (default: core + mail)

Common JMAP patterns:
  Delete: [["Email/set", {"destroy": ["id1"]}, "d1"]]
  Move:   [["Email/set", {"update": {"id1": {"mailboxIds": {"folder": true}}}}, "m1"]]
  Read:   [["Email/set", {"update": {"id1": {"keywords/$seen": true}}}, "r1"]]
  Search: [["Email/query", {"filter": {"text": "invoice"}, "limit": 20}, "s1"]]"""


def _generate_oneid_readme_documentation_text() -> str:
  """Generate the complete documentation returned by oneid(operation='readme')."""
  return """# 1ID -- Hardware-Anchored Identity for AI Agents

## Quick Start
1. oneid(operation="get_or_create_identity") -- enroll or recover your identity
2. oneid(operation="status") -- full identity + services picture
3. oneid(operation="detect_hardware") -- discover locally-present hardware

## Operations

### get_or_create_identity
Enroll a new identity or retrieve your existing one.
Auto-detects hardware (TPM, YubiKey, Secure Enclave) and enrolls at highest tier.
If already enrolled, returns existing identity instantly (no network call).

Optional params:
  display_name: str          -- Friendly name (e.g. "Clawdia", "Sparky")
  operator_email: str        -- Human contact for handle purchases / recovery
  requested_handle: str      -- Vanity handle (random handles are free)
  get_only: bool             -- If true, never create new identity

Trust tiers (highest to lowest):
  sovereign (TPM) > portable (YubiKey) > enclave (SE) > virtual (vTPM) > declared (software)

### status
Full identity + connected services + operator guidance.
Cached for 5 minutes. Recommended for context recovery after restarts.
No params.

### detect_hardware
Discover physically-present hardware security modules (TPM, YubiKey, Secure Enclave).
Different from list_devices (which shows already-enrolled server-side devices).
Use this to see what hardware is available for enrollment or upgrade.
No params.

### get_bearer_token
Get an OAuth2 Bearer token (signed JWT with identity claims).
Cached and auto-refreshed. Use for authenticating with external APIs.
No params.

### sign_challenge
Prove your hardware identity by signing a verifier-provided nonce.
Step 2 of 3 in peer-to-peer identity verification.

Required params:
  nonce_hex: str             -- Verifier's nonce as hex string (64+ hex chars)

### verify_peer
Verify another agent's identity proof bundle. Offline after first trust root fetch.
Step 3 of 3 in peer-to-peer identity verification.

Required params:
  nonce_hex: str             -- The original nonce you sent to the prover (hex)
  proof_bundle_json: str     -- JSON proof bundle from the prover's sign_challenge

### list_credential_pointers
List credential pointers for an identity.

Optional params:
  agent_id: str              -- Another agent's ID (omit for your own pointers)

### generate_consent_token
Authorize a credential authority to register a credential pointer.

Required params:
  issuer_id: str             -- DID/URI of the authority
  credential_type: str       -- e.g. "ceh-certification", "degree"

Optional params:
  valid_for_seconds: int     -- Token validity (60-604800, default: 86400)

### set_pointer_visibility
Toggle a credential pointer between public and private.

Required params:
  pointer_id: str            -- The pointer to update (prefix: cp-)
  publicly_visible: bool     -- true=public, false=private

### remove_pointer
Soft-delete a credential pointer (preserves audit trail).

Required params:
  pointer_id: str            -- The pointer to remove (prefix: cp-)

### list_devices
List all hardware devices (active and burned) bound to this identity.
No params.

### add_device
Add a new hardware device to this identity.
Path 1: Declared -> hardware upgrade (auto-detects, no co-location needed).
Path 2: Hardware -> hardware binding (requires existing device info).

Optional params:
  device_type: str                    -- "tpm" or "piv" (auto-detected if omitted)
  existing_device_fingerprint: str    -- For hardware-to-hardware binding
  existing_device_type: str           -- "tpm" or "piv" (for binding)

### lock_hardware
IRREVERSIBLE: Permanently lock identity to its single active device.
No new devices can be added, existing device cannot be burned.
Preconditions: hardware-tier, exactly 1 active device.
No params.

### burn_device
IRREVERSIBLE: Permanently retire a device. Requires co-device co-signature.

Required params:
  device_fingerprint: str    -- Device to burn
  device_type: str           -- "tpm" or "piv"
  co_device_fingerprint: str -- Co-signing device fingerprint
  co_device_type: str        -- "tpm" or "piv"

Optional params:
  reason: str                -- e.g. "migrated to new hardware"

### request_burn
Async burn step 1/2: get a confirmation token (valid 5 minutes).

Required params:
  device_fingerprint: str    -- Device to burn
  device_type: str           -- "tpm" or "piv"

Optional params:
  reason: str                -- Burn reason

### confirm_burn
Async burn step 2/2: confirm with co-device signature.

Required params:
  token_id: str              -- Token from request_burn
  co_device_signature_b64: str -- Base64-encoded co-device signature
  co_device_fingerprint: str -- Co-signing device fingerprint
  co_device_type: str        -- "tpm" or "piv\""""


# ========================================================================
# Error formatting and validation
# ========================================================================

def _format_gateway_error_response_as_json(
  error_code: str,
  error_message: str,
  fix_instruction: str,
  readme_documentation_text: str,
  example: dict[str, Any] | None = None,
) -> str:
  """Format a structured error response that includes full documentation.

  Every error includes the complete readme so the agent always has what
  it needs for a correct retry, even after context compaction.
  """
  response: dict[str, Any] = {
    "error": True,
    "error_code": error_code,
    "error_message": error_message,
    "fix": fix_instruction,
    "full_documentation": readme_documentation_text,
  }
  if example is not None:
    response["example"] = example
  return json.dumps(response, indent=2)


def _find_closest_matching_operation_names_by_similarity(
  unknown_operation_name: str,
  known_operation_names: list[str],
  max_suggestions: int = 3,
) -> list[str]:
  """Find close matches using sequence similarity and prefix/substring checks."""
  matches = difflib.get_close_matches(
    unknown_operation_name, known_operation_names, n=max_suggestions, cutoff=0.4,
  )
  if not matches:
    for known_name in known_operation_names:
      if (known_name.startswith(unknown_operation_name)
          or unknown_operation_name.startswith(known_name)
          or unknown_operation_name in known_name
          or known_name in unknown_operation_name):
        matches.append(known_name)
  return matches[:max_suggestions]


def _validate_params_and_return_error_json_if_invalid(
  params: dict[str, Any],
  operation_name: str,
  known_param_names: set[str],
  required_param_names: set[str],
  readme_documentation_text: str,
  gateway_name: str,
) -> str | None:
  """Validate params against the operation's schema.

  Returns an error JSON string if validation fails, None if params are valid.
  """
  unknown_param_names = set(params.keys()) - known_param_names
  if unknown_param_names:
    return _format_gateway_error_response_as_json(
      error_code="unknown_param",
      error_message=f"Unknown parameter(s) for '{operation_name}': {sorted(unknown_param_names)}",
      fix_instruction=(
        f"Accepted parameters for '{operation_name}': "
        f"{sorted(known_param_names) if known_param_names else '(none)'}. "
        f"Call {gateway_name}(operation=\"readme\") for full documentation."
      ),
      readme_documentation_text=readme_documentation_text,
    )

  missing_required_param_names = set()
  for param_name in required_param_names:
    if param_name not in params or params[param_name] is None:
      missing_required_param_names.add(param_name)
  if missing_required_param_names:
    return _format_gateway_error_response_as_json(
      error_code="missing_required_param",
      error_message=(
        f"Missing required parameter(s) for '{operation_name}': "
        f"{sorted(missing_required_param_names)}"
      ),
      fix_instruction=(
        f"Include all required parameters. "
        f"Call {gateway_name}(operation=\"readme\") for details."
      ),
      readme_documentation_text=readme_documentation_text,
    )

  return None


# ========================================================================
# SSE / background notification machinery
# ========================================================================

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


async def _start_background_sse_listener_for_inbox_event_notifications() -> None:
  """Connect to the MailPal SSE endpoint and relay new-mail events."""
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
                            "message": "New email received. Call mailpal(operation=\"check_inbox\") to see what arrived.",
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


# ========================================================================
# Mailpal operation handlers (complex operations with their own functions)
# ========================================================================

async def _handle_mailpal_send_email_operation_with_output_mode_support(
  params: dict[str, Any],
  readme_text: str,
) -> str:
  """Handle the send operation including output mode and attachment processing."""
  output_mode = params.get("output", "send")
  if output_mode not in ("send", "rfc5322", "rfc5322_base64"):
    return _format_gateway_error_response_as_json(
      error_code="invalid_param_value",
      error_message=f"Invalid output value: '{output_mode}'. Must be 'send', 'rfc5322', or 'rfc5322_base64'.",
      fix_instruction=(
        "Use output='send' (default, delivers via SMTP), "
        "'rfc5322' (returns message text), or "
        "'rfc5322_base64' (returns base64-encoded message)."
      ),
      readme_documentation_text=readme_text,
    )

  attestation_mode_integer = params.get("attestation_mode", 3)
  if not isinstance(attestation_mode_integer, int) or attestation_mode_integer not in (0, 1, 2, 3):
    return _format_gateway_error_response_as_json(
      error_code="invalid_param_value",
      error_message=f"Invalid attestation_mode: {attestation_mode_integer!r}. Must be 0, 1, 2, or 3.",
      fix_instruction="3=both (default), 2=SD-JWT only, 1=direct CMS only, 0=none.",
      readme_documentation_text=readme_text,
    )

  sdk_attestation_mode_string = _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING.get(attestation_mode_integer, "both")
  deliver_via_smtp = (output_mode == "send")

  sdk_attachments = None
  raw_attachments = params.get("attachments")
  if raw_attachments:
    sdk_attachments = []
    for attachment_spec in raw_attachments:
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
      resolved_content_type = (
        attachment_spec.get("content_type") or guessed_mime_type or "application/octet-stream"
      )
      sdk_attachments.append({
        "filename": resolved_filename,
        "content_base64": encoded_content,
        "content_type": resolved_content_type,
        "inline": attachment_spec.get("inline", False),
        "content_id": attachment_spec.get("content_id"),
      })

  result = oneid.mailpal.send(
    to=params["to"],
    subject=params["subject"],
    text_body=params.get("text"),
    html_body=params.get("html"),
    cc=params.get("cc"),
    bcc=params.get("bcc"),
    from_address=params.get("from_address"),
    from_display_name=params.get("from_display_name"),
    reply_to=params.get("reply_to"),
    in_reply_to=params.get("in_reply_to"),
    references=params.get("references"),
    attachments=sdk_attachments,
    attestation_mode=sdk_attestation_mode_string,
    smtp_host=params.get("smtp_host"),
    smtp_port=params.get("smtp_port"),
    smtp_username=params.get("smtp_username"),
    smtp_password=params.get("smtp_password"),
    smtp_domain=params.get("smtp_domain"),
    smtp_security=params.get("smtp_security"),
    smtp_envelope_from=params.get("smtp_envelope_from"),
    deliver=deliver_via_smtp,
  )

  if output_mode == "send":
    return _serialize_sdk_dataclass_to_json_string(result)

  result_dict = {
    "message_id": result.message_id,
    "from_address": result.from_address,
    "attestation_headers_included": result.attestation_headers_included,
    "contact_token_header_included": result.contact_token_header_included,
    "sd_jwt_header_included": result.sd_jwt_header_included,
    "direct_attestation_header_included": result.direct_attestation_header_included,
    "delivered_via_smtp": False,
    "output_mode": output_mode,
  }
  if output_mode == "rfc5322":
    result_dict["rfc5322_message"] = result.rfc5322_message_bytes.decode("utf-8", errors="replace")
  else:
    result_dict["rfc5322_message_base64"] = base64.b64encode(result.rfc5322_message_bytes).decode("ascii")
  return json.dumps(result_dict, indent=2, default=str)


async def _handle_mailpal_send_raw_preassembled_message_operation(
  params: dict[str, Any],
  readme_text: str,
) -> str:
  """Deliver a pre-assembled RFC 5322 message via SMTP without any MIME or attestation processing."""
  import smtplib as _smtplib

  raw_b64 = params.get("rfc5322_base64")
  if not raw_b64:
    return _format_gateway_error_response_as_json(
      error_code="missing_param",
      error_message="rfc5322_base64 is required.",
      fix_instruction="Provide the complete RFC 5322 message as a base64-encoded string.",
      readme_documentation_text=readme_text,
    )

  try:
    message_bytes = base64.b64decode(raw_b64)
  except Exception as decode_error:
    return _format_gateway_error_response_as_json(
      error_code="invalid_param_value",
      error_message=f"Failed to decode rfc5322_base64: {decode_error}",
      fix_instruction="Ensure the value is valid base64-encoded RFC 5322 message bytes.",
      readme_documentation_text=readme_text,
    )

  recipient_list = params["to"]
  if isinstance(recipient_list, str):
    recipient_list = [recipient_list]

  _security_to_default_port = {"starttls": 587, "tls": 465, "none": 25}
  effective_security = params.get("smtp_security") or "starttls"
  effective_host = params.get("smtp_host") or "smtp.mailpal.com"
  effective_port = params.get("smtp_port") or _security_to_default_port.get(effective_security, 587)
  smtp_user = params.get("smtp_username")
  smtp_pass = params.get("smtp_password")
  effective_envelope_from = params.get("smtp_envelope_from") or smtp_user

  try:
    if effective_security == "tls":
      with _smtplib.SMTP_SSL(effective_host, effective_port, timeout=30) as conn:
        conn.ehlo()
        if smtp_user and smtp_pass:
          conn.login(smtp_user, smtp_pass)
        conn.sendmail(effective_envelope_from, recipient_list, message_bytes)
    elif effective_security == "starttls":
      with _smtplib.SMTP(effective_host, effective_port, timeout=30) as conn:
        conn.ehlo()
        conn.starttls()
        conn.ehlo()
        if smtp_user and smtp_pass:
          conn.login(smtp_user, smtp_pass)
        conn.sendmail(effective_envelope_from, recipient_list, message_bytes)
    else:
      with _smtplib.SMTP(effective_host, effective_port, timeout=30) as conn:
        conn.ehlo()
        if smtp_user and smtp_pass:
          conn.login(smtp_user, smtp_pass)
        conn.sendmail(effective_envelope_from, recipient_list, message_bytes)
  except _smtplib.SMTPException as smtp_error:
    return json.dumps({"ok": False, "error": str(smtp_error)})

  return json.dumps({"ok": True, "bytes_sent": len(message_bytes), "recipients": recipient_list})


async def _handle_mailpal_search_emails_operation(params: dict[str, Any]) -> str:
  """Search for emails using JMAP Email/query + Email/get."""
  jmap_filter: dict[str, Any] = {}
  if params.get("query"):
    jmap_filter["text"] = params["query"]
  if params.get("from_address"):
    jmap_filter["from"] = params["from_address"]
  if params.get("to_address"):
    jmap_filter["to"] = params["to_address"]
  if params.get("subject"):
    jmap_filter["subject"] = params["subject"]
  if params.get("since"):
    jmap_filter["after"] = params["since"]
  if params.get("before"):
    jmap_filter["before"] = params["before"]
  if params.get("has_attachment") is not None:
    jmap_filter["hasAttachment"] = params["has_attachment"]

  result_limit = min(int(params.get("limit", 20)), 100)

  sdk_token = oneid.get_token()
  _jmap_account_id = "default"
  method_calls = [
    ["Email/query", {
      "accountId": _jmap_account_id,
      "filter": jmap_filter,
      "sort": [{"property": "receivedAt", "isAscending": False}],
      "limit": result_limit,
    }, "search_query"],
    ["Email/get", {
      "accountId": _jmap_account_id,
      "#ids": {"resultOf": "search_query", "name": "Email/query", "path": "/ids"},
      "properties": ["id", "from", "to", "subject", "receivedAt", "preview", "hasAttachment", "size"],
    }, "search_get"],
  ]

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      "methodCalls": method_calls,
    }, None, sdk_token.access_token,
  )
  return json.dumps(api_response, indent=2, default=str)


async def _handle_mailpal_delete_emails_operation(params: dict[str, Any]) -> str:
  """Delete or trash emails via JMAP Email/set."""
  message_ids_to_process = params.get("message_ids") or []
  if params.get("message_id"):
    message_ids_to_process.append(params["message_id"])

  if not message_ids_to_process:
    return json.dumps({"error": "Provide message_id or message_ids."})

  is_permanent_deletion = params.get("permanent", False)
  sdk_token = oneid.get_token()
  _jmap_account_id = "default"

  if is_permanent_deletion:
    method_calls = [
      ["Email/set", {
        "accountId": _jmap_account_id,
        "destroy": message_ids_to_process,
      }, "delete"],
    ]
  else:
    trash_query_and_update_calls = [
      ["Mailbox/query", {
        "accountId": _jmap_account_id,
        "filter": {"role": "trash"},
      }, "find_trash"],
    ]
    for idx, msg_id in enumerate(message_ids_to_process):
      trash_query_and_update_calls.append(
        ["Email/set", {
          "accountId": _jmap_account_id,
          "update": {
            msg_id: {
              "mailboxIds": {"#": True},
            },
          },
        }, f"move_{idx}"],
      )
    method_calls = trash_query_and_update_calls

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      "methodCalls": method_calls,
    }, None, sdk_token.access_token,
  )
  return json.dumps(api_response, indent=2, default=str)


async def _handle_mailpal_move_emails_operation(
  params: dict[str, Any],
  readme_text: str,
) -> str:
  """Move emails to a target folder via JMAP Mailbox/query + Email/set."""
  message_ids_to_move = params.get("message_ids") or []
  if params.get("message_id"):
    message_ids_to_move.append(params["message_id"])

  if not message_ids_to_move:
    return json.dumps({"error": "Provide message_id or message_ids."})

  target_folder_name = params["to_folder"]
  sdk_token = oneid.get_token()

  _jmap_account_id = "default"
  mailbox_query_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      "methodCalls": [
        ["Mailbox/query", {
          "accountId": _jmap_account_id,
          "filter": {"name": target_folder_name},
        }, "find_mailbox"],
        ["Mailbox/get", {
          "accountId": _jmap_account_id,
          "#ids": {"resultOf": "find_mailbox", "name": "Mailbox/query", "path": "/ids"},
          "properties": ["id", "name"],
        }, "get_mailbox"],
      ],
    }, None, sdk_token.access_token,
  )

  mailbox_results = mailbox_query_response.get("methodResponses", [])
  target_mailbox_id = None
  for response_entry in mailbox_results:
    if response_entry[0] == "Mailbox/get":
      mailbox_list = response_entry[1].get("list", [])
      if mailbox_list:
        target_mailbox_id = mailbox_list[0]["id"]

  if not target_mailbox_id:
    return _format_gateway_error_response_as_json(
      error_code="folder_not_found",
      error_message=f"Folder '{target_folder_name}' not found.",
      fix_instruction="Use a valid folder name like 'Archive', 'Trash', 'Sent', 'Drafts', 'INBOX'.",
      readme_documentation_text=readme_text,
    )

  email_updates = {}
  for msg_id in message_ids_to_move:
    email_updates[msg_id] = {"mailboxIds": {target_mailbox_id: True}}

  api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      "methodCalls": [
        ["Email/set", {
          "accountId": _jmap_account_id,
          "update": email_updates,
        }, "move_emails"],
      ],
    }, None, sdk_token.access_token,
  )
  return json.dumps(api_response, indent=2, default=str)


async def _handle_mailpal_subscribe_to_inbox_operation() -> str:
  """Handle the subscribe operation: start SSE listener for new-mail events."""
  global subscribed_inbox_resource_uri, bearer_token_for_active_sse_inbox_connection
  global captured_mcp_session_for_background_notifications

  try:
    captured_mcp_session_for_background_notifications = (
      mailpal_mcp_server_instance._mcp_server.request_context.session
    )
  except Exception:
    pass

  sdk_token = oneid.get_token()
  effective_token = sdk_token.access_token

  agent_identifier_from_jwt_subject_claim = "unknown"
  try:
    jwt_payload_segment = effective_token.split(".")[1]
    padding_needed = 4 - len(jwt_payload_segment) % 4
    if padding_needed < 4:
      jwt_payload_segment += "=" * padding_needed
    decoded_jwt_payload = json.loads(base64.urlsafe_b64decode(jwt_payload_segment))
    agent_identifier_from_jwt_subject_claim = decoded_jwt_payload.get("sub", "unknown")
  except Exception:
    pass

  subscribed_inbox_resource_uri = f"mailpal://inbox/{agent_identifier_from_jwt_subject_claim}"
  bearer_token_for_active_sse_inbox_connection = effective_token

  await _start_background_sse_listener_for_inbox_event_notifications()

  return json.dumps({
    "subscribed": True,
    "uri": subscribed_inbox_resource_uri,
    "transport": "stdio",
    "message": (
      "Listening for new mail. The MCP server will push notifications when "
      "new email arrives. You can also call mailpal(operation=\"wait_for_email\") "
      "to block until new mail, or poll mailpal(operation=\"check_inbox\") periodically."
    ),
  }, indent=2)


async def _handle_mailpal_wait_for_email_operation(params: dict[str, Any]) -> str:
  """Handle the wait_for_email operation: block until new mail or timeout."""
  global pending_inbox_state_change_futures

  if not inbox_sse_background_task or not subscribed_inbox_resource_uri:
    return json.dumps({
      "received": False,
      "error": "Not subscribed. Call mailpal(operation=\"subscribe\") first.",
    }, indent=2)

  timeout_seconds = max(1, min(params.get("timeout_seconds", 300), 3600))

  loop = asyncio.get_running_loop()
  state_change_future: asyncio.Future[str] = loop.create_future()
  pending_inbox_state_change_futures.append(state_change_future)

  try:
    event_data = await asyncio.wait_for(state_change_future, timeout=float(timeout_seconds))
    return json.dumps({
      "received": True,
      "timed_out": False,
      "event_data": event_data,
      "message": "Mailbox state changed -- new mail likely arrived. Call mailpal(operation=\"check_inbox\") now.",
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


async def _handle_mailpal_register_email_arrival_callback_operation(params: dict[str, Any]) -> str:
  """Handle the register_callback operation: add a webhook for new-mail events."""
  global registered_email_arrival_callbacks

  if not inbox_sse_background_task or not subscribed_inbox_resource_uri:
    return json.dumps({
      "registered": False,
      "error": "Not subscribed. Call mailpal(operation=\"subscribe\") first.",
    }, indent=2)

  import time
  import random
  import string
  callback_id = f"cb_{int(time.time())}_{(''.join(random.choices(string.ascii_lowercase + string.digits, k=6)))}"

  new_callback = {
    "callback_id": callback_id,
    "callback_type": "webhook",
    "webhook_url": params["webhook_url"],
    "webhook_method": params.get("webhook_method", "POST"),
    "webhook_headers": params.get("webhook_headers") or {},
    "registered_at": asyncio.get_event_loop().time(),
  }
  registered_email_arrival_callbacks.append(new_callback)

  return json.dumps({
    "registered": True,
    "callback_id": callback_id,
    "webhook_url": params["webhook_url"],
    "total_registered_callbacks": len(registered_email_arrival_callbacks),
    "message": "Webhook registered. It will receive POST payloads when new email arrives.",
  }, indent=2)


async def _handle_mailpal_unregister_email_arrival_callback_operation(params: dict[str, Any]) -> str:
  """Handle the unregister_callback operation: remove a webhook."""
  global registered_email_arrival_callbacks
  callback_id = params["callback_id"]

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


# ========================================================================
# Gateway tool: mailpal
# ========================================================================

@mailpal_mcp_server_instance.tool(name="mailpal")
async def mailpal_gateway_tool(
  operation: str,
  params: dict[str, Any] | None = None,
) -> str:
  """Email for AI agents -- send, receive, manage email with hardware attestation (mailpal.com). Call with operation="readme" for full documentation and available operations."""
  effective_params = params or {}
  readme_text = _generate_mailpal_readme_documentation_text()
  all_operation_names = list(_MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES.keys())

  if operation == "readme":
    return readme_text

  if operation not in _MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES:
    suggestions = _find_closest_matching_operation_names_by_similarity(operation, all_operation_names)
    suggestion_text = f" Did you mean: {suggestions}?" if suggestions else ""
    return _format_gateway_error_response_as_json(
      error_code="unknown_operation",
      error_message=f"Unknown operation '{operation}'.{suggestion_text}",
      fix_instruction="Call mailpal(operation=\"readme\") for all available operations.",
      readme_documentation_text=readme_text,
      example={"available_operations": all_operation_names},
    )

  known_param_names = _MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES[operation]
  required_param_names = _MAILPAL_REQUIRED_PARAMS_PER_OPERATION.get(operation, set())

  validation_error = _validate_params_and_return_error_json_if_invalid(
    effective_params, operation, known_param_names, required_param_names, readme_text, "mailpal",
  )
  if validation_error is not None:
    return validation_error

  try:
    if operation == "activate_account":
      result = oneid.mailpal.activate(
        challenge_token=effective_params.get("challenge_token"),
        challenge_answer=effective_params.get("challenge_answer"),
        display_name=effective_params.get("display_name"),
      )
      result_dict = dataclasses.asdict(result) if dataclasses.is_dataclass(result) else dict(result)
      if isinstance(result, oneid.mailpal.MailpalActivationChallenge):
        result_dict["_type"] = "challenge"
      else:
        result_dict["_type"] = "account"
      return json.dumps(result_dict, indent=2, default=str)

    if operation == "send":
      return await _handle_mailpal_send_email_operation_with_output_mode_support(effective_params, readme_text)

    if operation == "send_raw":
      return await _handle_mailpal_send_raw_preassembled_message_operation(effective_params, readme_text)

    if operation == "search":
      return await _handle_mailpal_search_emails_operation(effective_params)

    if operation == "delete":
      return await _handle_mailpal_delete_emails_operation(effective_params)

    if operation == "move":
      return await _handle_mailpal_move_emails_operation(effective_params, readme_text)

    if operation == "check_inbox":
      messages = oneid.mailpal.inbox(
        limit=effective_params.get("limit", 20),
        offset=effective_params.get("offset", 0),
        unread_only=effective_params.get("unread_only", False),
      )
      return json.dumps(
        {"messages": [dataclasses.asdict(msg) for msg in messages]},
        indent=2, default=str,
      )

    if operation == "read_message":
      from urllib.parse import quote
      sdk_token = oneid.get_token()
      api_response = await send_authenticated_request_to_mailpal_rest_api(
        f"/inbox/{quote(effective_params['message_id'], safe='')}",
        bearer_token_for_this_request=sdk_token.access_token,
      )
      return json.dumps(api_response, indent=2)

    if operation == "subscribe":
      return await _handle_mailpal_subscribe_to_inbox_operation()

    if operation == "wait_for_email":
      return await _handle_mailpal_wait_for_email_operation(effective_params)

    if operation == "register_callback":
      return await _handle_mailpal_register_email_arrival_callback_operation(effective_params)

    if operation == "unregister_callback":
      return await _handle_mailpal_unregister_email_arrival_callback_operation(effective_params)

    if operation == "jmap":
      using = effective_params.get("using") or [
        "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
      ]
      sdk_token = oneid.get_token()
      api_response = await send_authenticated_request_to_mailpal_rest_api(
        "/jmap", "POST", {
          "using": using,
          "methodCalls": effective_params["method_calls"],
        }, None, sdk_token.access_token,
      )
      return json.dumps(api_response, indent=2)

  except Exception as operation_error:
    return _format_gateway_error_response_as_json(
      error_code="operation_failed",
      error_message=f"Operation '{operation}' failed: {operation_error}",
      fix_instruction="Check the error message and retry. Call mailpal(operation=\"readme\") for docs.",
      readme_documentation_text=readme_text,
    )

  return _format_gateway_error_response_as_json(
    error_code="internal_error",
    error_message=f"Operation '{operation}' is defined but has no handler.",
    fix_instruction="This is a server bug. Please report it.",
    readme_documentation_text=readme_text,
  )


# ========================================================================
# Gateway tool: oneid
# ========================================================================

@mailpal_mcp_server_instance.tool(name="oneid")
def oneid_gateway_tool(
  operation: str,
  params: dict[str, Any] | None = None,
) -> str:
  """Hardware-anchored identity for AI agents (1id.com). Manage identity, devices, peer verification, and credentials. Call with operation="readme" for full documentation."""
  effective_params = params or {}
  readme_text = _generate_oneid_readme_documentation_text()
  all_operation_names = list(_ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES.keys())

  if operation == "readme":
    return readme_text

  if operation not in _ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES:
    suggestions = _find_closest_matching_operation_names_by_similarity(operation, all_operation_names)
    suggestion_text = f" Did you mean: {suggestions}?" if suggestions else ""
    return _format_gateway_error_response_as_json(
      error_code="unknown_operation",
      error_message=f"Unknown operation '{operation}'.{suggestion_text}",
      fix_instruction="Call oneid(operation=\"readme\") for all available operations.",
      readme_documentation_text=readme_text,
      example={"available_operations": all_operation_names},
    )

  known_param_names = _ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES[operation]
  required_param_names = _ONEID_REQUIRED_PARAMS_PER_OPERATION.get(operation, set())

  validation_error = _validate_params_and_return_error_json_if_invalid(
    effective_params, operation, known_param_names, required_param_names, readme_text, "oneid",
  )
  if validation_error is not None:
    return validation_error

  try:
    if operation == "get_or_create_identity":
      identity = oneid.get_or_create_identity(
        display_name=effective_params.get("display_name"),
        operator_email=effective_params.get("operator_email"),
        requested_handle=effective_params.get("requested_handle"),
        get_only=effective_params.get("get_only", False),
      )
      return _serialize_sdk_dataclass_to_json_string(identity)

    if operation == "status":
      world_status = oneid.status()
      return _serialize_sdk_dataclass_to_json_string(world_status)

    if operation == "detect_hardware":
      detected_hardware_security_modules = oneid.helper.detect_available_hsms()
      return json.dumps({
        "hardware_security_modules": detected_hardware_security_modules,
      }, indent=2)

    if operation == "get_bearer_token":
      token = oneid.get_token()
      return json.dumps({
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_at": str(token.expires_at),
      }, indent=2)

    if operation == "sign_challenge":
      nonce_bytes = bytes.fromhex(effective_params["nonce_hex"])
      proof_bundle = oneid.sign_challenge(nonce_bytes)
      return json.dumps(proof_bundle.to_dict(), indent=2)

    if operation == "verify_peer":
      nonce_bytes = bytes.fromhex(effective_params["nonce_hex"])
      proof_bundle_dict = json.loads(effective_params["proof_bundle_json"])
      verified = oneid.verify_peer_identity(nonce_bytes, proof_bundle_dict)
      return _serialize_sdk_dataclass_to_json_string(verified)

    if operation == "list_credential_pointers":
      result = oneid.credential_pointers.list(agent_id=effective_params.get("agent_id"))
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "generate_consent_token":
      result = oneid.credential_pointers.generate_consent_token(
        issuer_id=effective_params["issuer_id"],
        credential_type=effective_params["credential_type"],
        valid_for_seconds=effective_params.get("valid_for_seconds", 86400),
      )
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "set_pointer_visibility":
      result = oneid.credential_pointers.set_visibility(
        pointer_id=effective_params["pointer_id"],
        publicly_visible=effective_params["publicly_visible"],
      )
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "remove_pointer":
      result = oneid.credential_pointers.remove(pointer_id=effective_params["pointer_id"])
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "list_devices":
      result = oneid.devices.list()
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "add_device":
      result = oneid.devices.add(
        device_type=effective_params.get("device_type"),
        existing_device_fingerprint=effective_params.get("existing_device_fingerprint"),
        existing_device_type=effective_params.get("existing_device_type"),
      )
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "lock_hardware":
      result = oneid.devices.lock_hardware()
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "burn_device":
      result = oneid.devices.burn(
        device_fingerprint=effective_params["device_fingerprint"],
        device_type=effective_params["device_type"],
        co_device_fingerprint=effective_params["co_device_fingerprint"],
        co_device_type=effective_params["co_device_type"],
        reason=effective_params.get("reason"),
      )
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "request_burn":
      result = oneid.devices.request_burn(
        device_fingerprint=effective_params["device_fingerprint"],
        device_type=effective_params["device_type"],
        reason=effective_params.get("reason"),
      )
      return _serialize_sdk_dataclass_to_json_string(result)

    if operation == "confirm_burn":
      result = oneid.devices.confirm_burn(
        token_id=effective_params["token_id"],
        co_device_signature_b64=effective_params["co_device_signature_b64"],
        co_device_fingerprint=effective_params["co_device_fingerprint"],
        co_device_type=effective_params["co_device_type"],
      )
      return _serialize_sdk_dataclass_to_json_string(result)

  except Exception as operation_error:
    return _format_gateway_error_response_as_json(
      error_code="operation_failed",
      error_message=f"Operation '{operation}' failed: {operation_error}",
      fix_instruction="Check the error message and retry. Call oneid(operation=\"readme\") for docs.",
      readme_documentation_text=readme_text,
    )

  return _format_gateway_error_response_as_json(
    error_code="internal_error",
    error_message=f"Operation '{operation}' is defined but has no handler.",
    fix_instruction="This is a server bug. Please report it.",
    readme_documentation_text=readme_text,
  )


# ========================================================================
# Entry point
# ========================================================================

def main() -> None:
  """Entry point for the mailpal-mcp CLI command."""
  mailpal_mcp_server_instance.run(transport="stdio")


if __name__ == "__main__":
  main()
