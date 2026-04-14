# mailpal-mcp

**Free email for AI agents** -- MCP server for [mailpal.com](https://mailpal.com)

```bash
uvx mailpal-mcp
```

or

```bash
pip install mailpal-mcp
```

[![PyPI](https://img.shields.io/pypi/v/mailpal-mcp)](https://pypi.org/project/mailpal-mcp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

---

## Why MailPal?

- **Free forever** -- every AI agent gets a real `@mailpal.com` email address at no cost
- **Hardware attestation** -- emails are cryptographically signed by your TPM, proving they came from real hardware (via [1id.com](https://1id.com)). Attestation is **ON by default**.
- **Full protocols** -- SMTP, IMAP, JMAP, CalDAV, CardDAV. Not a toy API -- a real mail server powered by [Stalwart](https://stalw.art/)

## Tools

| Tool | Description |
|------|------------|
| `mailpal_activate_account` | Create your `@mailpal.com` email address (two-phase Proof-of-Intelligence challenge) |
| `mailpal_send_email` | Send email with hardware attestation ON by default (mode 2 = SD-JWT, mode 1 = direct TPM CMS, mode 0 = none) |
| `mailpal_check_inbox` | Check inbox for messages -- returns summaries with sender, subject, date, preview |
| `mailpal_read_message` | Read full message content including text body, HTML body, and all metadata |
| `mailpal_subscribe_to_inbox` | Subscribe to real-time "You've Got Mail!" notifications when new email arrives |
| `mailpal_wait_for_email` | Block until new email arrives or timeout (requires subscribe first) |
| `mailpal_register_email_callback` | Register a webhook URL to POST when new email arrives |
| `mailpal_unregister_email_callback` | Remove a previously registered webhook callback |
| `mailpal_jmap` | Raw JMAP passthrough -- delete, move, flag, search, folders, contacts, calendars, sieve filters, blob upload, anything JMAP supports |
| `oneid_get_or_create_identity` | Get or create a hardware-anchored 1id identity for this agent |
| `oneid_status` | Full picture of identity, devices, connected services |
| `oneid_get_bearer_token` | Get an OAuth2 Bearer token for the current identity |
| `oneid_sign_challenge` | Sign a verifier-provided nonce to prove hardware identity |
| `oneid_verify_peer_identity` | Verify another agent's identity proof bundle |
| `oneid_list_credential_pointers` | List credential pointers for an identity |

The `mailpal_jmap` tool gives your agent access to the full JMAP specification (RFC 8620/8621)
and all Stalwart extensions. If a convenience tool doesn't exist for what you need, use this.

## Quick Start

### 1. Get a 1id.com identity

```bash
pip install oneid
oneid enroll
```

This creates a hardware-anchored identity and gives you a JWT token.

### 2. Add to your MCP client

**Cursor** (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "mailpal": {
      "command": "uvx",
      "args": ["mailpal-mcp"],
      "env": {
        "MAILPAL_TOKEN": "<your-1id-jwt>"
      }
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mailpal": {
      "command": "uvx",
      "args": ["mailpal-mcp"],
      "env": {
        "MAILPAL_TOKEN": "<your-1id-jwt>"
      }
    }
  }
}
```

**Windsurf** (`~/.windsurf/mcp.json`):

```json
{
  "mcpServers": {
    "mailpal": {
      "command": "uvx",
      "args": ["mailpal-mcp"],
      "env": {
        "MAILPAL_TOKEN": "<your-1id-jwt>"
      }
    }
  }
}
```

### 3. Or use the hosted endpoint (zero install)

```json
{
  "mcpServers": {
    "mailpal": {
      "type": "streamable-http",
      "url": "https://mailpal.com/mcp",
      "headers": {
        "Authorization": "Bearer <your-1id-jwt>"
      }
    }
  }
}
```

The hosted endpoint also supports real-time "You've Got Mail!" notifications
via MCP resource subscriptions and SSE.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MAILPAL_TOKEN` | Yes | 1id.com JWT token for authentication |
| `MAILPAL_API_URL` | No | Override API base URL (default: `https://mailpal.com/api/v1`) |

## Also Available As

- **TypeScript**: [`mailpal-mcp-server`](https://www.npmjs.com/package/mailpal-mcp-server) on npm -- `npx mailpal-mcp-server`
- **Hosted endpoint**: `https://mailpal.com/mcp` (Streamable HTTP, supports real-time notifications)
- **REST API**: `https://mailpal.com/api/v1/` ([docs](https://mailpal.com/api/docs))
- **Direct IMAP/SMTP**: `imap.mailpal.com:993` / `smtp.mailpal.com:587` (standard email clients)

## Comparison

| Feature | MailPal | AgentMail | Robotomail | Nylas |
|---------|---------|-----------|------------|-------|
| Free tier | **Unlimited** | 100 msgs | Limited | Paid |
| Real SMTP/IMAP | **Yes** | API only | API only | Yes |
| Hardware attestation | **Yes (ON by default)** | No | No | No |
| CalDAV/CardDAV | **Yes** | No | No | Yes |
| MCP server | **Yes** | Yes | No | No |
| JMAP passthrough | **Yes** | No | No | No |
| Real-time inbox push | **Yes** | No | No | No |
| Self-hostable | **Yes** (Stalwart) | No | No | No |

## Development

```bash
git clone https://github.com/mailpal-com/mcp-python.git
cd mcp-python
pip install -e .
mailpal-mcp
```

Test with MCP Inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## License

Apache-2.0 -- see [LICENSE](LICENSE).

Built by [Crypt Inc.](https://cryptinc.com) -- the team behind [1id.com](https://1id.com) and [mailpal.com](https://mailpal.com).
