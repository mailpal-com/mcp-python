# DANGER -- DO NOT EDIT FILES IN THIS FOLDER

**Last synced: 2026-04-14T06:56:28Z**

This folder is a **read-only mirror** of the canonical source tree at
`websites/mailpal.com/` in the private 1id project repository.

## Files here are OVERWRITTEN every time the Makefile runs

Any changes you make directly in this folder **will be lost** the next
time someone runs `make github` from the source tree.

## How to make changes

1. Edit the source files in `websites/mailpal.com/` (the private repo)
2. Test and commit there as usual (`git push` auto-deploys to production)
3. Run the publish Makefile to sync changes to these GitHub repos:

```bash
cd websites/mailpal.com/
make github          # sync all repos
make github-push     # push all to GitHub
```

Or sync just one repo:

```bash
make github-mcp      # sync mcp-server only
make github-mcp-py   # sync mcp-python only
```

## Repo mapping

| GitHub repo | Source folder | What it contains |
|-------------|--------------|------------------|
| `mailpal-com/mcp-server` | `mcp-server/` | TypeScript MCP server (npm: `@mailpal/mcp-server`) |
| `mailpal-com/mcp-python` | `mcp-python/` | Python MCP server (PyPI: `mailpal-mcp`) |
