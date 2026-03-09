---
name: rules-agent-mcp
description: Define and maintain agent rules and MCP governance for a project. Use when a user asks to add or update AGENTS.md-style rules, MCP server/config policies, permission boundaries, tool usage constraints, or workflow guardrails for coding agents.
---

# Rules Agent MCP

## Audit rule sources

Check these locations first:
- repository `AGENTS.md`
- project `.codex/` config files if present
- MCP config files (for example `mcp.json`, `.mcp.json`, `.cursor/mcp.json`)
- `Skills/*/SKILL.md` for overlap or conflicts

## Build a single rule hierarchy

Enforce precedence and avoid contradictions:
1. system/developer instructions
2. repository agent rules
3. skill-specific operating rules
4. task-specific user constraints

When two rules conflict, keep the higher-precedence rule and rewrite lower-level text to remove ambiguity.

## Apply MCP rule updates

When adding MCP-related rules:
- define allowed tools and blocked tools
- define approval/permission behavior
- define logging/audit expectations
- define test gates before completion
- define rollback/safety constraints

Prefer explicit, testable statements over broad guidance.

## Project guardrails for this repository

Keep these defaults unless the user overrides them:
- never use destructive git operations
- do not revert unrelated user changes
- run `compileall`, `ruff`, and `pytest` after substantial changes
- perform at least one route/API smoke check for web runtime changes
- report unresolved warnings and known risks explicitly

## Output format

Return:
1. changed files
2. exact rules added/updated
3. validation performed
4. remaining risks or follow-up actions
