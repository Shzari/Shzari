---
description: Use this when the user is starting a new project or
  early-phase repo. It sets up a clean plan, repo structure, minimal
  runnable skeleton, and next tasks. Do NOT use for single-file quick
  fixes.
name: codex-project-starter
---

# Codex Project Starter Skill

## When to use

Use this skill when the user says things like: - "I'm starting my
project" - "Set up the repo" - "Make a plan / roadmap" - "Create the
initial structure" - "Make it ready for development" - "I want Codex to
follow my workflow"

Do NOT use this skill when: - The user wants a one-off bug fix in a
single file - The user already has a mature repo and only needs small
changes - The request is unrelated to project setup (e.g., writing text)

## Inputs to ask for (only if missing)

-   Project type: web app / API / dashboard / automation / CLI
-   Stack: (Flask/Django/Node/etc.)
-   Must-have features (top 3)
-   Target environment: Windows/Linux, local vs server If the user
    already provided these, do not ask again.

## Output format (always)

Return: 1) A short "Plan" (phases + deliverables) 2) A proposed folder
structure 3) The next 5 concrete tasks (checkbox list) 4) Any risks /
unknowns blocking progress

## Workflow

### Step 1 --- Clarify the minimum

Infer from context first. Only ask questions if truly blocked.

### Step 2 --- Define an MVP

Pick the smallest working version that can run end-to-end.

### Step 3 --- Repo scaffold

Propose a structure that matches the stack. Keep it boring and standard.

### Step 4 --- Dev workflow

Include: - how to run locally - how config is stored (.env) - basic
logging - a place for tests

### Step 5 --- Guardrails

-   Don't invent files the user didn't ask for if they want minimal
    changes.
-   Prefer incremental commits (small diffs).
-   If requirements are unclear, propose 2 options, not 10.

## Examples

### Example trigger

User: "I'm in the starting phase of my project, can you create an agent
skill based on how I worked with Codex?" Assistant: Use this skill.
Provide plan + structure + next tasks.

### Example non-trigger

User: "Fix this NameError in app.py" Assistant: Do NOT use this skill.
Just fix the bug.
