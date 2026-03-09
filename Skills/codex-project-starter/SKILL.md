---
description: Create an initial project setup plan for new or early-phase repositories. Use when a user asks to start a project, define structure, scaffold a clean baseline, or set a roadmap. Do not use for isolated bug fixes or small edits in mature repos.
name: codex-project-starter
---

# Codex Project Starter Skill

## Collect minimum inputs

Ask only for missing essentials:
- project type
- target stack
- top 3 must-have features
- deployment target (local/server, OS)

## Produce this output

Return exactly:
1. A short phased plan with concrete deliverables.
2. A proposed folder structure.
3. The next 5 tasks as an ordered checklist.
4. Risks or unknowns that block delivery.

## Apply workflow

1. Infer constraints from the existing repo before asking questions.
2. Define the smallest end-to-end MVP that can run.
3. Propose conventional structure over novel structure.
4. Include run instructions, config strategy, logging baseline, and test location.
5. Keep changes incremental and aligned with user scope.

## Enforce guardrails

- Avoid large speculative scaffolding when the user asked for minimal setup.
- Prefer two practical options when requirements are ambiguous.
- Do not mix setup work with unrelated feature implementation in one pass.
