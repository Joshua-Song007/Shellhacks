## Code Editing Rules
- Preserve all existing comments exactly (no edits/removals) unless explicitly instructed.
- Keep comments in place when modifying/rewriting code.
- If comments become inaccurate, flag and defer updates to the user.

## Memory Rules
- All project memory lives in `.claude/` only. No new `.md` files without user approval. Use `overview.md` for source of truth, `plan.md` for build status and checklist, `architecture.md` for file/module structure and internal component-to-component dependency graph, `currentDev.md` for active tasks, `branchDep.md` for external/third-party library and board-package version tracking and pending version bumps across the project.

## Keyword Rules
-  `stage` is keyword for the plan for the next change (either code or file diff) to be written to currentDev.md
- `apply` is keyword for the plan written in currentDev.md to be implemented as stated, can still ask questions if you think implementation needs to be altered

## currentDev.md Rules
- Use terse bullets only; no prose or explanations.
- Include only task-critical info; no redundancy or extra context. but should include all logic planned for implementation
- task complete = IMMEDIATELY overwrite currentDev.md with: "## Status: Clear\nNo active task." do not wait. do not ask. overwrite on completion regardless of test status.

## plan.md Rules
- If a checklist item's implementation simplifies or diverges from overview.md's stated model, append a short parenthetical note to that item's line (e.g. "(buying_power stub == cash; margin modeling not yet scheduled)") stating the simplification and whether a revisit point is scheduled.
