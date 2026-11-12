---
name: eyeguard-review
description: Review an EyeGuard plan or diff against .review/rules.md before a PR opens. Use before opening any EyeGuard PR, or when asked to review a plan, diff or branch.
---
# EyeGuard review (advisory in phase 1)

Inputs are SOURCE, diffs, SQL and metadata only. Never read captured content, review frames, EyeGuard-data/,
flags, pending queues, decrypted data or keys (EG-PRIV-01, `.review/denylist.txt`). Nothing captured goes to any API.

## 1. Plan review (before code)
Load `.review/rules.md` and `.review/context.md`. List every rule whose scope the plan touches.
Return PASS or a list of `RULE-ID: concrete risk`. Revise the plan until no blockers remain.

## 2. Build the input
`python3 tools/review_context.py origin/main` -> changed files, mechanical pre-pass hits, callers of every
changed symbol. It exits 1 on a blocker hit. Withheld (denylisted) paths show by name only.

## 3. Four passes (cheap model, in parallel)
(a) correctness, (b) security and secrets, (c) rules.md, (d) operations: deploy survival, TCC, rollback, alerting.
Each finding cites a rule ID or a concrete input/state that fails.

## 4. Verify pass (main model)
Re-read the code for each blocker/major finding. Drop any not tied to a real failing input or state.

## 5. Output
Add a `## Review agent` section to the PR body: findings by severity with rule IDs, and one line
"Coverage untouched: yes/no + why". If coverage is reduced the body starts with "⚠️ REDUCES COVERAGE".
Phase 1 is advisory; blockers become a gate only after the replay report (phase 2) is accepted by Jonah.

## Rules for this skill
- Never edit `.review/rules.md` from a review run; propose changes in a PR.
- Record verdicts in `.review/feedback.jsonl`: {"rule","pr","verdict","reason"}.
- Never post to GitHub by yourself; never change required CI checks.
- Check `~/.claude/usage/check.sh` before fan-out; stop at 85%.
