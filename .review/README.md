# .review/

Rules and context for the EyeGuard review agent. See `rules.md` (what is checked and why),
`context.md` (system map), `ignore.txt` (never reviewed), `denylist.txt` (never READ: captured content and keys),
`feedback.jsonl` (verdicts). Run: `python3 tools/review_context.py origin/main`. Test: `python3 tests/test_review_agent.py`.
Phase 1 is advisory. It adds review; it removes no monitoring and changes no runtime code, CI check or SQL.
