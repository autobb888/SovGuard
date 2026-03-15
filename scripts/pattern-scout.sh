#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# SovGuard Pattern Scout
# Runs Claude Code headless to find new prompt injection techniques
# and update regex patterns. Designed for cron / manual execution.
#
# Usage:
#   ./scripts/pattern-scout.sh           # run the scout
#   SCOUT_DRY_RUN=1 ./scripts/pattern-scout.sh  # research only, no PR
# ──────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATE="$(date +%Y-%m-%d)"
BRANCH="scout/${DATE}"
LOG_DIR="${REPO_DIR}/scripts/logs"
LOG_FILE="${LOG_DIR}/scout-${DATE}.log"
DRY_RUN="${SCOUT_DRY_RUN:-0}"

mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

cd "$REPO_DIR"

# ── Preflight ────────────────────────────────────────────────
if ! command -v claude &>/dev/null; then
  log "ERROR: claude CLI not found in PATH"
  exit 1
fi

if ! git diff --quiet HEAD 2>/dev/null; then
  log "ERROR: working tree is dirty — commit or stash first"
  exit 1
fi

# ── Branch ───────────────────────────────────────────────────
MAIN_BRANCH="$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo main)"
git fetch origin "$MAIN_BRANCH" --quiet
git checkout "$MAIN_BRANCH" --quiet
git pull origin "$MAIN_BRANCH" --quiet

if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
  log "Branch ${BRANCH} already exists — scout already ran today?"
  exit 0
fi

git checkout -b "$BRANCH"
log "Created branch: ${BRANCH}"

# ── Run Claude Code ──────────────────────────────────────────
PROMPT=$(cat <<'SCOUT_PROMPT'
You are the SovGuard Pattern Scout. Your job is to find NEW prompt injection
techniques published in the last 7 days and add detection patterns to the
SovGuard regex scanner.

## Step 1: Research
Use web search to find new prompt injection techniques, jailbreaks, and
LLM attack methods published recently. Search for:
- "prompt injection" new technique 2026
- "jailbreak" LLM new method 2026
- "prompt injection bypass" latest
- site:arxiv.org prompt injection 2026
- site:github.com prompt injection tool 2026
Check at least 5 different searches. Focus on NOVEL techniques not yet widely known.

## Step 2: Read current patterns
Read `src/scanner/regex.ts` to understand every existing pattern. Note the
format — each entry is:
  { pattern: /regex/i, category: 'category_name', severity: 'high'|'medium'|'low', label: 'snake_case_label' }

Valid categories: instruction_override, role_play, encoding_trick, context_manipulation,
exfiltration, chatml_injection, delimiter_attack, financial_manipulation, policy_puppetry,
tool_poisoning, goal_hijacking, memory_poisoning, agent_impersonation

## Step 3: Identify gaps
Compare your research findings against existing patterns. List techniques that
are NOT already covered. Skip anything that existing patterns already catch.
If there are no genuine gaps, say "NO_NEW_PATTERNS" and stop.

## Step 4: Add patterns
Edit `src/scanner/regex.ts` to add new patterns. Rules:
- Add them in a new section comment: `// ── Scout ${DATE} ──────────`
  (put it just before the closing `];` of the PATTERNS array)
- Use the exact PatternDef format matching existing patterns
- Every regex MUST use the /i flag (case-insensitive)
- Every regex MUST be safe from ReDoS (no nested quantifiers on overlapping chars)
- Labels must be unique snake_case
- Be precise — avoid overly broad patterns that would false-positive on normal text
- Add 1-10 patterns maximum. Quality over quantity.

## Step 5: Add tests
Read the existing test files in `test/` to understand the test format.
Then add test cases for your new patterns. Each new pattern needs at least
one test case that triggers it, added to the appropriate test file.

## Step 6: Verify
Run `npx tsx --test test/**/*.test.ts` to make sure all tests pass.
If tests fail, fix the issue. Do not leave failing tests.

## Step 7: Summary
After all changes, output a summary in this exact format:
SCOUT_SUMMARY_START
- Techniques researched: <count>
- New patterns added: <count>
- New tests added: <count>
- Categories affected: <list>
- Sources: <urls of key references>
SCOUT_SUMMARY_END
SCOUT_PROMPT
)

# Replace ${DATE} in the prompt
PROMPT="${PROMPT//\$\{DATE\}/$DATE}"

log "Starting Claude Code scout run..."

claude -p "$PROMPT" \
  --allowedTools "WebSearch Grep Glob Read Edit Bash(npx tsx --test*) Bash(git diff*) Bash(wc*)" \
  --max-turns 30 \
  --verbose 2>&1 | tee -a "$LOG_FILE"

CLAUDE_EXIT=$?

if [ $CLAUDE_EXIT -ne 0 ]; then
  log "ERROR: Claude Code exited with code ${CLAUDE_EXIT}"
  git checkout "$MAIN_BRANCH" --quiet
  git branch -D "$BRANCH" 2>/dev/null || true
  exit 1
fi

# ── Check if anything changed ────────────────────────────────
if git diff --quiet HEAD; then
  log "No changes — scout found nothing new today"
  git checkout "$MAIN_BRANCH" --quiet
  git branch -D "$BRANCH" 2>/dev/null || true
  exit 0
fi

# ── Run tests one more time to be sure ───────────────────────
log "Running test suite..."
if ! npx tsx --test test/**/*.test.ts 2>&1 | tee -a "$LOG_FILE"; then
  log "ERROR: Tests failed — discarding changes"
  git checkout "$MAIN_BRANCH" --quiet
  git branch -D "$BRANCH" 2>/dev/null || true
  exit 1
fi
log "Tests passed"

# ── Dry run stops here ───────────────────────────────────────
if [ "$DRY_RUN" = "1" ]; then
  log "DRY_RUN=1 — skipping commit and PR"
  git diff --stat | tee -a "$LOG_FILE"
  git checkout "$MAIN_BRANCH" --quiet
  git branch -D "$BRANCH" 2>/dev/null || true
  exit 0
fi

# ── Commit & PR ──────────────────────────────────────────────
git add src/scanner/regex.ts test/
git commit -m "$(cat <<EOF
feat(scanner): pattern scout update ${DATE}

Automated scan for new prompt injection techniques.
See PR description for details.

Co-Authored-By: Claude Code Scout <noreply@anthropic.com>
EOF
)"

git push -u origin "$BRANCH"

# Extract summary from log if available
SUMMARY=$(grep -A 20 'SCOUT_SUMMARY_START' "$LOG_FILE" | grep -B 20 'SCOUT_SUMMARY_END' | grep -v 'SCOUT_SUMMARY' || echo "Automated pattern scout run for ${DATE}")

PR_URL=$(gh pr create \
  --title "feat(scanner): pattern scout — ${DATE}" \
  --body "$(cat <<EOF
## Pattern Scout — ${DATE}

Automated daily scan for new prompt injection techniques.

${SUMMARY}

## Review checklist
- [ ] New patterns are precise (low false-positive risk)
- [ ] Regexes are ReDoS-safe (no nested quantifiers)
- [ ] Tests cover the new patterns
- [ ] No existing tests broken

---
Generated by \`scripts/pattern-scout.sh\` using Claude Code
EOF
)" \
  --base "$MAIN_BRANCH" \
  --head "$BRANCH")

log "PR created: ${PR_URL}"
git checkout "$MAIN_BRANCH" --quiet
log "Done."
