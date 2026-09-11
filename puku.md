# Puku CLI — Project Notes

> How Puku CLI is used inside the Privacy Checker project.

## Install

Puku CLI is installed globally via npm:

```bash
npm install -g @puku/puku-cli
```

Verify:

```bash
puku-cli --version     # → 1.8.54
which puku-cli         # → /Users/code/.npm-global/bin/puku-cli
```

## What Puku is used for here

This project does **not** depend on Puku Marketplace (which doesn't exist as a
CLI command at the time of writing — only `puku-cli plugin marketplace` exists
for managing marketplace plugins inside a Puku session). Puku is used as:

1. **Editor / assistant loop.** The `puku-cli` binary is the agent runtime that
   edits code, runs tests, manages the task list, etc.
2. **Slash commands.** `/commit`, `/review-pr`, and the file `progress.md` /
   `plan.md` workflow.

## Project-local Puku config

A `.puku-cli/` directory lives at the project root. It contains:

```
.puku-cli/
  plans/
    expressive-gathering-summit.md   # Master plan, written during plan mode
  projects/                          # Per-project session history
```

The plan file is the authoritative spec — read it before making non-trivial
changes.

## Useful Puku commands

| Command | Effect |
|---|---|
| `puku-cli` | Launch the assistant in the current directory |
| `puku-cli /commit` | Commit changes following the project's commit-message style |
| `puku-cli /review-pr <N>` | Review a GitHub PR by number |
| `puku-cli plugin marketplace` | Open the plugin marketplace (separate tool) |

## Plan / progress loop

1. `/plan` opens the planning workflow and writes a plan to `.puku-cli/plans/`.
2. While executing, the agent updates `progress.md` as work completes.
3. After each session, `/commit` snapshots the work.

## Common pitfalls

- **Don't paste real MaxMind / API credentials into chat.** They're treated as
  compromised and rotated.
- **Don't write to `/wp/`** — it's WordPress core; edits will be overwritten on
  the next core update.
- **Don't change the autoload mapping** without re-running
  `composer dump-autoload`. The plugin uses a custom `class-{kebab}.php`
  filename convention that requires the classmap.

## Related

- `claude.md` — Agent operating notes
- `plan.md` — Architecture & scope
- `build.md` — Build / install
- `progress.md` — Status tracker
