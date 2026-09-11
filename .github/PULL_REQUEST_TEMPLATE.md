## What does this PR do?

<!-- A clear, single-sentence summary of what this PR changes. -->

## Why?

<!-- The user story, bug link, or feature request this addresses. -->

## How to test

<!-- Step-by-step manual test instructions. Mark any area that needs attention. -->

1.
2.
3.

## Checklist

- [ ] I read the project's [`claude.md`](claude.md) and [`plan.md`](plan.md).
- [ ] I added / updated PHPUnit tests for any new PHP behavior.
- [ ] I added / updated Playwright specs for any UI-visible change (`e2e/`).
- [ ] I ran `vendor/bin/phpunit --testsuite="Privacy Checker"` locally.
- [ ] I ran `npx playwright test` locally and it's green.
- [ ] I ran `bin/deploy.sh local` and it shipped clean.
- [ ] No `print()`, `console.log()`, or `var_dump()` left behind.
- [ ] No new MaxMind or API secrets added.
- [ ] No changes under `wp/` (WordPress core; do not edit).
