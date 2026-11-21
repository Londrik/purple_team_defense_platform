# Extreme Programming (XP) Workflow & Definition of Done (DoD)

## Core XP Practices Applied to This Repository

- **Small Atomic Increments:** One task, one branch, and one focused Pull Request at a time to keep code review fast and isolate regressions.
- **Continuous Testing & Refactoring:** Keep unit, regression, and API tests green before moving forward; refactor gently with clear boundaries rather than building monolithic changes.
- **Living Documentation:** Pair architectural choices, operational procedures, and security controls with ADRs (`docs/adr/`) and runbooks (`docs/runbooks/`).
- **Fail-Safe & Reversible Automation:** Never ship destructive automation without safelists, explicit error handling, and rollback/unblock steps.

## Branching & Commit Flow

1. Start a new branch from the base integration branch (`feat/task-XX-...` or `docs/task-XX-...` or `test/task-XX-...`).
2. Implement the minimal, clean increment and add or update automated tests.
3. Run static analysis, typing, security, and test checks locally.
4. Commit with Conventional Commits (`feat(...)`, `fix(...)`, `docs(...)`, `test(...)`) and push to `origin`.

## Definition of Done (DoD)

- Code follows Python 3.11+ typing (`str | None`, `list[...]`) and Google-style docstrings where applicable.
- `ruff check` and `ruff format --check` pass without errors.
- `mypy` passes in strict mode.
- `bandit` reports zero unmitigated security issues.
- `pytest` passes all unit, regression, and API tests.
- `git status` shows no unintended leftover files and changes are committed and pushed.
