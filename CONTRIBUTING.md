# Contributing to Project C

## Python Coding Standards

- Target **Python 3.11+** and follow the **Google Python Style Guide**.
- Use modern type annotations (`list[str]`, `dict[str, Any]`, `str | None`) across all functions, methods, and attributes.
- Document public modules, classes, and functions using Google-style docstrings containing `Args:`, `Returns:`, and `Raises:` sections when applicable.

## Linting, Type Checking, and Security Analysis

Before opening a pull request, run the local checks inside the virtual environment:

~~~bash
ruff check soar/
bandit -r soar/
mypy soar/
~~~

## Git Workflow and Conventional Commits

- Branch from `develop` using descriptive feature branches (e.g., `feature/task-1-scaffolding-docs`).
- Format commits according to Conventional Commits:
  - `feat(soar): ...`
  - `docs(arch): ...`
  - `test(emulation): ...`
- Open Pull Requests targeting `develop` and ensure CI passes.
