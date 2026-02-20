# AGENTS.md - Agent Guidelines for Dogtag PKI

This file provides guidance for AI coding agents working in this repository.

## Project Overview

Dogtag PKI is an enterprise-class open source Certificate Authority (CA) system with multiple subsystems: CA, KRA, OCSP, TKS, TPS, ACME, and EST.

- **Java**: Core subsystem implementations (Maven build)
- **Python**: Server management, CLI tools, deployment scripts
- **C/C++**: Native utilities (pistool, setpin, tkstool, tpsclient)
- **Build Systems**: CMake for native code, Maven for Java

---

## Build Commands

### Main Build Script

```bash
# Build binaries only (default target)
./build.sh dist

# Build RPM packages (default working directory: ~/build/pki)
./build.sh rpm

# Skip unit tests during build
./build.sh --without-test rpm

# Build specific packages only
./build.sh --with-pkgs=base,server,ca,kra rpm

# Build with timestamp and commit ID in release number
./build.sh --with-timestamp --with-commit-id rpm
```

### Maven Commands (for Java)

```bash
# Build entire project
cd base && mvn clean install

# Build specific module
cd base/common && mvn clean install

# Run unit tests for a module
cd base/common && mvn test

# Run a single test class
cd base/common && mvn test -Dtest=com.netscape.certsrv.base.PKIExceptionTest

# Run a single test method
cd base/common && mvn test -Dtest=com.netscape.certsrv.base.PKIExceptionTest#testGetCode

# Skip tests
mvn clean install -DskipTests
```

### Python Commands

```bash
# Lint Python code with pylint (required)
pylint --rcfile=tests/pylintrc <file.py>

# Lint with flake8
flake8 <file.py>

# Run Python tests (if available)
pytest tests/
```

---

## Code Style Guidelines

### Java

**Copyright Header**: Every Java file must include the GPL copyright block:
```java
// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.base;
```

**Formatting**:
- 4-space indentation (no tabs)
- Opening brace on same line (K&R style)
- Max line length: ~100 characters (soft guideline)
- Use spaces around operators: `a + b`, not `a+b`

**Naming Conventions**:
- Classes: `CamelCase` (e.g., `PKIException`)
- Methods: `camelCase` (e.g., `getCode()`)
- Variables: `camelCase` (e.g., `code`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `serialVersionUID`)
- Packages: lowercase (e.g., `com.netscape.certsrv.base`)

**Imports**:
- Group by: java.*, javax.*, org.*, com.*
- Sort alphabetically within groups
- Use fully qualified names for single-use imports when appropriate

**Error Handling**:
- Use custom exceptions extending `PKIException` or `RuntimeException`
- Include meaningful error messages
- Use `try-with-resources` for auto-closeable resources

**Logging**:
- Use `java.util.logging.Logger`
- Log at appropriate levels (severe, warning, info, fine, finer, finest)

---

### Python

**Copyright Header**: Include license header:
```python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
```

**Formatting** (follow `tests/pylintrc`):
- Max line length: 100 characters
- 4-space indentation
- Use `from __future__ import absolute_import` for Python 2/3 compatibility

**Naming Conventions**:
- Classes: `CamelCase` (e.g., `PKIInstance`)
- Functions/methods: `snake_case` (e.g., `start_instance()`)
- Variables: `snake_case` (e.g., `instance_name`)
- Constants: `UPPER_SNAKE_CASE`

**Imports**:
- Standard library first, then third-party, then local
- Use absolute imports: `from pki.server import PKIServer`

**Pylint Configuration** (`tests/pylintrc`):
- Disabled: W0511 (fixme), W0105 (pointless-string-statement), W0142, W0707, W0719
- Max args: 5, max locals: 15, max attributes: 7
- Min public methods: 2

---

### Git Commit Messages

- Use present tense imperative mood ("Add feature" not "Added feature")
- Limit subject line to 50 characters
- Separate subject from body with blank line
- Reference issues/PRs: "Fix #123" or "Closes #456"

---

## Directory Structure

- `base/common/` - Shared Java libraries
- `base/server/` - Server framework and Python CLI
- `base/ca/`, `base/kra/`, `base/ocsp/`, `base/tks/`, `base/tps/` - Subsystems
- `base/acme/`, `base/est/` - Lightweight responders
- `base/tools/` - CLI tools and native utilities
- `tests/` - Test suites and linting config

---

## Key Packages

**Java**:
- `com.netscape.certsrv.*` - Public APIs and client libraries
- `com.netscape.cmscore.*` - Core implementation
- `com.netscape.cmsutil.*` - Utilities
- `org.dogtagpki.*` - Modern PKI framework

**Python**:
- `pki.server` - Server management
- `pki.server.cli` - CLI commands
- `pki` - Client libraries

---

## Testing Strategy

- Unit tests: Run via Maven (`mvn test`) in each module
- Integration tests: Container-based (see `.github/workflows/`)
- Test workflows use Docker containers with 389 DS and Tomcat

---

## Important Notes

- Branch naming: `master`, `v<major>.<minor>`, or `DOGTAG_<major>_<minor>_BRANCH`
- COPR repositories required for build dependencies (e.g., `@pki/master`)
- Default build working directory: `~/build/pki/`
- Available RPM packages: base, server, ca, kra, ocsp, tks, tps, acme, est

````markdown
## UBS Quick Reference for AI Agents

UBS stands for "Ultimate Bug Scanner": **The AI Coding Agent's Secret Weapon: Flagging Likely Bugs for Fixing Early On**

**Install:** `curl -sSL https://raw.githubusercontent.com/Dicklesworthstone/ultimate_bug_scanner/master/install.sh | bash`

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

**Commands:**
```bash
ubs file.ts file2.py                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=js,python src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs --help                              # Full command reference
ubs sessions --entries 1                # Tail the latest install session log
ubs .                                   # Whole project (ignores things like .venv and node_modules automatically)
```

**Output Format:**
```
⚠️  Category (N errors)
    file.ts:42:5 – Issue description
    💡 Suggested fix
Exit code: 1
```
Parse: `file:line:col` → location | 💡 → how to fix | Exit 0/1 → pass/fail

**Fix Workflow:**
1. Read finding → category + fix suggestion
2. Navigate `file:line:col` → view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` → exit 0
6. Commit

**Speed Critical:** Scope to changed files. `ubs src/file.ts` (< 1s) vs `ubs .` (30s). Never full scan for small edits.

**Bug Severity:**
- **Critical** (always fix): Null safety, XSS/injection, async/await, memory leaks
- **Important** (production): Type narrowing, division-by-zero, resource leaks
- **Contextual** (judgment): TODO/FIXME, console logs

**Anti-Patterns:**
- ❌ Ignore findings → ✅ Investigate each
- ❌ Full scan per edit → ✅ Scope to file
- ❌ Fix symptom (`if (x) { x.y }`) → ✅ Root cause (`x?.y`)
````
