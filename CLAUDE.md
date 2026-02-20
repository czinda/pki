# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Dogtag PKI is an enterprise-class open source Certificate Authority (CA) system. The project provides multiple PKI subsystems for certificate lifecycle management including CA, KRA (Key Recovery Authority), OCSP, TKS (Token Key Service), TPS (Token Processing System), ACME, and EST.

## Technology Stack

- **Java**: Core subsystem implementations (CA, KRA, OCSP, TKS, TPS, ACME, EST)
- **Python**: Server management, CLI tools, deployment and upgrade scripts
- **C/C++**: Native utilities (pistool, setpin, tkstool, tpsclient)
- **Build Systems**: CMake for native code, Maven for Java components
- **Application Server**: Quarkus
- **Dependencies**: NSS, NSPR, LDAP, Jackson, RESTEasy, Apache Commons

## Common Commands

### Building

```bash
# Install dependencies (use branch name matching current branch: master, @pki/10, etc.)
sudo dnf copr -y enable @pki/master
sudo dnf builddep -y --spec pki.spec

# Build binaries only
./build.sh dist

# Build RPM packages (default working directory: ~/build/pki)
./build.sh rpm

# Build with timestamp and commit ID in release number
./build.sh --with-timestamp --with-commit-id rpm

# Build specific packages only
./build.sh --with-pkgs=base,server,ca,kra rpm

# Install built binaries
./build.sh install
```

### Testing

```bash
# Run unit tests during build (enabled by default)
./build.sh dist

# Skip unit tests
./build.sh --without-test rpm

# Run specific GitHub workflow tests locally (see .github/workflows/)
# Tests are primarily integration tests using containers
```

### Python Code Quality

```bash
# Lint Python code
pylint --rcfile=tests/pylintrc <file.py>
flake8 <file.py>
```

### Server Management

```bash
# PKI server CLI (Python-based)
pki-server <command>

# Create subsystem instance
pki-server create <instance-id>

# Deploy subsystem (see docs/installation/)
pkispawn -f <config-file>

# Destroy subsystem
pkidestroy -i <instance-id> -s <subsystem>
```

## Architecture

### Directory Structure

- `base/` - All PKI subsystems and core components
  - `common/` - Shared Java libraries (`pki-common.jar`, `pki-tools.jar`)
  - `server/` - Server framework and Python management tools (`pki-server.jar`, Python CLI)
  - `server-webapp/` - Web application framework (`pki-server-webapp.jar`)
  - `ca/` - Certificate Authority subsystem (`pki-ca.jar`)
  - `kra/` - Key Recovery Authority subsystem (`pki-kra.jar`)
  - `ocsp/` - OCSP Responder subsystem (`pki-ocsp.jar`)
  - `tks/` - Token Key Service subsystem (`pki-tks.jar`)
  - `tps/` - Token Processing System subsystem (`pki-tps.jar`)
  - `acme/` - ACME Responder subsystem (`pki-acme.jar`)
  - `est/` - EST subsystem (`pki-est.jar`)
  - `quarkus-common/` - Shared Quarkus runtime components
  - `*-quarkus/` - Quarkus deployment modules per subsystem
  - `server-core/` - Container-agnostic server core
  - `tools/` - CLI tools and native utilities
  - `console/` - Management console (optional)
- `docs/` - Documentation organized by category
  - `installation/` - Deployment guides for each subsystem
  - `development/` - Developer documentation including Building_PKI.md
  - `admin/` - Administrator guides
  - `user/` - User guides
  - `manuals/` - Man pages
- `tests/` - Test suites and container-based integration tests
- `themes/` - UI themes
- `cmake/` - CMake build configuration modules

### Build System

The project uses a hybrid build system:

1. **CMake** (top-level): Orchestrates the overall build, handles native code compilation, and invokes Maven builds
2. **Maven** (Java modules): Builds Java components under `base/` hierarchy
3. **bash script** (`build.sh`): Wrapper that simplifies build commands and RPM generation

Key build artifacts are placed in `~/build/pki/dist/` when using `./build.sh dist`.

### Key Java Packages

- `com.netscape.certsrv.*` - Certificate server public APIs and client libraries
- `com.netscape.cmscore.*` - Certificate server core implementation
- `com.netscape.cmsutil.*` - Certificate server utilities
- `org.dogtagpki.*` - Modern PKI framework components

### Python Architecture

Python code is primarily in `base/server/python/pki/server/` and `base/common/python/pki/`:

- `pki/server/` - Server management framework
  - `cli/` - `pki-server` command implementations
  - `deployment/` - `pkispawn` deployment framework
  - `instance.py` - Instance management
  - `subsystem.py` - Subsystem management
  - `upgrade.py` - Upgrade framework
- `pki/` - Client libraries and utilities

### Subsystem Relationships

Each PKI subsystem (CA, KRA, OCSP, TKS, TPS, ACME, EST) follows a similar structure:
1. Quarkus JAX-RS REST API (using RESTEasy)
2. Backend services implementing PKI operations
3. Database backend (typically LDAP/389 Directory Server)
4. Shared server framework from `base/server`, `base/server-core`, and `base/quarkus-common`

The CA is typically deployed first and is required by other subsystems. KRA, OCSP, and TKS can be deployed as standalone or connected to a CA. ACME and EST are lightweight responders.

## Development Workflow

### Code Style

**Git Commit Messages:**
- Use present tense imperative mood ("Add feature" not "Added feature")
- Limit subject line to 50 characters
- Separate subject from body with blank line
- Reference issues/PRs liberally after first line

**Python:**
- Follow pylintrc configuration in `tests/pylintrc`
- Max line length: 100 characters
- Lint with both PyLint and Flake8

**Pull Requests:**
- Fork and create branch from `master`
- Update documentation for API changes
- Ensure CI passes (build, lint, tests on current stable Fedora)
- Include detailed description with test procedure

### Testing Strategy

The project uses extensive container-based integration testing via GitHub Actions. Test workflows are in `.github/workflows/` and cover:
- Basic subsystem functionality tests
- Clone and replication tests
- HSM integration tests
- Performance tests
- IPA (FreeIPA) integration tests

Test infrastructure scripts are in `tests/bin/` for creating/managing test containers.

## Important Notes

- **Branch names**: Follow formats `master`, `v<major>`, `v<major>.<minor>`, or `DOGTAG_<major>_<minor>_BRANCH`
- **COPR repositories**: Development dependencies may require enabling COPR repos matching the branch (e.g., `@pki/master`)
- **Working directory**: Default build working directory is `~/build/pki/`, can be changed with `--work-dir`
- **RPM packages**: Available packages are base, server, ca, kra, ocsp, tks, tps, acme, est, javadoc, theme, meta, tests, debug
- **Container support**: Dockerfile in root provides multi-stage builds for development and deployment
- **Documentation**: User/admin guides in `docs/`, man pages in `docs/manuals/`, design docs on wiki at https://github.com/dogtagpki/pki/wiki

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
