# Contributing to CySec Arsenal
**NuRichter · CySec Arsenal**

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork: `git clone https://github.com/YOUR_USER/cysec-arsenal`
3. **Setup**: `./scripts/setup.sh`
4. **Branch**: `git checkout -b feat/my-new-tool`

---

## Code Standards

### Rust

Follow the workspace style. Run before committing:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
```

New crates must:
- Add to `[workspace.members]` in root `Cargo.toml`
- Use `workspace.dependencies` for shared deps
- Use `arsenal-core` for colors, banner, and logging
- Include a `--json` output flag for pipeline composability

### C

```bash
make -C c all      # builds hardened tools
make -C c vuln     # builds lab targets
```

Follow K&R style. All new tools must compile cleanly with:
```
gcc -Wall -Wextra -O2 -fstack-protector-strong
```

Lab targets (intentionally vulnerable) go under `c/<name>/` and must include a
prominent `/* INTENTIONALLY VULNERABLE */` comment at the top.

### Shell Scripts

All scripts must pass `shellcheck --severity=warning`. Use `set -euo pipefail`.

### Python (≤5% of codebase)

Only for utilities that cannot reasonably be done in Rust/Shell.
Run `bandit -r python/` before committing.

---

## Adding a New Tool

1. Create the crate: `cargo new --bin rust/my-tool`
2. Add to `Cargo.toml` workspace members
3. Add shared deps via workspace
4. Follow the banner/colors pattern from existing tools
5. Add entry to the README table
6. Update `docs/cheatsheet.md` with usage example

---

## Ethical Guidelines

All contributions must:

- Be intended for **authorized** security testing, CTF, or research
- Include appropriate `# Authorized use only` or equivalent comments
- **Not** include hardcoded credentials, real API keys, or target systems
- **Not** include code designed to evade detection on production systems
- Follow the project's MIT License and ethical use notice

---

## Pull Request Checklist

- [ ] `cargo fmt` + `cargo clippy` pass
- [ ] New scripts pass `shellcheck`
- [ ] README and cheatsheet updated
- [ ] No hardcoded IPs, domains, or credentials
- [ ] Ethical use disclaimer included in new tool
- [ ] CI passes on the PR

---

*NuRichter Workspace · Richterize The Infinity ∞*
