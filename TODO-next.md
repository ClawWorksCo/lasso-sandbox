# LASSO — Next Steps TODO

> Post team-readiness items. Work through in order.

## 1. Fix iptables / network policy enforcement (IN PROGRESS)

See below — being tackled now.

## 2. Sensitive information audit

**CRITICAL — must be done before any public release or sharing with the bank team.**

- [x] Audit ALL documentation files for PII, internal IPs, credentials, org names — DONE
- [x] Audit profile TOML files for internal references — DONE
- [x] Audit example configs for anything specific — DONE
- [x] Audit CHANGELOG.md for internal context leaks — DONE
- [x] Audit test files for hardcoded paths or names — DONE
- [x] Audit pyproject.toml metadata — DONE
- [x] Check git history for committed secrets — clean (note: old commits have Gitea URLs, see below)
- [x] Verify CLAUDE.md excluded from PyPI package — DONE
- [x] Run comprehensive sensitive data grep — DONE, all clear
- [ ] Consider BFG/filter-branch to scrub Gitea URLs from old commits before GitHub sync

## 3. Sync to GitHub

- [ ] Push main to `ClawWorksCo/lasso-sandbox` on GitHub
- [ ] Verify LICENSE shows in GitHub sidebar
- [ ] Verify GitHub Actions CI runs on push
- [ ] Add repo topics if missing

## 4. Create v0.5.0 release

- [ ] Update version in `lasso/__init__.py` and `pyproject.toml`
- [ ] Update CHANGELOG.md with v0.5.0 entry
- [ ] Tag and push: `git tag v0.5.0 && git push origin v0.5.0`
- [ ] Verify GitHub Actions release workflow triggers
- [ ] Create GitHub Release via `scripts/create-release.sh v0.5.0`

## 5. Publish to PyPI

- [ ] Set up PyPI Trusted Publisher (see `docs/supply-chain.md`)
- [ ] Or use API token for first publish: `twine upload dist/*`
- [ ] Verify `pip install lasso-sandbox` works from PyPI
- [ ] Verify optional deps: `pip install lasso-sandbox[all]`

## 6. Kubernetes operator (backlog)

- [ ] CRD-based sandbox management
- [ ] Design doc needed before implementation

## 7. lasso-cloud SaaS development (backlog)

- [ ] Currently 2 commits, early stage
- [ ] Needs product direction decision
