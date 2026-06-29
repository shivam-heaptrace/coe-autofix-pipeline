# Fulcrum AI COE — Security Pipeline POC

GitHub-native loop: **generate → scan → autofix → re-scan → merge**.

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push / PR | Build, lint, test |
| `security.yml` | push / PR / nightly | CodeQL, Trivy, Gitleaks, SonarCloud |
| `autofix.yml` | bot PR comment / security failure | Claude-powered remediation |

## Quick start

1. Add GitHub secrets: `ANTHROPIC_API_KEY`, `AUTOFIX_PAT`, `SONAR_TOKEN`
2. Configure branch protection on `main` (require all status checks + CODEOWNERS review)
3. Edit `sonar-project.properties` with your SonarCloud org and project key
4. Replace `<org>` in `CODEOWNERS` with your GitHub org slug
5. Open a PR from `feature/poc-test` — the seeded vulnerabilities in `src/index.js` will trigger the full pipeline

**Full setup and test instructions:** [`docs/security-pipeline.md`](docs/security-pipeline.md)
