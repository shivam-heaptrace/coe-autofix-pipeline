# Security Pipeline POC — Implementation Guide

**Project:** Fulcrum AI COE
**Purpose:** Prove the generate → scan → autofix → re-scan → merge loop end-to-end
**Stack:** GitHub Actions, CodeQL, Trivy, Gitleaks, SonarCloud, Claude Code

---

## Repo Layout

```
.
├── .github/
│   └── workflows/
│       ├── ci.yml          # build, lint, test
│       ├── security.yml    # CodeQL + Trivy + Gitleaks + SonarCloud
│       └── autofix.yml     # Claude-powered remediation
├── src/
│   ├── index.js            # sample app (three seeded vulnerabilities)
│   ├── index.test.js       # tests (must stay green after autofix)
│   └── package.json
├── scripts/
│   └── sarif_to_findings.py  # collapses SARIF into findings.json for Claude
├── sonar-project.properties
├── trivy.yaml
├── CODEOWNERS
└── docs/
    └── security-pipeline.md   ← this file
```

---

## Pre-Flight Setup Checklist

### 1. GitHub secrets

Add these in **Settings → Secrets and variables → Actions**:

| Secret | Description |
|--------|-------------|
| `ANTHROPIC_API_KEY` | Claude API key for the autofix workflow |
| `AUTOFIX_PAT` | GitHub PAT (classic, `repo` scope) used by autofix to push commits back to the PR branch. GITHUB_TOKEN cannot push to protected branches |
| `SONAR_TOKEN` | SonarCloud project token |

### 2. SonarCloud project

1. Create a project at [sonarcloud.io](https://sonarcloud.io).
2. Copy your org key and project key into `sonar-project.properties`.
3. Set `SONAR_TOKEN` in GitHub secrets.
4. In SonarCloud, set **Administration → Analysis Method → GitHub Actions**.

### 3. Branch protection for `main`

In **Settings → Branches → Add rule** for `main`:

- [x] Require a pull request before merging
- [x] Require approvals (minimum: 1)
- [x] Require status checks to pass:
  - `Build & Test`
  - `CodeQL`
  - `Trivy`
  - `Secret Scan (Gitleaks)`
  - `SonarCloud`
- [x] Require branches to be up to date before merging
- [x] Require review from Code Owners
- [ ] Allow force pushes — **disabled**
- [ ] Allow deletions — **disabled**

### 4. CODEOWNERS teams

Create these teams in your GitHub org and add the right members:
- `@<org>/coe-engineering`
- `@<org>/coe-security`
- `@<org>/coe-operations`

Then replace `<org>` in `CODEOWNERS` with your real org slug.

### 5. Python in CI

`sarif_to_findings.py` requires Python 3.9+. GitHub-hosted runners include Python 3.x by default — no extra setup needed. For self-hosted runners, install Python and verify with `python3 --version`.

---

## POC Test Run — Proving the Pipeline

### Seeded vulnerabilities in `src/index.js`

| ID | Tool | Type | Location |
|----|------|------|----------|
| VULN-1 | CodeQL | SQL injection (`js/sql-injection`) | `index.js:42` |
| VULN-2 | CodeQL | Reflected XSS (`js/xss`) | `index.js:56` |
| VULN-3 | Gitleaks | Hardcoded API key | `index.js:29` |

### Step-by-step test

1. **Fork or clone** this repo.
2. **Create a feature branch:** `git checkout -b feature/poc-test`
3. **Push the branch:** `git push origin feature/poc-test`
4. **Open a pull request** targeting `main`.
5. Watch the **Actions tab**:
   - `CI` runs build and tests.
   - `Security Scan` runs CodeQL, Trivy, Gitleaks, SonarCloud.
   - CodeQL and Gitleaks should flag the seeded issues.
   - The security workflow posts a findings comment on the PR.
6. Watch for the **autofix workflow** to trigger:
   - It downloads the SARIF artifacts.
   - Runs `sarif_to_findings.py` to collapse them.
   - Invokes Claude Code with the findings payload.
   - Claude patches the affected files and pushes a fix commit.
   - The workflow posts an autofix summary comment on the PR.
7. `CI` and `Security Scan` re-run automatically on the fix commit.
8. Once all required checks are green and reviewers approve, **merge**.

### Success criteria

The POC is complete when:
- [ ] At least one seeded vulnerability is detected by a scanner.
- [ ] The finding appears as a PR comment (Trivy path) or SARIF alert (CodeQL/Gitleaks path).
- [ ] The autofix workflow triggers without manual intervention.
- [ ] Claude produces a targeted patch for the flagged file and line.
- [ ] The patched branch passes scanners on the next CI run.
- [ ] The PR cannot be merged until all required status checks pass.
- [ ] `autofix-summary.md` is committed alongside the fix, describing what changed.

---

## Architecture Notes

### Why SARIF → JSON → Claude?

SARIF files can be large (hundreds of KB for a full CodeQL run). Passing raw SARIF to Claude wastes tokens on schema boilerplate. `sarif_to_findings.py` extracts only the fields Claude needs: tool, rule, severity, file, line, message. Claude's prompt context stays small and focused.

### Why a PAT for the autofix push?

`GITHUB_TOKEN` cannot push to a branch protected by required status checks because GitHub would not re-trigger CI on a commit made by the Actions runner itself (prevents infinite loops). A PAT with `repo` scope is treated as a human push and does trigger CI.

Rotate the PAT quarterly. Store it in a repository secret, not an org-level secret, to limit blast radius.

### HITL timeout behaviour

The autofix workflow is not a merge bot. It patches the branch and posts a comment. A human reviewer must still approve the PR before merge (enforced by branch protection). If Claude cannot safely fix something, it writes a `# AUTOFIX NEEDS REVIEW` comment in the file and adds the finding to the `needs-human-review` section of `autofix-summary.md`.

Default on timeout or uncertainty: **escalate, never bypass.**

### Adding a new scanner

1. Add a job to `security.yml` that outputs a SARIF file.
2. Upload the SARIF as an artifact with a recognisable name (e.g. `mytools-sarif`).
3. Update `sarif_to_findings.py`'s `infer_tool_name()` to recognise the filename.
4. Test with a seeded finding.

No changes to `autofix.yml` are needed — it downloads all `*-sarif` artifacts generically.

---

## Operating the Pipeline Day-to-Day

### Reviewing an autofix commit

When Claude pushes a fix commit:
1. Read `autofix-summary.md` on the PR for what changed and why.
2. Check the diff — Claude should only touch lines flagged by a finding.
3. If Claude marked something `# AUTOFIX NEEDS REVIEW`, resolve it manually before approving.
4. Approve the PR once you are satisfied the fix is correct and tests are green.

### Secrets found by Gitleaks

Gitleaks findings are different from code vulnerabilities:
1. **Rotate the credential immediately** — assume it is compromised.
2. Claude will replace the literal with `process.env.MY_SECRET` in the working tree, but the secret is already in Git history.
3. Use `git filter-repo` or GitHub's secret scanning remediation guide to purge the secret from history.
4. Add the secret to your secrets manager (AWS Secrets Manager, GCP Secret Manager, etc.).

### Adding assets to the catalog

Every asset that passes this pipeline should be registered in the COE asset catalog with:
- owner
- purpose
- systems touched
- credentials required
- KPI baseline (manual time saved, expected run frequency)
- review history link (the PR URL)

---

## Open Questions (align with Fulcrum before hardening)

- Which GitHub org and repo will host COE assets in production?
- Is a self-hosted runner needed for GCP/network access, or are GitHub-hosted runners acceptable for V1?
- Should SonarCloud or SonarQube (self-hosted) be the quality gate?
- What is the maximum autofix loop count before the PR is escalated to a human? (Recommend: 3 attempts.)
- Should autofix be disabled for secret findings and always escalated? (Recommended: yes.)
