/**
 * Fulcrum AI COE — POC sample app
 *
 * ⚠️  This file intentionally contains three seeded vulnerabilities
 *     used to prove the scan → autofix → re-scan pipeline.
 *
 * VULN-1 (CodeQL — js/sql-injection): user input concatenated into SQL.
 * VULN-2 (CodeQL — js/xss):           unsanitised req.query echoed to HTML.
 * VULN-3 (Gitleaks — hardcoded-creds): fake API key literal in source.
 *
 * After autofix these should be patched to parameterised queries,
 * safe HTML escaping, and environment variable references respectively.
 */

"use strict";

const express = require("express");
const { Pool } = require("pg");

const app = express();

// ── Database pool ──────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ── VULN-3: hardcoded credential ──────────────────────────────────────────
// autofix target: replace with process.env.INTERNAL_API_KEY
const INTERNAL_API_KEY = "sk-fulcrum-dev-abc123secret";   // ← seeded secret

// ── Routes ────────────────────────────────────────────────────────────────

/**
 * GET /users?name=alice
 *
 * VULN-1: SQL injection — req.query.name concatenated directly into query.
 * autofix target: use parameterised query ($1 placeholder).
 */
app.get("/users", async (req, res) => {
  const name = req.query.name ?? "";

  // ⚠️  VULN-1: do not ship this
  const sql    = `SELECT id, name, email FROM users WHERE name = '${name}'`;
  const result = await pool.query(sql);

  res.json(result.rows);
});

/**
 * GET /greet?who=World
 *
 * VULN-2: reflected XSS — req.query.who echoed into HTML without escaping.
 * autofix target: escape the value before inserting into HTML.
 */
app.get("/greet", (req, res) => {
  const who = req.query.who ?? "stranger";

  // ⚠️  VULN-2: do not ship this
  res.send(`<h1>Hello, ${who}!</h1>`);
});

/**
 * GET /health
 * Safe endpoint used by CI and load balancers.
 */
app.get("/health", (_req, res) => {
  res.json({ status: "ok", version: process.env.npm_package_version });
});

// ── Start ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT ?? 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`COE POC listening on :${PORT}`);
  });
}

module.exports = { app };
