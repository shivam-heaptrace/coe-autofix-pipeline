/**
 * Basic smoke tests for the POC app.
 * These must stay green after autofix.
 */
"use strict";

const request = require("supertest");
const { app } = require("./index");

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const res = await request(app).get("/health");
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe("ok");
  });
});

describe("GET /greet", () => {
  it("returns 200", async () => {
    const res = await request(app).get("/greet?who=World");
    expect(res.statusCode).toBe(200);
  });

  it("contains the name in the response", async () => {
    const res = await request(app).get("/greet?who=Alice");
    expect(res.text).toContain("Alice");
  });
});
