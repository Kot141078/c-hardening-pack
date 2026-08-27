#!/usr/bin/env node
// Independent ECMAScript verifier for the repository's RFC 8785 golden bytes.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(readFileSync(resolve(root, "canonicalization/runtime-jcs-golden-vectors.json"), "utf8"));
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function assertNoDuplicateObjectMembers(text) {
  let index = 0;
  const whitespace = /\s/;
  function skip() { while (index < text.length && whitespace.test(text[index])) index += 1; }
  function parseString() {
    skip();
    if (text[index] !== '"') throw new Error("expected string");
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    throw new Error("unterminated string");
  }
  function parseValue() {
    skip();
    if (text[index] === "{") {
      index += 1;
      const keys = new Set();
      skip();
      if (text[index] === "}") { index += 1; return; }
      while (true) {
        const key = parseString();
        if (keys.has(key)) throw new Error(`duplicate object member: ${key}`);
        keys.add(key);
        skip();
        if (text[index++] !== ":") throw new Error("expected colon");
        parseValue();
        skip();
        if (text[index] === "}") { index += 1; return; }
        if (text[index++] !== ",") throw new Error("expected comma");
      }
    }
    if (text[index] === "[") {
      index += 1;
      skip();
      if (text[index] === "]") { index += 1; return; }
      while (true) {
        parseValue();
        skip();
        if (text[index] === "]") { index += 1; return; }
        if (text[index++] !== ",") throw new Error("expected comma");
      }
    }
    if (text[index] === '"') { parseString(); return; }
    const start = index;
    while (index < text.length && !/[\s,}\]]/.test(text[index])) index += 1;
    if (start === index) throw new Error("expected value");
    const token = text.slice(start, index);
    if (/^-?(?:0|[1-9][0-9]*)$/.test(token) && (BigInt(token) > 9007199254740991n || BigInt(token) < -9007199254740991n)) {
      throw new Error("unsafe integer");
    }
  }
  parseValue();
  skip();
  if (index !== text.length) throw new Error("trailing input");
}

function validateString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("lone surrogate");
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("lone surrogate");
    }
  }
}

function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") { validateString(value); return JSON.stringify(value); }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE) throw new Error("unsafe integer-valued number");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => {
      validateString(key);
      return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
    }).join(",")}}`;
  }
  throw new Error(`unsupported type: ${typeof value}`);
}

let passed = 0;
const failures = [];
for (const vector of vectors.positive_vectors) {
  try {
    assertNoDuplicateObjectMembers(vector.input_json);
    const bytes = Buffer.from(canonicalize(JSON.parse(vector.input_json)), "utf8");
    if (bytes.toString("hex") !== vector.canonical_utf8_hex) throw new Error("canonical bytes differ");
    if (createHash("sha256").update(bytes).digest("hex") !== vector.sha256) throw new Error("SHA-256 differs");
    passed += 1;
  } catch (error) { failures.push(`${vector.id}: ${error.message}`); }
}
for (const vector of vectors.negative_vectors) {
  try {
    assertNoDuplicateObjectMembers(vector.input_json);
    canonicalize(JSON.parse(vector.input_json));
    failures.push(`${vector.id}: out-of-domain JSON was accepted`);
  } catch (_) { passed += 1; }
}
const total = vectors.positive_vectors.length + vectors.negative_vectors.length;
console.log(`RUNTIME_JCS_NODE vectors=${total} pass=${passed} fail=${failures.length}`);
for (const failure of failures) console.error(failure);
process.exitCode = failures.length === 0 ? 0 : 1;
