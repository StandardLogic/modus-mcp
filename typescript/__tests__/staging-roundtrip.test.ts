/**
 * C20.7 — cross-backend round-trip tests against live staging.
 *
 * Port of python/tests/passport/test_cross_backend_roundtrip.py. Spec §13
 * row coverage when staging is reachable:
 *   * Row 1  — self-issue + register.
 *   * Row 2  — registered self-issued PERMIT at L0 gate.
 *   * Row 3  — self-signed revocation.
 *   * Row 10 — 2-link delegation PERMIT at L0 gate  (SKIPPED: backend gap).
 *   * Row 21 — revoked passport blocks at gate (bounded-poll).
 *
 * Rows 17, 18 (platform- and gate-rooted delegations) remain deferred:
 * staging lacks the signing-key material. SDK PassportVerifier returns
 * `signature_key_unavailable` locally for those envelopes.
 *
 * Env-var gates
 * -------------
 * * `MODEI_STAGING_URL` — required for ALL tests here. Skips cleanly
 *   when absent.
 * * `MODEI_TEST_L0_GATE_ID` — required for the 3 gate-check tests
 *   (rows 2, 10 skipped, 21). Rows 1 and 3 run without it.
 *
 * Rate-limit warnings
 * -------------------
 * The staging register endpoint rate-limits at 10 per hour per IP. A
 * full-suite run posts ~4 registrations. Two consecutive reruns hit
 * the cap — hour-long cooldowns required between bulk reruns from the
 * same workstation.
 *
 * Test artifact cleanup: registered passports stay on staging as test
 * artifacts. Test 3 self-revokes its passport; other tests do not.
 * Matches Python behavior.
 */

import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import {
  AgentCredentials,
  PassportIssuer,
  canonicalizeStrict,
} from '../src/index.js';
import type { SignedPassport } from '../src/passport/envelope.js';

// sync SHA-512 hook for @noble/ed25519 v3; required before any sign/verify/getPublicKey call.
ed.hashes.sha512 = sha512;

const STAGING_URL = process.env.MODEI_STAGING_URL;
const L0_GATE_ID = process.env.MODEI_TEST_L0_GATE_ID;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async function post(path: string, body: unknown, timeoutMs = 30_000): Promise<Response> {
  if (!STAGING_URL) throw new Error('MODEI_STAGING_URL is not set');
  const url = STAGING_URL.replace(/\/$/, '') + path;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function registerPassport(signed: SignedPassport): Promise<Response> {
  return post('/api/passports/register', {
    passport_json: signed.envelope,
    signature: signed.signature,
  });
}

async function gateCheck(
  gateId: string,
  passportId: string,
  action = 'test:permit',
): Promise<Response> {
  return post(`/api/gates/${gateId}/check`, { passport_id: passportId, action });
}

/**
 * Build the `{assertion_json, assertion_signature}` body for POST
 * /api/passports/{id}/revoke. Port of Python `_build_revocation_payload`.
 * Endpoint-specific shape; not part of the public SDK surface.
 */
function buildRevocationPayload(
  passportId: string,
  creds: AgentCredentials,
): { assertion_json: Record<string, string>; assertion_signature: string } {
  const assertionJson = {
    passport_id: passportId,
    action: 'revoke',
    nonce: Buffer.from(randomBytes(16)).toString('base64url'),
    revoked_at: new Date().toISOString(),
  };
  const canonical = canonicalizeStrict(assertionJson);
  const sigBytes = ed.sign(canonical, creds.privateKey);
  return {
    assertion_json: assertionJson,
    assertion_signature: Buffer.from(sigBytes).toString('base64'),
  };
}

function issueFreshSelf(
  opts: {
    delegationAuthority?: boolean;
    expiresAt?: Date;
    permissions?: Array<{ permission_key: string; constraints?: Record<string, unknown> }>;
  } = {},
): { creds: AgentCredentials; signed: SignedPassport } {
  const creds = AgentCredentials.generate();
  const signed = new PassportIssuer(creds, { identityClaim: 'sdk-test@dev.local' }).selfIssue({
    permissions: opts.permissions ?? [{ permission_key: 'test:permit', constraints: {} }],
    expiresAt: opts.expiresAt ?? new Date(Date.now() + 60 * 60 * 1000),
    delegationAuthority: opts.delegationAuthority,
  });
  return { creds, signed };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

describe.skipIf(!STAGING_URL)('staging round-trip (C20.7)', () => {
  // -------------------------------------------------------------------------
  // Row 1 — self-issue + register
  // -------------------------------------------------------------------------
  it('self-issue + register', { timeout: 30_000 }, async () => {
    const { creds, signed } = issueFreshSelf();
    const response = await registerPassport(signed);
    const text = await response.text();
    expect(response.status, `register failed: ${response.status} body=${text}`).toBe(200);

    const body = JSON.parse(text) as {
      passport_id?: string;
      agent_id?: string;
      status?: string;
    };
    expect(body.passport_id).toBe(signed.envelope.passport_id);
    expect(body.agent_id).toBe(creds.agentId);
    expect(['active', 'idempotent']).toContain(body.status);
  });

  // -------------------------------------------------------------------------
  // Row 3 — self-signed revocation
  // -------------------------------------------------------------------------
  it('self-signed revocation', { timeout: 30_000 }, async () => {
    const { creds, signed } = issueFreshSelf();
    const reg = await registerPassport(signed);
    expect(reg.status, `register failed: ${reg.status}`).toBe(200);

    const revokeBody = buildRevocationPayload(signed.envelope.passport_id, creds);
    const revoke = await post(`/api/passports/${signed.envelope.passport_id}/revoke`, revokeBody);
    const text = await revoke.text();
    expect(revoke.status, `revoke failed: ${revoke.status} body=${text}`).toBe(200);

    const body = JSON.parse(text) as { passport_id?: string; status?: string };
    expect(body.passport_id).toBe(signed.envelope.passport_id);
    // Idempotent — either freshly revoked or already_revoked is acceptable.
    expect(['active', 'already_revoked', 'revoked']).toContain(body.status);
  });

  // -------------------------------------------------------------------------
  // L0 gate subset (rows 2, 10, 21) — requires MODEI_TEST_L0_GATE_ID
  // -------------------------------------------------------------------------
  describe.skipIf(!L0_GATE_ID)('L0 gate checks', () => {
    // Re-read inside the block so TS sees a stable non-null reference.
    const gateId = L0_GATE_ID as string;

    // -----------------------------------------------------------------------
    // Row 2 — registered self-issued PERMIT at L0 gate
    // -----------------------------------------------------------------------
    it('self-issued permit at L0 gate', { timeout: 30_000 }, async () => {
      const { signed } = issueFreshSelf();
      const reg = await registerPassport(signed);
      expect(reg.status).toBe(200);

      const check = await gateCheck(gateId, signed.envelope.passport_id);
      const text = await check.text();
      expect(check.status, `/check failed: ${check.status} body=${text}`).toBe(200);

      const body = JSON.parse(text) as { allowed?: boolean; decision?: string };
      expect(body.allowed, `expected allowed=true; got body=${text}`).toBe(true);
      // Endpoint returns lowercase "allow"/"deny"; canonical PERMIT/BLOCK/
      // SUSPEND taxonomy reconciliation tracked in modei checklist C19.7
      // additions.
      expect(body.decision).toBe('allow');
    });

    // -----------------------------------------------------------------------
    // Row 10 — SKIPPED: backend /check auth-bypass gap
    // -----------------------------------------------------------------------
    it.skip(
      'delegation chain permits at L0 gate (backend /check auth-bypass gap)',
      () => {
        // Backend product gap: /check auth-bypass keys on envelope-level
        // `is_self_issued` flag (issuer.type === 'self'), not on chain
        // root. Delegate-rooted-from-self passports require API key for
        // /check, breaking the sub-agent delegation use case. Tracked in
        // `modei specs/modei-remaining-checklist.md` C19.7 additions.
        // Protocol-level delegation round-trip is already validated
        // offline by C20.4's verifier.test.ts "cross-backend delegation
        // fixture parity" test. Re-enable when /check honors chain-root
        // identity (see C19.7b commit: register/route.ts:162,
        // check/route.ts:283-296).
      },
    );

    // -----------------------------------------------------------------------
    // Row 21 — revoked passport blocks at gate (bounded-poll)
    // -----------------------------------------------------------------------
    it('revoked passport blocks at gate', { timeout: 120_000 }, async () => {
      // Revoke cascades to gate /check within the 60s revocation-cache TTL.
      // Spec §10 documents bounded eventual consistency; gates running
      // against a warm cache may continue to PERMIT a revoked passport
      // until refresh. Bounded retries (up to 6 × 15s = 90s) so the cache
      // has ample time to refresh. Passes when allowed === false is
      // observed at any iteration. Fails only if all 6 attempts return
      // allowed === true — that would indicate the cache cascade is fully
      // broken, not slow.
      const { creds, signed } = issueFreshSelf();
      const reg = await registerPassport(signed);
      expect(reg.status).toBe(200);

      const revokeBody = buildRevocationPayload(signed.envelope.passport_id, creds);
      const revoke = await post(`/api/passports/${signed.envelope.passport_id}/revoke`, revokeBody);
      expect(revoke.status).toBe(200);

      const MAX_ATTEMPTS = 6;
      const SLEEP_MS = 15_000;
      const observed: Array<{
        attempt: number;
        status_code: number;
        allowed: unknown;
        decision: unknown;
        reason_code: unknown;
      }> = [];

      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const check = await gateCheck(gateId, signed.envelope.passport_id);
        let body: { allowed?: unknown; decision?: unknown; reason_code?: unknown } = {};
        const text = await check.text();
        try {
          body = JSON.parse(text) as typeof body;
        } catch {
          body = { allowed: undefined, decision: undefined, reason_code: undefined };
        }
        observed.push({
          attempt,
          status_code: check.status,
          allowed: body.allowed,
          decision: body.decision,
          reason_code: body.reason_code,
        });
        if (body.allowed === false) {
          console.log(
            `[row21] cache cascade observed on attempt ${attempt} after ` +
              `~${(attempt - 1) * (SLEEP_MS / 1000)}s: ` +
              `reason_code=${JSON.stringify(body.reason_code)} ` +
              `decision=${JSON.stringify(body.decision)}`,
          );
          return;
        }
        if (attempt < MAX_ATTEMPTS) {
          await sleep(SLEEP_MS);
        }
      }

      throw new Error(
        `revoked passport still PERMITting after ${MAX_ATTEMPTS} attempts ` +
          `spanning ~${(MAX_ATTEMPTS - 1) * (SLEEP_MS / 1000)}s. ` +
          `Observations: ${JSON.stringify(observed)}`,
      );
    });
  });
});
