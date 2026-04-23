/**
 * RFC 8785 canonicalizer tests — byte-equality against the shared fixture suite.
 *
 * The fixtures file is byte-identical to
 * `python/tests/passport/fixtures/rfc8785-fixtures.json`. Cross-SDK
 * byte-equality is a release invariant (spec §11.2, §13 row 23): if any
 * fixture diverges between `json-canonicalize`, the backend's canonicalizer,
 * or the Python SDK's `jcs`, STOP — do not paper over the divergence.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { canonicalizeStrict, CanonicalizationError } from '../src/passport/canonical.js';

interface Fixture {
  name: string;
  description: string;
  input: unknown;
  input_is_sentinel?: boolean;
  input_sentinel?: 'NaN' | 'Infinity' | '-Infinity';
  expected_canonical_bytes_hex?: string;
  expected_rejects?: boolean;
}

const __filename = fileURLToPath(import.meta.url);
const FIXTURES_PATH = join(dirname(__filename), 'fixtures', 'rfc8785-fixtures.json');

const SENTINEL_DECODE: Record<string, number> = {
  NaN: Number.NaN,
  Infinity: Number.POSITIVE_INFINITY,
  '-Infinity': Number.NEGATIVE_INFINITY,
};

function loadFixtures(): Fixture[] {
  return JSON.parse(readFileSync(FIXTURES_PATH, 'utf8')) as Fixture[];
}

function decodeFixtureInput(fx: Fixture): unknown {
  if (fx.input_is_sentinel) {
    const sentinel = fx.input_sentinel;
    if (sentinel === undefined || !(sentinel in SENTINEL_DECODE)) {
      throw new Error(`unknown sentinel ${String(sentinel)} in fixture ${fx.name}`);
    }
    return SENTINEL_DECODE[sentinel];
  }
  return fx.input;
}

const ALL_FIXTURES = loadFixtures();
const BYTE_EQUAL_FIXTURES = ALL_FIXTURES.filter((f) => !f.expected_rejects);
const REJECT_FIXTURES = ALL_FIXTURES.filter((f) => f.expected_rejects === true);

describe('canonicalizeStrict: RFC 8785 byte-equal fixtures', () => {
  it.each(BYTE_EQUAL_FIXTURES)('$name', (fx) => {
    if (fx.expected_canonical_bytes_hex === undefined) {
      throw new Error(`fixture ${fx.name} is not a reject case but has no expected bytes`);
    }
    const expected = Buffer.from(fx.expected_canonical_bytes_hex, 'hex');
    const actual = canonicalizeStrict(decodeFixtureInput(fx));
    const actualBuf = Buffer.from(actual.buffer, actual.byteOffset, actual.byteLength);
    expect(actualBuf.equals(expected)).toBe(true);
  });
});

describe('canonicalizeStrict: reject non-finite numbers', () => {
  it.each(REJECT_FIXTURES)('$name', (fx) => {
    expect(() => canonicalizeStrict(decodeFixtureInput(fx))).toThrow(CanonicalizationError);
  });
});

describe('canonicalizeStrict: contract pinning', () => {
  it('rejects each non-finite value directly', () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => canonicalizeStrict(value)).toThrow(CanonicalizationError);
    }
  });

  it('CanonicalizationError is not a TypeError', () => {
    // Pin the error-type contract against accidental drift. `JSON.stringify`
    // returns the string "null" for NaN, and `json-canonicalize` matches that;
    // our pre-walk must intercept first so callers get a stable SDK-owned type.
    let caught: unknown = null;
    try {
      canonicalizeStrict(Number.NaN);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CanonicalizationError);
    expect(caught).not.toBeInstanceOf(TypeError);
  });

  it('error carries reasonCode', () => {
    try {
      canonicalizeStrict(Number.NaN);
      throw new Error('expected CanonicalizationError');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalizationError);
      expect((err as CanonicalizationError).reasonCode).toBe(
        'non_finite_number_in_canonical_input',
      );
    }
  });

  it('error carries path pointing at the offending value', () => {
    try {
      canonicalizeStrict({ a: [1, Number.NaN] });
      throw new Error('expected CanonicalizationError');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalizationError);
      expect((err as CanonicalizationError).path).toEqual(['a', '1']);
    }
  });
});
