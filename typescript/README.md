# modei-typescript

TypeScript SDK for the [Modei](https://modei.ai) REST API and self-issued passport workflows.

> **Status:** `1.0.0-rc.1` — release candidate. Promotes to `1.0.0` at prod cutover.

## Install

```bash
npm install modei-typescript
# or
pnpm add modei-typescript
```

Requires Node.js ≥ 18.

## RFC 8785 canonicalization

The SDK exposes a strict RFC 8785 canonicalizer that is byte-equal with the Modei backend and the [`modei-python`](https://pypi.org/project/modei-python/) SDK. Cross-SDK byte-equality is a release invariant.

```ts
import { canonicalizeStrict, CanonicalizationError } from 'modei-typescript/passport/canonical';

const bytes = canonicalizeStrict({ b: 1, a: 2 });
// => Uint8Array of UTF-8 bytes for '{"a":2,"b":1}'

try {
  canonicalizeStrict({ x: Number.NaN });
} catch (err) {
  if (err instanceof CanonicalizationError) {
    console.log(err.reasonCode); // 'non_finite_number_in_canonical_input'
    console.log(err.path); // ['x']
  }
}
```

## Passport verify reason codes

```ts
import {
  PASSPORT_VERIFY_REASON_CODES,
  type PassportVerifyReasonCode,
} from 'modei-typescript/passport/reasons';

PASSPORT_VERIFY_REASON_CODES.has('passport_expired'); // true
```

## License

MIT — see [LICENSE](./LICENSE).
