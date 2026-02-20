# nullspace

Security-first SSRF protection for Node.js outbound HTTP requests.

`nullspace` validates URLs, blocks private/internal ranges, defends against DNS rebinding, and pins connections to validated IPs.

## Installation

```bash
npm install nullspace
```

## Quick Start

```typescript
import { safeFetch, validateURL, isIPAllowed } from 'nullspace';

const response = await safeFetch('https://api.example.com/data');

const check = await validateURL('https://api.example.com/data');
if (!check.valid) {
  console.error(check.errorCode, check.error);
}

isIPAllowed('8.8.8.8');         // true
isIPAllowed('127.0.0.1');       // false
isIPAllowed('169.254.169.254'); // false
```

## Key Protections

- Restricts protocols to `http` and `https`.
- Blocks loopback, private, link-local, metadata, multicast, and reserved ranges.
- Handles IPv4 encoding tricks (decimal, octal, hex, short forms).
- Handles IPv6 edge cases (`::1`, mapped IPv4, NAT64 embeddings).
- Rejects hostnames when any resolved record is internal.
- Resolves CNAME chains with loop and recursion-depth protection.
- Uses DNS cache floor plus socket pinning for rebinding resistance.
- Enforces response size, response header size, redirect count, and total timeout limits.

## Example Options

```typescript
await safeFetch('https://api.example.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ok: true }),
  followRedirects: true,
  maxRedirects: 5,
  connectTimeout: 5000,
  responseTimeout: 30000,
  totalTimeout: 60000,
  maxResponseSize: 10 * 1024 * 1024,
  maxResponseHeadersSize: 32 * 1024,
  allowedHostnames: ['api.example.com'],
});
```

## Documentation

- Usage examples: [how-to-use.md](./how-to-use.md)
- Technical reference: [docs.md](./docs.md)

## License

MIT
