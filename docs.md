# nullspace docs

the detailed stuff. you probably don't need this unless you're curious.

---

## how it works

6-stage pipeline that runs on every request:

1. **parse** - whatwg url parser, catches null bytes and weird encodings
2. **protocol check** - only http/https gets through
3. **dns resolve** - controlled resolver with 60s ttl floor (anti-rebinding)
4. **ip canonicalize** - converts all formats to binary for comparison
5. **range check** - compares against all rfc private/reserved ranges
6. **socket pin** - connects to the validated ip, not the hostname

---

## blocked ip ranges

### ipv4

| range | why |
|-------|-----|
| `0.0.0.0/8` | this host |
| `10.0.0.0/8` | private |
| `100.64.0.0/10` | carrier-grade nat |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local / cloud metadata |
| `172.16.0.0/12` | private |
| `192.168.0.0/16` | private |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved |

### ipv6

| range | why |
|-------|-----|
| `::1/128` | loopback |
| `::ffff:0:0/96` | ipv4-mapped (embedded ip checked) |
| `64:ff9b::/96` | nat64 (embedded ip checked) |
| `fc00::/7` | unique local (private) |
| `fe80::/10` | link-local |
| `ff00::/8` | multicast |

---

## bypass protection

things attackers try that we block:

### ip encoding tricks

```
2130706433        → 127.0.0.1 (decimal)
0x7f000001        → 127.0.0.1 (hex)
0177.0.0.1        → 127.0.0.1 (octal)
127.1             → 127.0.0.1 (short-form)
::ffff:127.0.0.1  → 127.0.0.1 (ipv6-mapped)
```

### dns attacks

- **rebinding**: attacker's dns returns public ip first, then localhost. we cache for 60s minimum + pin to validated ip.
- **multiple a records**: if any resolved ip is blocked, entire hostname is rejected.

### url tricks

- **null bytes**: `%00`, `%2500` detected and blocked
- **userinfo confusion**: `http://google.com@evil.com` blocked
- **backslash**: handled safely

### protocol attacks

blocked: `file://`, `gopher://`, `dict://`, `ftp://`, `data:`, `javascript:`

### redirect attacks

- each hop revalidated
- https→http blocked (protocol downgrade)

---

## error handling

```typescript
import { safeFetch, RangeError, DNSError } from 'nullspace';

try {
  await safeFetch(url);
} catch (error) {
  if (error.code === 'RANGE_BLOCKED') {
    console.log('blocked ip:', error.blockedIP);
  }
  if (error.code === 'NULL_BYTE_DETECTED') {
    console.log('injection attempt');
  }
}
```

### error codes

| code | meaning |
|------|---------|
| `RANGE_BLOCKED` | ip in private/reserved range |
| `NULL_BYTE_DETECTED` | null byte injection |
| `AMBIGUOUS_USERINFO` | multiple @ in url |
| `MALFORMED_URL` | invalid url |
| `DNS_ERROR` | resolution failed |
| `REQUEST_ERROR` | connection issue |

---

## full api

### `safeFetch(url, options?)`

```typescript
const res = await safeFetch('https://api.example.com', {
  method: 'POST',
  body: JSON.stringify({ data: 'value' }),
  headers: { 'Content-Type': 'application/json' },
  followRedirects: false,
  maxRedirects: 0,
  connectTimeout: 5000,
  responseTimeout: 30000,
  maxResponseSize: 10 * 1024 * 1024,
  stripSensitiveHeaders: true,
  userAgent: 'nullspace/1.0',
});
```

### `validateURL(url)`

```typescript
const result = await validateURL('https://api.example.com');
// { valid: true, parsedURL: {...}, resolvedIPs: [...] }
// or { valid: false, error: '...', errorCode: 'RANGE_BLOCKED' }
```

### `isIPAllowed(ip)`

```typescript
isIPAllowed('8.8.8.8');  // true
isIPAllowed('10.0.0.1'); // false
```

### `configureDNSResolver(config)`

```typescript
// for testing only - don't use in production
configureDNSResolver({
  dnsResolver: async (hostname) => ({ ipv4: ['1.2.3.4'], ipv6: [] }),
  dnsCacheTTLFloor: 60000,
});
```

---
## design principles

> the internal network must exist in a nullspace with respect to user-controlled input: reachable in theory, unreachable in practice.

we avoid the complexity of allowlists. private ranges are blocked by construction, not configuration. there is no `allowPrivate: true` option, as providing such an escape hatch would defeat the fundamental purpose of the library.

every line of code assumes the input is hostile.
