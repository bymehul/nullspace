# nullspace Technical Reference

## Request Validation Pipeline

Every `safeFetch` request follows this flow:

1. Parse and normalize URL input.
2. Enforce protocol allowlist (`http`/`https`).
3. Enforce optional hostname allowlist policy.
4. Resolve DNS with timeout control.
5. Resolve recursive CNAME chains (with loop/depth checks).
6. Canonicalize all IPs and validate ranges.
7. Pin socket connection to the validated IP.
8. Execute request with redirect, timeout, and size hardening.

## Blocked Network Ranges

### IPv4

| Range | Reason |
|---|---|
| `0.0.0.0/8` | this host |
| `10.0.0.0/8` | private |
| `100.64.0.0/10` | carrier-grade NAT |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local / metadata |
| `172.16.0.0/12` | private |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.168.0.0/16` | private |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved |
| `255.255.255.255/32` | broadcast |

### IPv6

| Range | Reason |
|---|---|
| `::/128` | unspecified |
| `::1/128` | loopback |
| `::ffff:0:0/96` | IPv4-mapped IPv6 |
| `64:ff9b::/96` | NAT64 embedding |
| `100::/64` | discard-only |
| `2001:db8::/32` | documentation |
| `fc00::/7` | unique local |
| `fe80::/10` | link-local |
| `ff00::/8` | multicast |

## DNS Security Model

- Enforces a minimum DNS cache TTL floor to reduce rebinding risk.
- Rejects hostnames when any resolved IP is blocked.
- Supports IPv4 + IPv6 resolution (IPv6 can be disabled).
- Supports recursive CNAME resolution with:
  - loop detection
  - configurable max CNAME depth
- Supports bounded DNS cache size with oldest-entry eviction.

## Redirect Security Model

- Redirects are disabled by default.
- If enabled, each redirect target is parsed and validated again.
- Enforces redirect count limit.
- Blocks `https -> http` downgrade redirects.
- Preserves method/body only for `307` and `308`.

## DoS-Oriented Request Limits

`safeFetch` enforces:

- `connectTimeout`
- `responseTimeout`
- `totalTimeout` (absolute request deadline including redirects)
- `maxResponseSize`
- `maxResponseHeadersSize`
- header sanitization (`Authorization`, cookies, token-like headers)

## API

### `safeFetch(url, options?)`

```typescript
const result = await safeFetch('https://api.example.com', {
  method: 'GET',
  headers: { Accept: 'application/json' },
  followRedirects: false,
  maxRedirects: 0,
  connectTimeout: 5000,
  responseTimeout: 30000,
  totalTimeout: 60000,
  maxResponseSize: 10 * 1024 * 1024,
  maxResponseHeadersSize: 32 * 1024,
  stripSensitiveHeaders: true,
  userAgent: 'nullspace/1.0',
  allowedHostnames: ['api.example.com'],
});
```

### `validateURL(url, options?)`

```typescript
const check = await validateURL('https://api.example.com', {
  allowedHostnames: ['api.example.com'],
  dnsTimeout: 3000,
});
```

### `configureDNSResolver(config)`

```typescript
configureDNSResolver({
  dnsCacheTTLFloor: 60000,
  dnsCacheMaxEntries: 1024,
  maxCNAMEDepth: 8,
  allowIPv6: true,
  additionalBlockedRanges: ['203.0.114.0/24'],
});
```

## Error Codes

### Validation

- `MALFORMED_URL`
- `INVALID_PROTOCOL`
- `INVALID_HOSTNAME`
- `INVALID_PORT`
- `AMBIGUOUS_USERINFO`
- `NULL_BYTE_DETECTED`
- `WHITESPACE_IN_HOST`
- `HOST_NOT_ALLOWED`

### DNS

- `DNS_ERROR` with reason:
  - `RESOLUTION_FAILED`
  - `RESOLUTION_TIMEOUT`
  - `NO_RECORDS`
  - `NXDOMAIN`

### Request

- `REQUEST_ERROR` with reason:
  - `CONNECT_TIMEOUT`
  - `RESPONSE_TIMEOUT`
  - `HEADERS_TOO_LARGE`
  - `RESPONSE_TOO_LARGE`
  - `CONNECTION_REFUSED`
  - `CONNECTION_RESET`

### Redirect

- `REDIRECT_BLOCKED` with reason:
  - `MAX_REDIRECTS_EXCEEDED`
  - `PROTOCOL_DOWNGRADE`
  - `CROSS_PROTOCOL`
  - `INVALID_LOCATION`

## Security Notes

- `dnsResolver` override is intended for testing and controlled environments.
- `additionalBlockedRanges` is cumulative with built-in range protections.
- Hostname allowlists are optional and are useful for high-trust outbound integrations.
