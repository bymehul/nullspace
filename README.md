# nullspace

ssrf protection that just works. blocks private ips, cloud metadata, dns rebinding.

## install

```bash
npm install nullspace
```

## use

```typescript
import { safeFetch, validateURL, isIPAllowed } from 'nullspace';

// fetch with protection
const res = await safeFetch('https://api.example.com/data');

// validate without fetching  
const check = await validateURL(userInput);
if (!check.valid) console.log('blocked:', check.error);

// check single ip
isIPAllowed('8.8.8.8');        // true
isIPAllowed('127.0.0.1');      // false
isIPAllowed('169.254.169.254'); // false
```

## what gets blocked

- localhost (`127.x.x.x`, `::1`)
- private ips (`10.x`, `172.16-31.x`, `192.168.x`)
- cloud metadata (`169.254.169.254`)
- dangerous protocols (`file://`, `gopher://`, `dict://`)
- encoding tricks (decimal, octal, hex ips)
- dns rebinding (ttl floor + socket pinning)

## options

```typescript
await safeFetch(url, {
  followRedirects: false,     // don't follow
  connectTimeout: 5000,       // ms
  maxResponseSize: 10485760,  // 10mb
});
```

## more docs

see [docs.md](./docs.md) for more details.

## license

mit
