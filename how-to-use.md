# How to Use nullspace

This guide provides practical examples for common integration patterns.

## Basic Fetch

```typescript
import { safeFetch } from 'nullspace';

const res = await safeFetch('https://api.example.com/users');

console.log(res.status);
console.log(res.body.toString());
console.log(res.connectedIP);
```

## Validate Without Fetching

```typescript
import { validateURL } from 'nullspace';

const result = await validateURL(userInput);

if (!result.valid) {
  console.error(result.errorCode, result.error);
}
```

## Validate with Hostname Policy

```typescript
import { validateURL } from 'nullspace';

const result = await validateURL('https://api.example.com/data', {
  allowedHostnames: ['api.example.com'],
  dnsTimeout: 3000,
});
```

## Check a Single IP

```typescript
import { isIPAllowed } from 'nullspace';

isIPAllowed('8.8.8.8');          // true
isIPAllowed('127.0.0.1');        // false
isIPAllowed('192.168.1.1');      // false
isIPAllowed('169.254.169.254');  // false
isIPAllowed('::1');              // false
```

## Full `safeFetch` Options

```typescript
import { safeFetch } from 'nullspace';

const res = await safeFetch('https://api.example.com', {
  method: 'POST',
  body: JSON.stringify({ name: 'test' }),
  headers: {
    'Content-Type': 'application/json',
    'X-Custom': 'value',
  },
  followRedirects: true,
  maxRedirects: 5,
  connectTimeout: 5000,
  responseTimeout: 30000,
  totalTimeout: 60000,
  maxResponseSize: 10 * 1024 * 1024,
  maxResponseHeadersSize: 32 * 1024,
  stripSensitiveHeaders: true,
  userAgent: 'my-app/1.0',
  allowedHostnames: ['api.example.com'],
});
```

## Read Response Fields

```typescript
const res = await safeFetch(url);

res.status;
res.statusText;
res.headers;
res.body;
res.body.toString();
res.finalURL;
res.connectedIP;
res.redirectChain;
res.timing.totalMs;
res.timing.dnsTime;
res.timing.connectTime;
```

## Error Handling

```typescript
import { safeFetch } from 'nullspace';

try {
  await safeFetch(url);
} catch (error: any) {
  console.error(error.code, error.reason, error.message);
}
```

## Redirects

Redirects are disabled by default.

```typescript
const res = await safeFetch(url, {
  followRedirects: true,
  maxRedirects: 5,
});

console.log(res.finalURL);
console.log(res.redirectChain);
```

## Webhook / User URL Pattern

```typescript
import { validateURL, safeFetch } from 'nullspace';

async function sendWebhook(userURL: string): Promise<boolean> {
  const check = await validateURL(userURL, {
    allowedHostnames: ['hooks.example.com'],
  });

  if (!check.valid) {
    throw new Error(`invalid URL: ${check.errorCode}`);
  }

  const res = await safeFetch(userURL, {
    method: 'POST',
    body: JSON.stringify({ event: 'user.created' }),
    headers: { 'Content-Type': 'application/json' },
    connectTimeout: 10000,
    responseTimeout: 30000,
    totalTimeout: 60000,
  });

  return res.status === 200;
}
```

## Batch Validation

```typescript
import { validateURL } from 'nullspace';

async function validateUrls(urls: string[]) {
  const results = await Promise.all(
    urls.map(async (url) => ({
      url,
      result: await validateURL(url),
    }))
  );

  return {
    valid: results.filter((x) => x.result.valid).map((x) => x.url),
    blocked: results.filter((x) => !x.result.valid),
  };
}
```

## Express Middleware Example

```typescript
import express from 'express';
import { validateURL, safeFetch } from 'nullspace';

const app = express();

app.get('/fetch', async (req, res) => {
  const url = req.query.url as string;

  if (!url) {
    return res.status(400).json({ error: 'url required' });
  }

  const check = await validateURL(url);
  if (!check.valid) {
    return res.status(403).json({ error: 'blocked', reason: check.errorCode });
  }

  try {
    const result = await safeFetch(url, {
      responseTimeout: 10000,
      totalTimeout: 15000,
      maxResponseSize: 2 * 1024 * 1024,
    });

    res.set('Content-Type', result.headers['content-type'] || 'text/plain');
    return res.send(result.body);
  } catch {
    return res.status(502).json({ error: 'fetch failed' });
  }
});
```

For detailed behavior and full policy definitions, see [docs.md](./docs.md).
