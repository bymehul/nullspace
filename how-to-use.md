# how to use nullspace

a casual guide with examples. grab coffee.

---

## basic fetch

the simplest case - just fetch with protection:

```typescript
import { safeFetch } from 'nullspace';

const res = await safeFetch('https://api.example.com/users');

console.log(res.status);        // 200
console.log(res.body.toString()); // response body
console.log(res.connectedIP);   // actual ip connected to
```

---

## validate without fetching

sometimes you just wanna check if a url is safe:

```typescript
import { validateURL } from 'nullspace';

const result = await validateURL(userInput);

if (result.valid) {
  console.log('safe to fetch');
  console.log('resolved ips:', result.resolvedIPs);
} else {
  console.log('blocked:', result.error);
  console.log('reason:', result.errorCode);
}
```

---

## check a single ip

quick ip check, no dns involved:

```typescript
import { isIPAllowed } from 'nullspace';

isIPAllowed('8.8.8.8');          // true - public
isIPAllowed('127.0.0.1');        // false - loopback
isIPAllowed('192.168.1.1');      // false - private
isIPAllowed('169.254.169.254');  // false - cloud metadata
isIPAllowed('::1');              // false - ipv6 loopback
```

---

## all fetch options

here's everything you can pass:

```typescript
const res = await safeFetch('https://api.example.com', {
  // http method
  method: 'POST',  // GET, HEAD, POST, PUT, DELETE, PATCH
  
  // request body
  body: JSON.stringify({ name: 'test' }),
  
  // headers (sensitive ones get stripped automatically)
  headers: {
    'Content-Type': 'application/json',
    'X-Custom': 'value',
  },
  
  // redirects (disabled by default - safer)
  followRedirects: false,
  maxRedirects: 0,
  
  // timeouts
  connectTimeout: 5000,   // 5s to establish connection
  responseTimeout: 30000, // 30s total response time
  
  // limits
  maxResponseSize: 10 * 1024 * 1024, // 10mb max
  
  // security
  stripSensitiveHeaders: true,  // removes auth, cookies, etc
  userAgent: 'my-app/1.0',
});
```

---

## handling responses

what you get back:

```typescript
const res = await safeFetch(url);

// status
res.status;      // 200
res.statusText;  // 'OK'

// headers
res.headers;     // { 'content-type': 'application/json', ... }

// body (buffer)
res.body;                  // <Buffer ...>
res.body.toString();       // as string
JSON.parse(res.body.toString()); // as json

// metadata
res.finalURL;     // final url after redirects
res.connectedIP;  // ip that was actually connected to
res.redirectChain; // list of urls if redirects followed

// timing
res.timing.totalMs;    // total request time
res.timing.dnsTime;    // dns resolution time
res.timing.connectTime; // connection established time
```

---

## error handling

things can fail. here's how to catch them:

```typescript
import { 
  safeFetch, 
  RangeError,
  DNSError,
  RequestError,
  ValidationError 
} from 'nullspace';

try {
  await safeFetch(url);
} catch (error) {
  // check error type
  if (error.code === 'RANGE_BLOCKED') {
    console.log('blocked ip:', error.blockedIP);
    console.log('range:', error.blockedRange);
  }
  
  if (error.code === 'DNS_ERROR') {
    console.log('hostname:', error.hostname);
  }
  
  if (error.code === 'REQUEST_ERROR') {
    console.log('connection failed');
  }
  
  // all errors have these
  console.log(error.code);      // error code
  console.log(error.message);   // human message
  console.log(error.input);     // original url
  console.log(error.timestamp); // when it happened
}
```

---

## common error codes

| code | what happened |
|------|---------------|
| `RANGE_BLOCKED` | ip is private/reserved |
| `NULL_BYTE_DETECTED` | someone's being sneaky |
| `AMBIGUOUS_USERINFO` | weird @ symbols in url |
| `MALFORMED_URL` | url parsing failed |
| `DNS_ERROR` | couldn't resolve hostname |
| `CONNECT_TIMEOUT` | took too long to connect |
| `RESPONSE_TIMEOUT` | response took too long |
| `RESPONSE_TOO_LARGE` | body exceeded limit |
| `CONNECTION_REFUSED` | server said no |
| `CONNECTION_RESET` | connection dropped |

---

## following redirects

disabled by default (safer). if you need them:

```typescript
const res = await safeFetch(url, {
  followRedirects: true,
  maxRedirects: 5,  // limit hops
});

// see where we ended up
console.log(res.finalURL);
console.log(res.redirectChain);
```

each redirect gets fully validated. no sneaky redirects to localhost.

---

## post with json

common pattern:

```typescript
const res = await safeFetch('https://api.example.com/users', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'user',
    email: 'user@example.com',
  }),
});

const user = JSON.parse(res.body.toString());
```

---

## webhooks / user urls

classic ssrf scenario - user gives you a url:

```typescript
async function handleWebhook(userUrl: string) {
  // validate first
  const check = await validateURL(userUrl);
  
  if (!check.valid) {
    throw new Error(`invalid url: ${check.error}`);
  }
  
  // safe to fetch
  const res = await safeFetch(userUrl, {
    method: 'POST',
    body: JSON.stringify({ event: 'user.created' }),
    headers: { 'Content-Type': 'application/json' },
    connectTimeout: 10000,
    responseTimeout: 30000,
  });
  
  return res.status === 200;
}
```

---

## batch validation

check multiple urls:

```typescript
async function validateUrls(urls: string[]) {
  const results = await Promise.all(
    urls.map(async (url) => ({
      url,
      result: await validateURL(url),
    }))
  );
  
  const valid = results.filter(r => r.result.valid);
  const blocked = results.filter(r => !r.result.valid);
  
  console.log(`${valid.length} valid, ${blocked.length} blocked`);
  return valid.map(r => r.url);
}
```

---

## express middleware example

protect your proxy endpoint:

```typescript
import express from 'express';
import { validateURL, safeFetch } from 'nullspace';

const app = express();

app.get('/fetch', async (req, res) => {
  const url = req.query.url as string;
  
  if (!url) {
    return res.status(400).json({ error: 'url required' });
  }
  
  // validate
  const check = await validateURL(url);
  if (!check.valid) {
    return res.status(403).json({ 
      error: 'blocked', 
      reason: check.errorCode 
    });
  }
  
  // fetch
  try {
    const result = await safeFetch(url, { responseTimeout: 10000 });
    res.set('Content-Type', result.headers['content-type'] || 'text/plain');
    res.send(result.body);
  } catch (error) {
    res.status(502).json({ error: 'fetch failed' });
  }
});
```

---

## that's it

if something's not covered here, check [docs.md](./docs.md) for the deep dive.
