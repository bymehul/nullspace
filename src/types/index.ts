/**
 * nullspace - ssrf prevention library
 * 
 * typescript type definitions for the library.
 */

import type { CanonicalIP, CIDRRange } from '../utils/ip-utils';

// re-export utility types
export type { CanonicalIP, CIDRRange };

// result of url parsing and normalization
export interface ParsedURL {
    // protocol (always 'http:' or 'https:' after validation)
    protocol: 'http:' | 'https:';

    // normalized hostname (lowercase, ascii after idna)
    hostname: string;

    // port number (explicit or default based on protocol)
    port: number;

    // path component
    pathname: string;

    // query string (including leading ?)
    search: string;

    // fragment (stripped for actual requests, kept for reference)
    hash: string;

    // original url input for logging
    originalURL: string;

    // whether hostname is an ip literal (vs domain name)
    isIPLiteral: boolean;
}

// result of dns resolution
export interface ResolvedHost {
    // original hostname that was resolved
    hostname: string;

    // all resolved ipv4 addresses
    ipv4Addresses: CanonicalIP[];

    // all resolved ipv6 addresses
    ipv6Addresses: CanonicalIP[];

    // timestamp of resolution (for cache management)
    resolvedAt: number;
}

// result of ip range validation
export interface RangeCheckResult {
    // whether the ip is allowed (not in any blocked range)
    allowed: boolean;

    // if blocked, which range triggered the block
    blockedRange?: CIDRRange;

    // the ip that was checked
    ip: CanonicalIP;
}

// result of full url validation (without fetching)
export interface ValidationResult {
    // whether the url passed all validation
    valid: boolean;

    // error message if validation failed
    error?: string;

    // error code if validation failed
    errorCode?: string;

    // parsed and normalized url if validation succeeded
    parsedURL?: ParsedURL;

    // resolved ips if validation succeeded and included dns resolution
    resolvedIPs?: CanonicalIP[];
}

// options for safe fetch operation
export interface SafeFetchOptions {
    // http method (default: 'get')
    method?: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

    // request headers (sensitive headers will be stripped)
    headers?: Record<string, string>;

    // request body (for post/put/patch)
    body?: string | Buffer;

    // whether to follow redirects (default: false)
    followRedirects?: boolean;

    // maximum number of redirects to follow (default: 0)
    maxRedirects?: number;

    // connection timeout in milliseconds (default: 5000)
    connectTimeout?: number;

    // total response timeout in milliseconds (default: 30000)
    responseTimeout?: number;

    // maximum response body size in bytes (default: 10mb)
    maxResponseSize?: number;

    // whether to strip sensitive headers from request (default: true)
    stripSensitiveHeaders?: boolean;

    // custom user agent (default: 'nullspace/1.0')
    userAgent?: string;
}

// timing information for a request
export interface RequestTiming {
    // when the request started
    startTime: number;

    // when dns resolution completed
    dnsTime?: number;

    // when connection was established
    connectTime?: number;

    // when first byte was received
    firstByteTime?: number;

    // when request completed
    endTime: number;

    // total duration in milliseconds
    totalMs: number;
}

// result of a safe fetch operation
export interface SafeFetchResult {
    // http status code
    status: number;

    // http status text
    statusText: string;

    // response headers
    headers: Record<string, string>;

    // response body
    body: Buffer;

    // final url after any redirects
    finalURL: string;

    // chain of urls if redirects were followed
    redirectChain: string[];

    // timing information
    timing: RequestTiming;

    // the ip address that was actually connected to
    connectedIP: string;
}

// configuration options for nullspace
export interface NullspaceConfig {
    // custom dns resolver function (for testing)
    // warning: using a custom resolver can bypass security protections
    dnsResolver?: (hostname: string) => Promise<{ ipv4: string[]; ipv6: string[] }>;

    // minimum ttl for dns cache in milliseconds (default: 60000)
    // cannot be set below 60000 to prevent dns rebinding
    dnsCacheTTLFloor?: number;

    // whether to allow ipv6 (default: true)
    // set to false if your infrastructure is ipv4-only
    allowIPv6?: boolean;

    // additional cidr ranges to block (on top of default blocks)
    additionalBlockedRanges?: string[];
}

// internal validated url ready for fetching
export interface ValidatedRequest {
    // original parsed url
    parsedURL: ParsedURL;

    // validated ip to connect to
    targetIP: CanonicalIP;

    // port to connect to
    targetPort: number;

    // original hostname for host header
    originalHost: string;

    // whether connection should use tls
    useTLS: boolean;
}

// headers that should never be forwarded to external hosts
export const SENSITIVE_HEADERS = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-csrf-token',
    'x-xsrf-token',
    'proxy-authorization',
] as const;

// default safe fetch options
export const DEFAULT_FETCH_OPTIONS: Required<Omit<SafeFetchOptions, 'body' | 'headers'>> = {
    method: 'GET',
    followRedirects: false,
    maxRedirects: 0,
    connectTimeout: 5000,
    responseTimeout: 30000,
    maxResponseSize: 10 * 1024 * 1024, // 10mb
    stripSensitiveHeaders: true,
    userAgent: 'nullspace/1.0',
};
