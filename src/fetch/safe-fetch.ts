/**
 * nullspace - ssrf prevention library
 *
 * safe fetch module
 *
 * the main entry point for making safe outbound http requests.
 * combines all validation layers into a single secure fetch operation.
 */

import * as http from 'http';
import * as https from 'https';
import { parseURL, reconstructURL } from '../core/url-parser';
import { validateProtocol } from '../core/protocol-validator';
import { tryCanonicalizeIP } from '../core/ip-canonicalizer';
import { validateIPRange } from '../core/range-classifier';
import { validateHostnameAllowlist } from '../core/hostname-policy';
import { resolveAndValidate, selectConnectionIP } from '../core/dns-resolver';
import { createPinnedAgent, destroyAgent } from '../core/socket-pinner';
import {
    buildRequestHeaders,
    SizeLimitedBuffer,
    getTimeouts,
    getSizeLimits,
    validateRequestBody,
} from './request-hardener';
import {
    isRedirectStatus,
    shouldFollowRedirects,
    getMaxRedirects,
    parseRedirectLocation,
    validateRedirectCount,
    extractLocationHeader,
    shouldPreserveMethod,
    shouldPreserveBody,
} from './redirect-handler';
import { RequestError } from '../utils/errors';
import type {
    ParsedURL,
    SafeFetchOptions,
    SafeFetchResult,
    RequestTiming,
    CanonicalIP,
} from '../types';
import { DEFAULT_FETCH_OPTIONS } from '../types';

// computes remaining time until the absolute deadline, throws if exhausted
function getRemainingTimeout(deadlineAt: number, originalInput: string, totalTimeout: number): number {
    const remaining = deadlineAt - Date.now();
    if (remaining <= 0) {
        throw new RequestError(
            `total request timeout (${totalTimeout}ms) exceeded`,
            originalInput,
            'RESPONSE_TIMEOUT'
        );
    }
    return remaining;
}

// estimates response header byte size from raw header pairs
function getHeaderSizeBytes(rawHeaders: string[] | undefined): number {
    if (!rawHeaders || rawHeaders.length === 0) {
        return 0;
    }

    let total = 0;

    for (let i = 0; i < rawHeaders.length; i += 2) {
        const key = rawHeaders[i] ?? '';
        const value = rawHeaders[i + 1] ?? '';
        total += Buffer.byteLength(key) + 2 + Buffer.byteLength(value) + 2;
    }

    return total;
}

/**
 * performs a safe http/https fetch with full ssrf protection.
 *
 * pipeline:
 * 1. parse and normalize url
 * 2. validate protocol (http/https only)
 * 3. validate optional hostname allowlist policy
 * 4. resolve dns (or validate ip literal)
 * 5. validate all resolved ips against blocked ranges
 * 6. create pinned connection to validated ip
 * 7. execute request with hardening
 * 8. handle redirects (if enabled) by repeating pipeline
 */
export async function safeFetch(
    url: string,
    options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
    const timing: RequestTiming = {
        startTime: Date.now(),
        endTime: 0,
        totalMs: 0,
    };

    const totalTimeout = options.totalTimeout ?? DEFAULT_FETCH_OPTIONS.totalTimeout;
    const deadlineAt = timing.startTime + totalTimeout;

    const redirectChain: string[] = [];
    let currentURL = url;
    let redirectCount = 0;

    // validate request body if present
    const body = validateRequestBody(
        options.body,
        getSizeLimits(options).maxResponseSize
    );

    let currentMethod: SafeFetchOptions['method'] | 'GET' = options.method;
    let currentBody = body;

    // main request loop (handles redirects)
    while (true) {
        getRemainingTimeout(deadlineAt, url, totalTimeout);

        // step 1: parse url
        const parsedURL = parseURL(currentURL);
        redirectChain.push(reconstructURL(parsedURL));

        // step 2: validate protocol
        validateProtocol(parsedURL);

        // step 3: optional hostname allowlist
        validateHostnameAllowlist(parsedURL.hostname, url, options.allowedHostnames);

        // step 4 & 5: resolve dns and validate ips
        let targetIP: CanonicalIP;

        if (parsedURL.isIPLiteral) {
            // it's an ip literal - canonicalize and validate directly
            const canonical = tryCanonicalizeIP(parsedURL.hostname);
            if (!canonical) {
                throw new RequestError(
                    `invalid ip address: ${parsedURL.hostname}`,
                    url,
                    'CONNECTION_REFUSED'
                );
            }
            validateIPRange(canonical, url);
            targetIP = canonical;
        } else {
            // it's a hostname - resolve and validate
            timing.dnsTime = Date.now();
            const dnsTimeout = getRemainingTimeout(deadlineAt, url, totalTimeout);
            const resolved = await resolveAndValidate(parsedURL.hostname, url, dnsTimeout);

            // select the best ip to connect to
            const selected = selectConnectionIP(resolved);
            if (!selected) {
                throw new RequestError(
                    `no valid ip addresses for ${parsedURL.hostname}`,
                    url,
                    'CONNECTION_REFUSED'
                );
            }
            targetIP = selected;
        }

        // step 6: create pinned agent
        const protocol = parsedURL.protocol === 'https:' ? 'https' : 'http';
        const { connectTimeout, responseTimeout } = getTimeouts(options);

        const remaining = getRemainingTimeout(deadlineAt, url, totalTimeout);
        const effectiveConnectTimeout = Math.max(1, Math.min(connectTimeout, remaining));
        const effectiveResponseTimeout = Math.max(1, Math.min(responseTimeout, remaining));

        const agent = createPinnedAgent(protocol, {
            targetIP,
            targetPort: parsedURL.port,
            originalHost: parsedURL.hostname,
            connectTimeout: effectiveConnectTimeout,
        });

        try {
            // step 7: execute request
            const response = await executeRequest(
                parsedURL,
                targetIP,
                agent,
                options,
                currentBody,
                currentMethod,
                effectiveResponseTimeout,
                deadlineAt
            );

            timing.connectTime = Date.now();
            timing.firstByteTime = Date.now();

            // step 8: handle redirects
            if (isRedirectStatus(response.status)) {
                if (!shouldFollowRedirects(options)) {
                    // return the redirect response as-is
                    timing.endTime = Date.now();
                    timing.totalMs = timing.endTime - timing.startTime;

                    return {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers,
                        body: response.body,
                        finalURL: reconstructURL(parsedURL),
                        redirectChain,
                        timing,
                        connectedIP: targetIP.canonical,
                    };
                }

                // validate redirect count
                const maxRedirects = getMaxRedirects(options);
                validateRedirectCount(redirectCount, maxRedirects, url);

                // parse and validate redirect location
                const locationHeader = extractLocationHeader(response.headers);
                const redirectURL = parseRedirectLocation(
                    locationHeader,
                    parsedURL,
                    url,
                    redirectCount
                );

                // update redirect semantics for next hop
                const preserveMethod = shouldPreserveMethod(response.status);
                const preserveBody = shouldPreserveBody(response.status);

                if (!preserveMethod) {
                    currentMethod = 'GET';
                }

                if (!preserveBody) {
                    currentBody = undefined;
                }

                // continue with redirect
                currentURL = reconstructURL(redirectURL);
                redirectCount++;

                // clean up agent
                destroyAgent(agent);

                continue;
            }

            // success - return response
            timing.endTime = Date.now();
            timing.totalMs = timing.endTime - timing.startTime;

            return {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body,
                finalURL: reconstructURL(parsedURL),
                redirectChain,
                timing,
                connectedIP: targetIP.canonical,
            };

        } finally {
            destroyAgent(agent);
        }
    }
}

// executes the actual http request
async function executeRequest(
    parsedURL: ParsedURL,
    targetIP: CanonicalIP,
    agent: http.Agent | https.Agent,
    options: SafeFetchOptions,
    body: Buffer | undefined,
    method: string | undefined,
    responseTimeout: number,
    deadlineAt: number
): Promise<{
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: Buffer;
}> {
    const protocol = parsedURL.protocol === 'https:' ? https : http;

    const headers = buildRequestHeaders(
        options.headers,
        parsedURL.hostname,
        options
    );

    // add content-length for body
    if (body) {
        headers['Content-Length'] = String(body.length);
    }

    const remaining = Math.max(1, deadlineAt - Date.now());
    const effectiveResponseTimeout = Math.max(1, Math.min(responseTimeout, remaining));

    const requestOptions: http.RequestOptions = {
        hostname: targetIP.canonical,
        port: parsedURL.port,
        path: parsedURL.pathname + parsedURL.search,
        method: method ?? DEFAULT_FETCH_OPTIONS.method,
        headers,
        agent,
        timeout: effectiveResponseTimeout,
    };

    return new Promise((resolve, reject) => {
        let settled = false;
        let timeoutHandle: NodeJS.Timeout | undefined;

        const settleReject = (error: RequestError): void => {
            if (settled) {
                return;
            }
            settled = true;
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
            }
            reject(error);
        };

        const settleResolve = (result: {
            status: number;
            statusText: string;
            headers: Record<string, string>;
            body: Buffer;
        }): void => {
            if (settled) {
                return;
            }
            settled = true;
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
            }
            resolve(result);
        };

        const req = protocol.request(requestOptions, (res) => {
            const { maxResponseSize, maxResponseHeadersSize } = getSizeLimits(options);
            const buffer = new SizeLimitedBuffer(maxResponseSize);

            const responseHeaderSize = getHeaderSizeBytes(res.rawHeaders);
            if (responseHeaderSize > maxResponseHeadersSize) {
                req.destroy();
                settleReject(new RequestError(
                    `response headers too large: ${responseHeaderSize} bytes exceeds ${maxResponseHeadersSize}`,
                    parsedURL.originalURL,
                    'HEADERS_TOO_LARGE'
                ));
                return;
            }

            res.on('data', (chunk: Buffer) => {
                try {
                    buffer.push(chunk);
                } catch {
                    req.destroy();
                    settleReject(new RequestError(
                        `response too large: exceeds ${maxResponseSize} bytes`,
                        parsedURL.originalURL,
                        'RESPONSE_TOO_LARGE'
                    ));
                }
            });

            res.on('end', () => {
                // convert headers to simple object
                const responseHeaders: Record<string, string> = {};
                for (const [key, value] of Object.entries(res.headers)) {
                    if (value !== undefined) {
                        responseHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
                    }
                }

                settleResolve({
                    status: res.statusCode ?? 0,
                    statusText: res.statusMessage ?? '',
                    headers: responseHeaders,
                    body: buffer.toBuffer(),
                });
            });

            res.on('error', (error) => {
                settleReject(new RequestError(
                    `response error: ${error.message}`,
                    parsedURL.originalURL,
                    'CONNECTION_RESET'
                ));
            });
        });

        timeoutHandle = setTimeout(() => {
            req.destroy();
            settleReject(new RequestError(
                `request timed out after ${effectiveResponseTimeout}ms`,
                parsedURL.originalURL,
                'RESPONSE_TIMEOUT'
            ));
        }, effectiveResponseTimeout);

        req.on('timeout', () => {
            req.destroy();
            settleReject(new RequestError(
                `request timed out after ${effectiveResponseTimeout}ms`,
                parsedURL.originalURL,
                'RESPONSE_TIMEOUT'
            ));
        });

        req.on('error', (error: NodeJS.ErrnoException) => {
            if (error.code === 'ECONNREFUSED') {
                settleReject(new RequestError(
                    `connection refused to ${targetIP.canonical}:${parsedURL.port}`,
                    parsedURL.originalURL,
                    'CONNECTION_REFUSED'
                ));
            } else if (error.code === 'ECONNRESET') {
                settleReject(new RequestError(
                    `connection reset by ${targetIP.canonical}`,
                    parsedURL.originalURL,
                    'CONNECTION_RESET'
                ));
            } else if (error.code === 'ETIMEDOUT') {
                settleReject(new RequestError(
                    `connection timed out to ${targetIP.canonical}`,
                    parsedURL.originalURL,
                    'CONNECT_TIMEOUT'
                ));
            } else {
                settleReject(new RequestError(
                    `request error: ${error.message}`,
                    parsedURL.originalURL,
                    'CONNECTION_RESET'
                ));
            }
        });

        // send body if present
        if (body) {
            req.write(body);
        }

        req.end();
    });
}
