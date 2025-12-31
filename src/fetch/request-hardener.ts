/**
 * nullspace - ssrf prevention library
 * 
 * request hardener module
 * 
 * applies security hardening to outbound requests:
 * - strips sensitive headers
 * - enforces size limits
 * - applies timeouts
 */

import type { SafeFetchOptions } from '../types';
import { SENSITIVE_HEADERS, DEFAULT_FETCH_OPTIONS } from '../types';

/**
 * sanitizes headers by removing sensitive ones.
 */
export function sanitizeHeaders(
    headers: Record<string, string> | undefined,
    options: SafeFetchOptions
): Record<string, string> {
    const result: Record<string, string> = {};

    if (!headers) {
        return result;
    }

    const shouldStrip = options.stripSensitiveHeaders ?? DEFAULT_FETCH_OPTIONS.stripSensitiveHeaders;

    for (const [key, value] of Object.entries(headers)) {
        const lowerKey = key.toLowerCase();

        if (shouldStrip && isSensitiveHeader(lowerKey)) {
            // skip sensitive headers
            continue;
        }

        result[key] = value;
    }

    return result;
}

// checks if a header is in the sensitive list
function isSensitiveHeader(headerName: string): boolean {
    const lower = headerName.toLowerCase();

    // check exact matches
    if ((SENSITIVE_HEADERS as readonly string[]).includes(lower)) {
        return true;
    }

    // also block any custom x- headers that look auth-related
    if (lower.startsWith('x-') && (
        lower.includes('auth') ||
        lower.includes('token') ||
        lower.includes('key') ||
        lower.includes('secret') ||
        lower.includes('credential') ||
        lower.includes('session') ||
        lower.includes('api-key')
    )) {
        return true;
    }

    return false;
}

/**
 * builds the final request headers with hardening applied.
 */
export function buildRequestHeaders(
    userHeaders: Record<string, string> | undefined,
    hostname: string,
    options: SafeFetchOptions
): Record<string, string> {
    // start with sanitized user headers
    const headers = sanitizeHeaders(userHeaders, options);

    // set host header (required for http/1.1)
    headers['Host'] = hostname;

    // set user-agent
    headers['User-Agent'] = options.userAgent ?? DEFAULT_FETCH_OPTIONS.userAgent;

    // disable compression to simplify size limiting
    headers['Accept-Encoding'] = 'identity';

    // set accept header if not already set
    if (!headers['Accept']) {
        headers['Accept'] = '*/*';
    }

    // set connection header to close to prevent keep-alive
    headers['Connection'] = 'close';

    return headers;
}

/**
 * creates an abort controller with timeout.
 */
export function createTimeoutAbort(timeoutMs: number): {
    controller: AbortController;
    timeout: NodeJS.Timeout;
    cleanup: () => void;
} {
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, timeoutMs);

    return {
        controller,
        timeout,
        cleanup: () => clearTimeout(timeout),
    };
}

/**
 * response size tracker that aborts if size limit is exceeded.
 */
export class SizeLimitedBuffer {
    private chunks: Buffer[] = [];
    private currentSize = 0;
    private readonly maxSize: number;

    constructor(maxSize: number) {
        this.maxSize = maxSize;
    }

    /**
     * adds a chunk to the buffer.
     * throws if size limit is exceeded.
     */
    push(chunk: Buffer): void {
        const newSize = this.currentSize + chunk.length;

        if (newSize > this.maxSize) {
            throw new Error(
                `response size ${newSize} exceeds limit of ${this.maxSize} bytes`
            );
        }

        this.chunks.push(chunk);
        this.currentSize = newSize;
    }

    // returns the current accumulated size
    get size(): number {
        return this.currentSize;
    }

    // concatenates all chunks into a single buffer
    toBuffer(): Buffer {
        return Buffer.concat(this.chunks, this.currentSize);
    }
}

/**
 * validates request body size if provided.
 */
export function validateRequestBody(
    body: string | Buffer | undefined,
    maxSize: number
): Buffer | undefined {
    if (!body) {
        return undefined;
    }

    const buffer = typeof body === 'string' ? Buffer.from(body) : body;

    if (buffer.length > maxSize) {
        throw new Error(
            `request body size ${buffer.length} exceeds limit of ${maxSize} bytes`
        );
    }

    return buffer;
}

/**
 * gets the effective timeout values from options.
 */
export function getTimeouts(options: SafeFetchOptions): {
    connectTimeout: number;
    responseTimeout: number;
} {
    return {
        connectTimeout: options.connectTimeout ?? DEFAULT_FETCH_OPTIONS.connectTimeout,
        responseTimeout: options.responseTimeout ?? DEFAULT_FETCH_OPTIONS.responseTimeout,
    };
}

/**
 * gets the effective size limits from options.
 */
export function getSizeLimits(options: SafeFetchOptions): {
    maxResponseSize: number;
} {
    return {
        maxResponseSize: options.maxResponseSize ?? DEFAULT_FETCH_OPTIONS.maxResponseSize,
    };
}
