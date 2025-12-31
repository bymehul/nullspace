/**
 * nullspace - ssrf prevention library
 * 
 * redirect handler module
 * 
 * safely handles http redirects by re-validating each hop.
 * enforces protocol safety and redirect limits.
 */

import { RedirectError } from '../utils/errors';
import { parseURL } from '../core/url-parser';
import { validateProtocol } from '../core/protocol-validator';
import type { ParsedURL, SafeFetchOptions } from '../types';
import { DEFAULT_FETCH_OPTIONS } from '../types';

// http status codes that indicate a redirect
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * checks if a status code is a redirect.
 */
export function isRedirectStatus(status: number): boolean {
    return REDIRECT_STATUS_CODES.has(status);
}

/**
 * determines if redirects should be followed based on options.
 */
export function shouldFollowRedirects(options: SafeFetchOptions): boolean {
    return options.followRedirects ?? DEFAULT_FETCH_OPTIONS.followRedirects;
}

/**
 * gets the maximum number of redirects allowed.
 */
export function getMaxRedirects(options: SafeFetchOptions): number {
    return options.maxRedirects ?? DEFAULT_FETCH_OPTIONS.maxRedirects;
}

/**
 * validates and parses a redirect location header.
 */
export function parseRedirectLocation(
    locationHeader: string | undefined,
    currentURL: ParsedURL,
    originalInput: string,
    redirectCount: number
): ParsedURL {
    if (!locationHeader) {
        throw new RedirectError(
            'redirect response missing location header',
            originalInput,
            '',
            'INVALID_LOCATION',
            redirectCount
        );
    }

    // trim whitespace
    const location = locationHeader.trim();

    if (location.length === 0) {
        throw new RedirectError(
            'redirect location header is empty',
            originalInput,
            '',
            'INVALID_LOCATION',
            redirectCount
        );
    }

    // resolve relative urls against current url
    let absoluteURL: string;

    try {
        if (location.startsWith('//')) {
            // protocol-relative url
            absoluteURL = `${currentURL.protocol}${location}`;
        } else if (location.startsWith('/')) {
            // absolute path
            const port = (currentURL.protocol === 'http:' && currentURL.port === 80) ||
                (currentURL.protocol === 'https:' && currentURL.port === 443)
                ? ''
                : `:${currentURL.port}`;
            absoluteURL = `${currentURL.protocol}//${currentURL.hostname}${port}${location}`;
        } else if (location.startsWith('http://') || location.startsWith('https://')) {
            // absolute url
            absoluteURL = location;
        } else {
            // relative path - resolve against current url
            const currentPath = currentURL.pathname;
            const basePath = currentPath.substring(0, currentPath.lastIndexOf('/') + 1);
            const port = (currentURL.protocol === 'http:' && currentURL.port === 80) ||
                (currentURL.protocol === 'https:' && currentURL.port === 443)
                ? ''
                : `:${currentURL.port}`;
            absoluteURL = `${currentURL.protocol}//${currentURL.hostname}${port}${basePath}${location}`;
        }
    } catch {
        throw new RedirectError(
            `failed to resolve redirect url: ${location}`,
            originalInput,
            location,
            'INVALID_LOCATION',
            redirectCount
        );
    }

    // parse the redirect url
    let parsedRedirect: ParsedURL;
    try {
        parsedRedirect = parseURL(absoluteURL);
    } catch (error) {
        throw new RedirectError(
            `invalid redirect url: ${location}`,
            originalInput,
            location,
            'INVALID_LOCATION',
            redirectCount
        );
    }

    // validate protocol
    try {
        validateProtocol(parsedRedirect);
    } catch {
        throw new RedirectError(
            `redirect to forbidden protocol: ${parsedRedirect.protocol}`,
            originalInput,
            location,
            'CROSS_PROTOCOL',
            redirectCount
        );
    }

    // check for protocol downgrade (https -> http)
    if (currentURL.protocol === 'https:' && parsedRedirect.protocol === 'http:') {
        throw new RedirectError(
            'protocol downgrade from https to http is not allowed',
            originalInput,
            location,
            'PROTOCOL_DOWNGRADE',
            redirectCount
        );
    }

    return parsedRedirect;
}

/**
 * validates that redirect count hasn't exceeded the limit.
 */
export function validateRedirectCount(
    currentCount: number,
    maxRedirects: number,
    originalInput: string
): void {
    if (currentCount >= maxRedirects) {
        throw new RedirectError(
            `maximum redirect count (${maxRedirects}) exceeded`,
            originalInput,
            '',
            'MAX_REDIRECTS_EXCEEDED',
            currentCount
        );
    }
}

/**
 * extracts the location header from response headers.
 * handles case-insensitive header names.
 */
export function extractLocationHeader(
    headers: Record<string, string | string[] | undefined>
): string | undefined {
    // http headers are case-insensitive
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === 'location') {
            // handle array of headers (multiple location headers)
            if (Array.isArray(value)) {
                return value[0];
            }
            return value;
        }
    }
    return undefined;
}

/**
 * determines if the redirect should preserve the request method.
 * 
 * 301, 302: historically changed post to get (though 302 shouldn't)
 * 303: always changes to get
 * 307, 308: must preserve original method
 */
export function shouldPreserveMethod(status: number): boolean {
    return status === 307 || status === 308;
}

/**
 * determines if the redirect should include the request body.
 * body should only be preserved for 307 and 308 redirects.
 */
export function shouldPreserveBody(status: number): boolean {
    return status === 307 || status === 308;
}
