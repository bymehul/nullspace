/**
 * nullspace - ssrf prevention library
 * 
 * url parser module
 * 
 * strict url parsing using whatwg url standard.
 * handles normalization, encoding, and ambiguity detection.
 */

import { ValidationError } from '../utils/errors';
import type { ParsedURL } from '../types';

// forbidden characters in hostnames (null bytes, whitespace, etc)
const FORBIDDEN_HOST_CHARS = /[\x00-\x1f\x7f\s#%/<>?@[\\\]^|]/;

/**
 * parses and normalizes a url with strict security validation.
 */
export function parseURL(input: string): ParsedURL {
    // reject null input
    if (input === null || input === undefined) {
        throw new ValidationError(
            'url cannot be null or undefined',
            String(input),
            'MALFORMED_URL'
        );
    }

    // coerce to string and trim
    const urlString = String(input).trim();

    if (urlString.length === 0) {
        throw new ValidationError(
            'url cannot be empty',
            input,
            'MALFORMED_URL'
        );
    }

    // check for null bytes before any parsing
    // handles \0, %00, and double-encoded %2500
    if (urlString.includes('\x00') || urlString.includes('%00') || urlString.toLowerCase().includes('%2500')) {
        throw new ValidationError(
            'url contains null byte',
            input,
            'NULL_BYTE_DETECTED'
        );
    }

    // use whatwg url parser
    let url: URL;
    try {
        url = new URL(urlString);
    } catch {
        throw new ValidationError(
            'invalid url format',
            input,
            'MALFORMED_URL'
        );
    }

    // extract and validate protocol
    const protocol = url.protocol.toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
        throw new ValidationError(
            `invalid protocol: ${protocol}`,
            input,
            'INVALID_PROTOCOL'
        );
    }

    // validate hostname
    // whatwg url parser keeps brackets for ipv6, we strip them
    let hostname = url.hostname.toLowerCase();

    // strip brackets from ipv6 addresses
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
    }

    if (hostname.length === 0) {
        throw new ValidationError(
            'hostname cannot be empty',
            input,
            'INVALID_HOSTNAME'
        );
    }

    // check for dangerous patterns in hostname
    // ipv6 addresses contain colons, which is valid
    const forbiddenForIPv6 = /[\x00-\x1f\x7f\s#%/<>?@\[\\\]^|]/;
    const forbiddenForHostname = /[\x00-\x1f\x7f\s#%/<>?@\[\\\]^|:]/;

    // if hostname contains colons, it's ipv6 - use ipv6 rules
    const forbiddenPattern = hostname.includes(':') ? forbiddenForIPv6 : forbiddenForHostname;

    if (forbiddenPattern.test(hostname)) {
        throw new ValidationError(
            'hostname contains forbidden characters',
            input,
            'INVALID_HOSTNAME'
        );
    }

    // check for ambiguous userinfo (user:pass@host patterns)
    // catch patterns like "http://google.com@evil.com" or "http://user:pass@google.com@evil.com"
    if (url.username || url.password || urlString.split('@').length > 2) {
        const atCount = urlString.split('@').length - 1;
        if (atCount > 1) {
            throw new ValidationError(
                'ambiguous url with multiple @ symbols',
                input,
                'AMBIGUOUS_USERINFO'
            );
        }
    }

    // detect whitespace that might have been normalized
    if (/[\t\n\r]/.test(urlString)) {
        throw new ValidationError(
            'url contains whitespace characters',
            input,
            'WHITESPACE_IN_HOST'
        );
    }

    // determine port
    let port: number;
    if (url.port) {
        port = parseInt(url.port, 10);
        if (isNaN(port) || port < 1 || port > 65535) {
            throw new ValidationError(
                `invalid port number: ${url.port}`,
                input,
                'INVALID_PORT'
            );
        }
    } else {
        // default ports
        port = protocol === 'https:' ? 443 : 80;
    }

    // check if hostname is an ip literal
    const isIPLiteral = isIPAddress(hostname);

    return {
        protocol: protocol as 'http:' | 'https:',
        hostname,
        port,
        pathname: url.pathname || '/',
        search: url.search || '',
        hash: url.hash || '',
        originalURL: input,
        isIPLiteral,
    };
}

/**
 * checks if a hostname string is an ip address (v4 or v6).
 */
function isIPAddress(hostname: string): boolean {
    // ipv6 literal (with or without brackets)
    if (hostname.startsWith('[') || hostname.includes(':')) {
        return true;
    }

    // ipv4 - check if all parts are numbers
    const parts = hostname.split('.');
    if (parts.length >= 1 && parts.length <= 4) {
        const allNumeric = parts.every(p => /^(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*|0)$/.test(p));
        if (allNumeric) {
            return true;
        }
    }

    return false;
}

/**
 * reconstructs a url string from parsed components.
 * uses only validated/normalized values.
 */
export function reconstructURL(parsed: ParsedURL): string {
    let url = `${parsed.protocol}//`;

    // add hostname (with brackets for ipv6)
    if (parsed.hostname.includes(':')) {
        url += `[${parsed.hostname}]`;
    } else {
        url += parsed.hostname;
    }

    // add port only if non-default
    const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
    if (parsed.port !== defaultPort) {
        url += `:${parsed.port}`;
    }

    // add path (ensure it starts with /)
    url += parsed.pathname.startsWith('/') ? parsed.pathname : `/${parsed.pathname}`;

    // add query string
    url += parsed.search;

    // note: hash is intentionally not included for network requests

    return url;
}

/**
 * normalizes a url for safe comparison.
 * removes default ports, lowercases hostname, etc.
 */
export function normalizeForComparison(parsed: ParsedURL): string {
    return reconstructURL(parsed).toLowerCase();
}
