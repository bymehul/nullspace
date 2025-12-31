/**
 * nullspace - ssrf prevention library
 * 
 * ip canonicalizer module
 * 
 * converts ip addresses from any format to canonical binary form.
 * this is the foundation of secure ip range checking.
 */

import { ValidationError } from '../utils/errors';
import {
    parseIPv4ToBinary,
    parseIPv6ToBinary,
    ipv4BytesToString,
    ipv6BytesToString,
    type CanonicalIP,
} from '../utils/ip-utils';

/**
 * canonicalizes an ip address from any format to binary.
 * handles all known encoding bypasses (decimal, hex, octal, short-form, ipv6 variants).
 */
export function canonicalizeIP(input: string): CanonicalIP {
    if (!input || typeof input !== 'string') {
        throw new ValidationError(
            'ip address cannot be empty',
            String(input),
            'INVALID_HOSTNAME'
        );
    }

    const trimmed = input.trim();

    // check if this looks like ipv6 (has colons or brackets)
    if (trimmed.includes(':') || trimmed.startsWith('[')) {
        return canonicalizeIPv6(trimmed);
    }

    // try ipv4
    return canonicalizeIPv4(trimmed);
}

// canonicalizes an ipv4 address
function canonicalizeIPv4(input: string): CanonicalIP {
    const bytes = parseIPv4ToBinary(input);

    if (!bytes) {
        throw new ValidationError(
            `invalid ipv4 address: ${input}`,
            input,
            'INVALID_HOSTNAME'
        );
    }

    return {
        version: 4,
        bytes,
        canonical: ipv4BytesToString(bytes),
    };
}

// canonicalizes an ipv6 address
function canonicalizeIPv6(input: string): CanonicalIP {
    const bytes = parseIPv6ToBinary(input);

    if (!bytes) {
        throw new ValidationError(
            `invalid ipv6 address: ${input}`,
            input,
            'INVALID_HOSTNAME'
        );
    }

    return {
        version: 6,
        bytes,
        canonical: ipv6BytesToString(bytes),
    };
}

/**
 * attempts to parse a hostname as an ip address.
 * returns null if the hostname is not an ip literal.
 */
export function tryCanonicalizeIP(hostname: string): CanonicalIP | null {
    if (!hostname) {
        return null;
    }

    const trimmed = hostname.trim();

    // ipv6 check
    if (trimmed.includes(':') || trimmed.startsWith('[')) {
        const bytes = parseIPv6ToBinary(trimmed);
        if (bytes) {
            return {
                version: 6,
                bytes,
                canonical: ipv6BytesToString(bytes),
            };
        }
        return null;
    }

    // ipv4 check - be more strict here since we're guessing
    if (/^[0-9a-fA-Fx.]+$/.test(trimmed)) {
        const bytes = parseIPv4ToBinary(trimmed);
        if (bytes) {
            return {
                version: 4,
                bytes,
                canonical: ipv4BytesToString(bytes),
            };
        }
    }

    return null;
}

/**
 * checks if a hostname string is definitely an ip address (not a domain).
 */
export function isIPAddress(hostname: string): boolean {
    return tryCanonicalizeIP(hostname) !== null;
}

/**
 * compares two ip addresses for equality.
 * both must be in canonical form.
 */
export function ipEquals(a: CanonicalIP, b: CanonicalIP): boolean {
    if (a.version !== b.version) {
        return false;
    }

    if (a.bytes.length !== b.bytes.length) {
        return false;
    }

    for (let i = 0; i < a.bytes.length; i++) {
        if (a.bytes[i] !== b.bytes[i]) {
            return false;
        }
    }

    return true;
}
