/**
 * nullspace - ssrf prevention library
 * 
 * protocol validator module
 * 
 * enforces strict protocol allow-listing.
 * only http:// and https:// are ever permitted.
 */

import { ProtocolError } from '../utils/errors';
import type { ParsedURL } from '../types';

// the only protocols ever allowed - this is a fundamental security invariant
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// protocols commonly used in ssrf attacks (for documentation and error messages)
const DANGEROUS_PROTOCOLS = new Map<string, string>([
    ['file:', 'local file access'],
    ['gopher:', 'raw tcp/protocol smuggling'],
    ['dict:', 'dictionary service (often memcache/redis)'],
    ['ftp:', 'ftp file access'],
    ['sftp:', 'sftp file access'],
    ['tftp:', 'tftp file access'],
    ['ldap:', 'ldap directory access'],
    ['ldaps:', 'ldaps directory access'],
    ['jar:', 'java archive access'],
    ['netdoc:', 'java network document'],
    ['data:', 'inline data uri'],
    ['javascript:', 'javascript execution'],
    ['vbscript:', 'vbscript execution'],
    ['mailto:', 'email protocol'],
    ['telnet:', 'telnet access'],
    ['ssh:', 'ssh access'],
    ['expect:', 'expect protocol'],
    ['php:', 'php stream wrapper'],
    ['phar:', 'php archive'],
    ['glob:', 'glob pattern'],
    ['zip:', 'zip file access'],
    ['rar:', 'rar file access'],
    ['ogg:', 'ogg stream'],
]);

/**
 * validates that a parsed url uses an allowed protocol.
 */
export function validateProtocol(parsedURL: ParsedURL): void {
    const protocol = parsedURL.protocol.toLowerCase();

    if (!ALLOWED_PROTOCOLS.has(protocol)) {
        const dangerReason = DANGEROUS_PROTOCOLS.get(protocol);
        const message = dangerReason
            ? `protocol '${protocol}' is blocked: ${dangerReason}`
            : `protocol '${protocol}' is not allowed`;

        throw new ProtocolError(
            message,
            parsedURL.originalURL,
            protocol
        );
    }
}

/**
 * checks if a protocol is allowed without throwing.
 * useful for pre-validation checks.
 */
export function isProtocolAllowed(protocol: string): boolean {
    const normalized = protocol.toLowerCase().endsWith(':')
        ? protocol.toLowerCase()
        : `${protocol.toLowerCase()}:`;

    return ALLOWED_PROTOCOLS.has(normalized);
}

/**
 * returns the set of allowed protocols.
 * for informational/documentation purposes only.
 */
export function getAllowedProtocols(): ReadonlySet<string> {
    return ALLOWED_PROTOCOLS;
}

/**
 * returns information about why a protocol is dangerous.
 * for error messages and logging.
 */
export function getProtocolDangerReason(protocol: string): string | undefined {
    const normalized = protocol.toLowerCase().endsWith(':')
        ? protocol.toLowerCase()
        : `${protocol.toLowerCase()}:`;

    return DANGEROUS_PROTOCOLS.get(normalized);
}
