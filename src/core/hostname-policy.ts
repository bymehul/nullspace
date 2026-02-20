/**
 * nullspace - ssrf prevention library
 *
 * hostname allowlist policy module
 *
 * optional strict outbound policy for high-risk deployments.
 */

import { ValidationError } from '../utils/errors';

function normalizeHostname(value: string): string {
    return value.trim().toLowerCase().replace(/\.+$/, '');
}

/**
 * checks whether a hostname is permitted by an allowlist.
 * supports exact host and subdomain matching.
 */
export function isHostnameAllowed(hostname: string, allowedHostnames: string[]): boolean {
    const normalizedHost = normalizeHostname(hostname);

    for (const candidate of allowedHostnames) {
        const normalizedCandidate = normalizeHostname(candidate);
        if (!normalizedCandidate) {
            continue;
        }

        if (
            normalizedHost === normalizedCandidate ||
            normalizedHost.endsWith(`.${normalizedCandidate}`)
        ) {
            return true;
        }
    }

    return false;
}

/**
 * validates hostname against optional allowlist and throws on mismatch.
 */
export function validateHostnameAllowlist(
    hostname: string,
    originalInput: string,
    allowedHostnames?: string[]
): void {
    if (!allowedHostnames || allowedHostnames.length === 0) {
        return;
    }

    const normalized = allowedHostnames
        .map(normalizeHostname)
        .filter((entry) => entry.length > 0);

    if (normalized.length === 0) {
        return;
    }

    if (!isHostnameAllowed(hostname, normalized)) {
        throw new ValidationError(
            `hostname '${hostname}' is not in the allowed hostnames policy`,
            originalInput,
            'HOST_NOT_ALLOWED'
        );
    }
}
