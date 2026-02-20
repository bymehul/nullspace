/**
 * nullspace - ssrf prevention library
 * 
 * the internal network must exist in a nullspace with respect to user-controlled input:
 * reachable in theory, unreachable in practice.
 */

// core validation functions
export { parseURL, reconstructURL, normalizeForComparison } from './core/url-parser';
export { validateProtocol, isProtocolAllowed, getAllowedProtocols } from './core/protocol-validator';
export { canonicalizeIP, tryCanonicalizeIP, isIPAddress, ipEquals } from './core/ip-canonicalizer';
export { isHostnameAllowed, validateHostnameAllowlist } from './core/hostname-policy';
export {
    checkIPRange,
    validateIPRange,
    getBlockedRanges,
    addBlockedRanges,
    setAdditionalBlockedRanges,
} from './core/range-classifier';
export {
    resolveHost,
    resolveAndValidate,
    selectConnectionIP,
    configureDNSResolver,
    clearDNSCache,
} from './core/dns-resolver';

// safe fetch
export { safeFetch } from './fetch/safe-fetch';

// types
export type {
    ParsedURL,
    ResolvedHost,
    RangeCheckResult,
    ValidationResult,
    ValidateURLOptions,
    SafeFetchOptions,
    SafeFetchResult,
    RequestTiming,
    NullspaceConfig,
    ValidatedRequest,
    CanonicalIP,
    CIDRRange,
} from './types';

export { SENSITIVE_HEADERS, DEFAULT_FETCH_OPTIONS } from './types';

// errors
export {
    NullspaceError,
    ValidationError,
    DNSError,
    RangeError,
    ProtocolError,
    RedirectError,
    RequestError,
    isSSRFError,
} from './utils/errors';

export type {
    SSRFError,
    ValidationFailureReason,
    DNSFailureReason,
    RedirectFailureReason,
    RequestFailureReason,
} from './utils/errors';

// convenience functions

import { parseURL } from './core/url-parser';
import { validateProtocol } from './core/protocol-validator';
import { tryCanonicalizeIP } from './core/ip-canonicalizer';
import { checkIPRange, validateIPRange } from './core/range-classifier';
import { validateHostnameAllowlist } from './core/hostname-policy';
import { resolveAndValidate, selectConnectionIP } from './core/dns-resolver';
import type { ValidationResult, CanonicalIP, ValidateURLOptions } from './types';
import { isSSRFError } from './utils/errors';

/**
 * validates a url without making a request.
 * performs full validation pipeline including dns resolution.
 */
export async function validateURL(
    url: string,
    options: ValidateURLOptions = {}
): Promise<ValidationResult> {
    try {
        // step 1: parse url
        const parsedURL = parseURL(url);

        // step 2: validate protocol
        validateProtocol(parsedURL);

        // step 3: optional hostname allowlist
        validateHostnameAllowlist(parsedURL.hostname, url, options.allowedHostnames);

        // step 4: resolve and validate ip
        let resolvedIPs: CanonicalIP[] = [];

        if (parsedURL.isIPLiteral) {
            const canonical = tryCanonicalizeIP(parsedURL.hostname);
            if (!canonical) {
                return {
                    valid: false,
                    error: `invalid ip address: ${parsedURL.hostname}`,
                    errorCode: 'INVALID_IP',
                };
            }
            validateIPRange(canonical, url);
            resolvedIPs = [canonical];
        } else {
            const resolved = await resolveAndValidate(parsedURL.hostname, url, options.dnsTimeout);
            resolvedIPs = [...resolved.ipv4Addresses, ...resolved.ipv6Addresses];
        }

        return {
            valid: true,
            parsedURL,
            resolvedIPs,
        };
    } catch (error) {
        if (isSSRFError(error)) {
            return {
                valid: false,
                error: error.message,
                errorCode: error.code,
            };
        }
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'unknown error',
            errorCode: 'UNKNOWN',
        };
    }
}

/**
 * resolves a hostname and checks if all ips are in allowed ranges.
 * does not make any network requests beyond dns.
 */
export async function resolveAndCheck(hostname: string): Promise<{
    safe: boolean;
    ips: CanonicalIP[];
    blockedReason?: string;
}> {
    try {
        const resolved = await resolveAndValidate(hostname, hostname);
        return {
            safe: true,
            ips: [...resolved.ipv4Addresses, ...resolved.ipv6Addresses],
        };
    } catch (error) {
        if (isSSRFError(error)) {
            return {
                safe: false,
                ips: [],
                blockedReason: error.message,
            };
        }
        return {
            safe: false,
            ips: [],
            blockedReason: error instanceof Error ? error.message : 'unknown error',
        };
    }
}

/**
 * checks if an ip address string is allowed (not in any blocked range).
 */
export function isIPAllowed(ip: string): boolean {
    const canonical = tryCanonicalizeIP(ip);
    if (!canonical) {
        return false; // invalid ip format
    }

    const result = checkIPRange(canonical);
    return result.allowed;
}
