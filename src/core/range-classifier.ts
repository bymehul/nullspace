/**
 * nullspace - ssrf prevention library
 * 
 * range classifier module
 * 
 * determines if an ip address falls within any blocked range.
 * based on rfc specifications for private, loopback, link-local, and reserved addresses.
 */

import { RangeError as SSRFRangeError } from '../utils/errors';
import {
    type CanonicalIP,
    type CIDRRange,
    parseCIDR,
    ipMatchesCIDR,
    extractMappedIPv4,
    extractNAT64IPv4,
} from '../utils/ip-utils';
import type { RangeCheckResult } from '../types';

// all blocked ipv4 cidr ranges with rfc references
const BLOCKED_IPV4_RANGES: CIDRRange[] = [
    // rfc 1122 - "this host on this network"
    parseCIDR('0.0.0.0/8', 'rfc 1122 - this host')!,

    // rfc 1918 - private networks
    parseCIDR('10.0.0.0/8', 'rfc 1918 - private (class a)')!,
    parseCIDR('172.16.0.0/12', 'rfc 1918 - private (class b)')!,
    parseCIDR('192.168.0.0/16', 'rfc 1918 - private (class c)')!,

    // rfc 6598 - carrier-grade nat
    parseCIDR('100.64.0.0/10', 'rfc 6598 - carrier-grade nat')!,

    // rfc 1122 - loopback
    parseCIDR('127.0.0.0/8', 'rfc 1122 - loopback')!,

    // rfc 3927 - link-local (includes cloud metadata 169.254.169.254)
    parseCIDR('169.254.0.0/16', 'rfc 3927 - link-local / cloud metadata')!,

    // rfc 6890 - ietf protocol assignments
    parseCIDR('192.0.0.0/24', 'rfc 6890 - ietf protocol assignments')!,

    // rfc 5737 - documentation (test-net-1)
    parseCIDR('192.0.2.0/24', 'rfc 5737 - documentation (test-net-1)')!,

    // rfc 7526 - 6to4 relay anycast (deprecated)
    parseCIDR('192.88.99.0/24', 'rfc 7526 - 6to4 relay anycast')!,

    // rfc 2544 - benchmarking
    parseCIDR('198.18.0.0/15', 'rfc 2544 - benchmarking')!,

    // rfc 5737 - documentation (test-net-2)
    parseCIDR('198.51.100.0/24', 'rfc 5737 - documentation (test-net-2)')!,

    // rfc 5737 - documentation (test-net-3)
    parseCIDR('203.0.113.0/24', 'rfc 5737 - documentation (test-net-3)')!,

    // rfc 5771 - multicast
    parseCIDR('224.0.0.0/4', 'rfc 5771 - multicast')!,

    // rfc 1112 - reserved for future use
    parseCIDR('240.0.0.0/4', 'rfc 1112 - reserved')!,

    // rfc 919 - limited broadcast
    parseCIDR('255.255.255.255/32', 'rfc 919 - broadcast')!,
];

// all blocked ipv6 cidr ranges with rfc references
const BLOCKED_IPV6_RANGES: CIDRRange[] = [
    // rfc 4291 - unspecified address
    parseCIDR('::/128', 'rfc 4291 - unspecified')!,

    // rfc 4291 - loopback
    parseCIDR('::1/128', 'rfc 4291 - loopback')!,

    // rfc 4291 - ipv4-mapped ipv6 (checked separately for embedded ipv4)
    parseCIDR('::ffff:0:0/96', 'rfc 4291 - ipv4-mapped (requires embedded check)')!,

    // rfc 6052 - nat64 (checked separately for embedded ipv4)
    parseCIDR('64:ff9b::/96', 'rfc 6052 - nat64 (requires embedded check)')!,

    // rfc 6666 - discard-only
    parseCIDR('100::/64', 'rfc 6666 - discard-only')!,

    // rfc 3849 - documentation
    parseCIDR('2001:db8::/32', 'rfc 3849 - documentation')!,

    // rfc 4193 - unique local addresses (private)
    parseCIDR('fc00::/7', 'rfc 4193 - unique local (private)')!,

    // rfc 4291 - link-local
    parseCIDR('fe80::/10', 'rfc 4291 - link-local')!,

    // rfc 4291 - multicast
    parseCIDR('ff00::/8', 'rfc 4291 - multicast')!,
];

/**
 * checks if an ip address is in any blocked range.
 */
export function checkIPRange(ip: CanonicalIP): RangeCheckResult {
    if (ip.version === 4) {
        return checkIPv4Range(ip);
    } else {
        return checkIPv6Range(ip);
    }
}

// checks an ipv4 address against blocked ranges
function checkIPv4Range(ip: CanonicalIP): RangeCheckResult {
    for (const range of BLOCKED_IPV4_RANGES) {
        if (ipMatchesCIDR(ip.bytes, range)) {
            return {
                allowed: false,
                blockedRange: range,
                ip,
            };
        }
    }

    return {
        allowed: true,
        ip,
    };
}

// checks an ipv6 address against blocked ranges
// also checks embedded ipv4 addresses in mapped/nat64 formats
function checkIPv6Range(ip: CanonicalIP): RangeCheckResult {
    // first check pure ipv6 ranges
    for (const range of BLOCKED_IPV6_RANGES) {
        if (ipMatchesCIDR(ip.bytes, range)) {
            // special handling for ipv4-mapped and nat64 - check embedded ipv4
            if (range.description.includes('ipv4-mapped')) {
                const embeddedIPv4 = extractMappedIPv4(ip.bytes);
                if (embeddedIPv4) {
                    // check the embedded ipv4 against ipv4 ranges
                    const embeddedResult = checkIPv4Range({
                        version: 4,
                        bytes: embeddedIPv4,
                        canonical: `${embeddedIPv4[0]}.${embeddedIPv4[1]}.${embeddedIPv4[2]}.${embeddedIPv4[3]}`,
                    });

                    if (!embeddedResult.allowed) {
                        return {
                            allowed: false,
                            blockedRange: embeddedResult.blockedRange,
                            ip,
                        };
                    }
                    // embedded ipv4 is allowed, continue checking other ipv6 ranges
                    continue;
                }
            }

            if (range.description.includes('nat64')) {
                const embeddedIPv4 = extractNAT64IPv4(ip.bytes);
                if (embeddedIPv4) {
                    // check the embedded ipv4 against ipv4 ranges
                    const embeddedResult = checkIPv4Range({
                        version: 4,
                        bytes: embeddedIPv4,
                        canonical: `${embeddedIPv4[0]}.${embeddedIPv4[1]}.${embeddedIPv4[2]}.${embeddedIPv4[3]}`,
                    });

                    if (!embeddedResult.allowed) {
                        return {
                            allowed: false,
                            blockedRange: embeddedResult.blockedRange,
                            ip,
                        };
                    }
                    // embedded ipv4 is allowed, continue checking other ipv6 ranges
                    continue;
                }
            }

            return {
                allowed: false,
                blockedRange: range,
                ip,
            };
        }
    }

    return {
        allowed: true,
        ip,
    };
}

/**
 * validates an ip address and throws if it's in a blocked range.
 */
export function validateIPRange(ip: CanonicalIP, originalInput: string): void {
    const result = checkIPRange(ip);

    if (!result.allowed && result.blockedRange) {
        throw new SSRFRangeError(
            `ip address ${ip.canonical} is in blocked range: ${result.blockedRange.description}`,
            originalInput,
            ip.canonical,
            result.blockedRange.description,
            ip.version
        );
    }
}

/**
 * returns all blocked ranges for documentation/debugging.
 */
export function getBlockedRanges(): { ipv4: readonly CIDRRange[]; ipv6: readonly CIDRRange[] } {
    return {
        ipv4: BLOCKED_IPV4_RANGES,
        ipv6: BLOCKED_IPV6_RANGES,
    };
}

/**
 * adds additional blocked ranges (for advanced configuration only).
 * note: this modifies the global state and should only be called at startup.
 */
export function addBlockedRanges(ranges: Array<{ cidr: string; description: string }>): void {
    for (const { cidr, description } of ranges) {
        const parsed = parseCIDR(cidr, description);
        if (parsed) {
            if (parsed.version === 4) {
                BLOCKED_IPV4_RANGES.push(parsed);
            } else {
                BLOCKED_IPV6_RANGES.push(parsed);
            }
        }
    }
}
