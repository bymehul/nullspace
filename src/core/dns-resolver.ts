/**
 * nullspace - ssrf prevention library
 * 
 * dns resolver module
 * 
 * controlled dns resolution with anti-rebinding measures.
 * dns resolution is the single source of truth for hostname → ip mapping.
 */

import * as dns from 'dns';
import { promisify } from 'util';
import { DNSError } from '../utils/errors';
import { canonicalizeIP } from './ip-canonicalizer';
import { checkIPRange, validateIPRange } from './range-classifier';
import type { ResolvedHost, CanonicalIP, NullspaceConfig } from '../types';

// promisified dns functions
const resolve4Async = promisify(dns.resolve4);
const resolve6Async = promisify(dns.resolve6);

// dns cache entry with enforced minimum ttl
interface DNSCacheEntry {
    result: ResolvedHost;
    expiresAt: number;
}

// in-memory dns cache with minimum ttl floor to prevent rebinding
const dnsCache = new Map<string, DNSCacheEntry>();

// minimum ttl for dns cache entries (60 seconds)
// this is a security control to prevent rapid dns rebinding attacks
const MIN_DNS_TTL_MS = 60_000;

// maximum dns resolution timeout (5 seconds)
const DNS_TIMEOUT_MS = 5_000;

// configuration for the dns resolver
let resolverConfig: NullspaceConfig = {};

/**
 * configures the dns resolver.
 * warning: custom resolvers can bypass security protections.
 */
export function configureDNSResolver(config: NullspaceConfig): void {
    // enforce minimum ttl floor
    if (config.dnsCacheTTLFloor !== undefined && config.dnsCacheTTLFloor < MIN_DNS_TTL_MS) {
        throw new Error(`dns cache ttl floor cannot be less than ${MIN_DNS_TTL_MS}ms`);
    }
    resolverConfig = config;
}

/**
 * resolves a hostname to ip addresses with validation.
 */
export async function resolveHost(
    hostname: string,
    originalInput: string
): Promise<ResolvedHost> {
    // check cache first
    const cached = dnsCache.get(hostname);
    if (cached && cached.expiresAt > Date.now()) {
        return cached.result;
    }

    // resolve with timeout
    const resolvePromise = performResolution(hostname, originalInput);
    const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(
            () => reject(new DNSError(
                `dns resolution timed out after ${DNS_TIMEOUT_MS}ms`,
                originalInput,
                hostname,
                'RESOLUTION_TIMEOUT'
            )),
            DNS_TIMEOUT_MS
        );
    });

    const result = await Promise.race([resolvePromise, timeoutPromise]);

    // cache the result
    const ttl = resolverConfig.dnsCacheTTLFloor ?? MIN_DNS_TTL_MS;
    dnsCache.set(hostname, {
        result,
        expiresAt: Date.now() + ttl,
    });

    return result;
}

// performs the actual dns resolution
async function performResolution(
    hostname: string,
    originalInput: string
): Promise<ResolvedHost> {
    // use custom resolver if provided (for testing)
    if (resolverConfig.dnsResolver) {
        const customResult = await resolverConfig.dnsResolver(hostname);
        return processResolutionResult(
            hostname,
            originalInput,
            customResult.ipv4,
            customResult.ipv6
        );
    }

    // use system dns resolver
    const [ipv4Result, ipv6Result] = await Promise.allSettled([
        resolve4Async(hostname),
        resolverConfig.allowIPv6 !== false ? resolve6Async(hostname) : Promise.resolve([]),
    ]);

    const ipv4Addresses = ipv4Result.status === 'fulfilled' ? ipv4Result.value : [];
    const ipv6Addresses = ipv6Result.status === 'fulfilled' ? ipv6Result.value : [];

    // if both failed, throw error
    if (ipv4Addresses.length === 0 && ipv6Addresses.length === 0) {
        const ipv4Error = ipv4Result.status === 'rejected' ? ipv4Result.reason : null;

        // check for specific dns errors
        if (ipv4Error?.code === 'ENOTFOUND') {
            throw new DNSError(
                `hostname not found: ${hostname}`,
                originalInput,
                hostname,
                'NXDOMAIN'
            );
        }

        throw new DNSError(
            `no dns records found for: ${hostname}`,
            originalInput,
            hostname,
            'NO_RECORDS'
        );
    }

    return processResolutionResult(hostname, originalInput, ipv4Addresses, ipv6Addresses);
}

// processes raw resolution results into validated canonical ips
function processResolutionResult(
    hostname: string,
    originalInput: string,
    ipv4Addresses: string[],
    ipv6Addresses: string[]
): ResolvedHost {
    const canonicalIPv4: CanonicalIP[] = [];
    const canonicalIPv6: CanonicalIP[] = [];

    // process ipv4 addresses
    for (const ip of ipv4Addresses) {
        try {
            const canonical = canonicalizeIP(ip);
            canonicalIPv4.push(canonical);
        } catch {
            // skip malformed ips from dns
            continue;
        }
    }

    // process ipv6 addresses
    for (const ip of ipv6Addresses) {
        try {
            const canonical = canonicalizeIP(ip);
            canonicalIPv6.push(canonical);
        } catch {
            // skip malformed ips from dns
            continue;
        }
    }

    return {
        hostname,
        ipv4Addresses: canonicalIPv4,
        ipv6Addresses: canonicalIPv6,
        resolvedAt: Date.now(),
    };
}

/**
 * resolves a hostname and validates all resolved ips are in allowed ranges.
 * if any resolved ip is blocked, the entire resolution is rejected.
 */
export async function resolveAndValidate(
    hostname: string,
    originalInput: string
): Promise<ResolvedHost> {
    const resolved = await resolveHost(hostname, originalInput);

    // validate all ips - if any is blocked, reject the whole thing
    for (const ip of resolved.ipv4Addresses) {
        validateIPRange(ip, originalInput);
    }

    for (const ip of resolved.ipv6Addresses) {
        validateIPRange(ip, originalInput);
    }

    return resolved;
}

/**
 * selects the best ip to connect to from resolved addresses.
 * prefers ipv4 for maximum compatibility.
 */
export function selectConnectionIP(resolved: ResolvedHost): CanonicalIP | null {
    // prefer ipv4 for compatibility
    for (const ip of resolved.ipv4Addresses) {
        const check = checkIPRange(ip);
        if (check.allowed) {
            return ip;
        }
    }

    // fall back to ipv6
    for (const ip of resolved.ipv6Addresses) {
        const check = checkIPRange(ip);
        if (check.allowed) {
            return ip;
        }
    }

    return null;
}

/**
 * clears the dns cache.
 * primarily for testing purposes.
 */
export function clearDNSCache(): void {
    dnsCache.clear();
}

/**
 * gets the current cache size.
 * for monitoring purposes.
 */
export function getDNSCacheSize(): number {
    return dnsCache.size;
}
