/**
 * nullspace - ssrf prevention library
 *
 * dns resolver module
 *
 * controlled dns resolution with anti-rebinding measures.
 * dns resolution is the single source of truth for hostname -> ip mapping.
 */

import * as dns from 'dns';
import { promisify } from 'util';
import { DNSError } from '../utils/errors';
import { canonicalizeIP } from './ip-canonicalizer';
import { checkIPRange, validateIPRange, setAdditionalBlockedRanges } from './range-classifier';
import type { ResolvedHost, CanonicalIP, NullspaceConfig } from '../types';

// promisified dns functions
const resolve4Async = promisify(dns.resolve4);
const resolve6Async = promisify(dns.resolve6);
const resolveCnameAsync = promisify(dns.resolveCname);

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

// maximum dns resolution timeout per lookup stage (5 seconds)
const DNS_TIMEOUT_MS = 5_000;

// default max dns cache size before oldest entry eviction
const DEFAULT_DNS_CACHE_MAX_ENTRIES = 1024;

// default max recursive cname depth
const DEFAULT_MAX_CNAME_DEPTH = 8;

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

    if (
        config.dnsCacheMaxEntries !== undefined &&
        (!Number.isInteger(config.dnsCacheMaxEntries) || config.dnsCacheMaxEntries < 1)
    ) {
        throw new Error('dns cache max entries must be a positive integer');
    }

    if (
        config.maxCNAMEDepth !== undefined &&
        (!Number.isInteger(config.maxCNAMEDepth) || config.maxCNAMEDepth < 1)
    ) {
        throw new Error('max cname depth must be a positive integer');
    }

    // refresh runtime custom ranges every time config changes
    setAdditionalBlockedRanges(config.additionalBlockedRanges ?? []);

    resolverConfig = config;
}

// computes effective timeout for current resolution call
function getEffectiveResolutionTimeout(timeoutOverrideMs?: number): number {
    if (timeoutOverrideMs === undefined) {
        return DNS_TIMEOUT_MS;
    }

    if (!Number.isFinite(timeoutOverrideMs) || timeoutOverrideMs <= 0) {
        return 1;
    }

    return Math.max(1, Math.min(DNS_TIMEOUT_MS, Math.floor(timeoutOverrideMs)));
}

// evicts expired entries and then oldest entries when needed
function cacheResolvedHost(hostname: string, result: ResolvedHost): void {
    const now = Date.now();

    for (const [key, entry] of dnsCache.entries()) {
        if (entry.expiresAt <= now) {
            dnsCache.delete(key);
        }
    }

    const ttl = resolverConfig.dnsCacheTTLFloor ?? MIN_DNS_TTL_MS;
    const maxEntries = resolverConfig.dnsCacheMaxEntries ?? DEFAULT_DNS_CACHE_MAX_ENTRIES;

    if (dnsCache.has(hostname)) {
        dnsCache.delete(hostname);
    }

    dnsCache.set(hostname, {
        result,
        expiresAt: now + ttl,
    });

    while (dnsCache.size > maxEntries) {
        const oldestKey = dnsCache.keys().next().value as string | undefined;
        if (!oldestKey) {
            break;
        }
        dnsCache.delete(oldestKey);
    }
}

/**
 * resolves a hostname to ip addresses with validation.
 */
export async function resolveHost(
    hostname: string,
    originalInput: string,
    timeoutOverrideMs?: number
): Promise<ResolvedHost> {
    // check cache first
    const cached = dnsCache.get(hostname);
    if (cached && cached.expiresAt > Date.now()) {
        return cached.result;
    }

    const resolutionTimeout = getEffectiveResolutionTimeout(timeoutOverrideMs);

    let timeoutHandle: NodeJS.Timeout | undefined;

    try {
        // resolve with timeout
        const resolvePromise = performResolution(hostname, originalInput, new Set<string>(), 0);
        const timeoutPromise = new Promise<never>((_, reject) => {
            timeoutHandle = setTimeout(
                () => reject(new DNSError(
                    `dns resolution timed out after ${resolutionTimeout}ms`,
                    originalInput,
                    hostname,
                    'RESOLUTION_TIMEOUT'
                )),
                resolutionTimeout
            );
        });

        const result = await Promise.race([resolvePromise, timeoutPromise]);

        cacheResolvedHost(hostname, result);

        return result;
    } finally {
        if (timeoutHandle) {
            clearTimeout(timeoutHandle);
        }
    }
}

// performs the actual dns resolution
async function performResolution(
    hostname: string,
    originalInput: string,
    visited: Set<string>,
    depth: number
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

    return resolveThroughSystemDNS(hostname, originalInput, visited, depth);
}

// resolves through system dns with recursive cname handling
async function resolveThroughSystemDNS(
    hostname: string,
    originalInput: string,
    visited: Set<string>,
    depth: number
): Promise<ResolvedHost> {
    const maxDepth = resolverConfig.maxCNAMEDepth ?? DEFAULT_MAX_CNAME_DEPTH;

    if (depth > maxDepth) {
        throw new DNSError(
            `cname recursion depth exceeded for ${hostname}`,
            originalInput,
            hostname,
            'RESOLUTION_FAILED'
        );
    }

    if (visited.has(hostname)) {
        throw new DNSError(
            `cname loop detected while resolving ${hostname}`,
            originalInput,
            hostname,
            'RESOLUTION_FAILED'
        );
    }

    const nextVisited = new Set(visited);
    nextVisited.add(hostname);

    const [ipv4Result, ipv6Result, cnameResult] = await Promise.allSettled([
        resolve4Async(hostname),
        resolverConfig.allowIPv6 !== false ? resolve6Async(hostname) : Promise.resolve([]),
        resolveCnameAsync(hostname),
    ]);

    const ipv4Addresses = ipv4Result.status === 'fulfilled' ? ipv4Result.value : [];
    const ipv6Addresses = ipv6Result.status === 'fulfilled' ? ipv6Result.value : [];

    // direct a/aaaa records take priority
    if (ipv4Addresses.length > 0 || ipv6Addresses.length > 0) {
        return processResolutionResult(hostname, originalInput, ipv4Addresses, ipv6Addresses);
    }

    const cnameTargets = cnameResult.status === 'fulfilled' ? cnameResult.value : [];

    if (cnameTargets.length === 0) {
        const ipv4Error = ipv4Result.status === 'rejected' ? ipv4Result.reason : null;
        const cnameError = cnameResult.status === 'rejected' ? cnameResult.reason : null;

        if (ipv4Error?.code === 'ENOTFOUND' || cnameError?.code === 'ENOTFOUND') {
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

    // recursively resolve cname targets and merge all terminal a/aaaa answers
    const mergedIPv4: CanonicalIP[] = [];
    const mergedIPv6: CanonicalIP[] = [];

    for (const cnameTarget of cnameTargets) {
        const resolved = await resolveThroughSystemDNS(
            cnameTarget,
            originalInput,
            nextVisited,
            depth + 1
        );
        mergedIPv4.push(...resolved.ipv4Addresses);
        mergedIPv6.push(...resolved.ipv6Addresses);
    }

    return {
        hostname,
        ipv4Addresses: dedupeCanonicalIPs(mergedIPv4),
        ipv6Addresses: dedupeCanonicalIPs(mergedIPv6),
        resolvedAt: Date.now(),
    };
}

// deduplicates canonical ips while preserving first-seen order
function dedupeCanonicalIPs(ips: CanonicalIP[]): CanonicalIP[] {
    const seen = new Set<string>();
    const deduped: CanonicalIP[] = [];

    for (const ip of ips) {
        const key = `${ip.version}:${ip.canonical}`;
        if (seen.has(key)) {
            continue;
        }
        seen.add(key);
        deduped.push(ip);
    }

    return deduped;
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
        ipv4Addresses: dedupeCanonicalIPs(canonicalIPv4),
        ipv6Addresses: dedupeCanonicalIPs(canonicalIPv6),
        resolvedAt: Date.now(),
    };
}

/**
 * resolves a hostname and validates all resolved ips are in allowed ranges.
 * if any resolved ip is blocked, the entire resolution is rejected.
 */
export async function resolveAndValidate(
    hostname: string,
    originalInput: string,
    timeoutOverrideMs?: number
): Promise<ResolvedHost> {
    const resolved = await resolveHost(hostname, originalInput, timeoutOverrideMs);

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
