/**
 * nullspace - SSRF Prevention Library
 *
 * DNS Resolver Unit Tests
 *
 * Tests cname recursion, cache controls, and resolver hardening.
 */

function makeDNSError(code: string): NodeJS.ErrnoException {
    const err = new Error(code) as NodeJS.ErrnoException;
    err.code = code;
    return err;
}

type DNSMockConfig = {
    aRecords?: Record<string, string[]>;
    cnameRecords?: Record<string, string[]>;
};

function setupDNSMock(config: DNSMockConfig): {
    resolve4: jest.Mock;
    resolve6: jest.Mock;
    resolveCname: jest.Mock;
} {
    const resolve4 = jest.fn((hostname: string, callback: (err: NodeJS.ErrnoException | null, addresses?: string[]) => void) => {
        process.nextTick(() => {
            const records = config.aRecords?.[hostname];
            if (records && records.length > 0) {
                callback(null, records);
                return;
            }
            callback(makeDNSError('ENODATA'));
        });
    });

    const resolve6 = jest.fn((hostname: string, callback: (err: NodeJS.ErrnoException | null, addresses?: string[]) => void) => {
        process.nextTick(() => {
            callback(makeDNSError('ENODATA'));
        });
    });

    const resolveCname = jest.fn((hostname: string, callback: (err: NodeJS.ErrnoException | null, addresses?: string[]) => void) => {
        process.nextTick(() => {
            const records = config.cnameRecords?.[hostname];
            if (records && records.length > 0) {
                callback(null, records);
                return;
            }
            callback(makeDNSError('ENODATA'));
        });
    });

    jest.doMock('dns', () => ({
        resolve4,
        resolve6,
        resolveCname,
    }));

    return { resolve4, resolve6, resolveCname };
}

describe('DNS resolver hardening', () => {
    afterEach(() => {
        jest.resetModules();
        jest.clearAllMocks();
        jest.dontMock('dns');
    });

    test('follows cname chain to terminal a records', async () => {
        setupDNSMock({
            aRecords: {
                'origin.test': ['93.184.216.34'],
            },
            cnameRecords: {
                'start.test': ['edge.test'],
                'edge.test': ['origin.test'],
            },
        });

        const resolver = await import('../../src/core/dns-resolver');

        resolver.clearDNSCache();
        resolver.configureDNSResolver({ allowIPv6: false });

        const resolved = await resolver.resolveAndValidate('start.test', 'http://start.test');

        expect(resolved.ipv4Addresses).toHaveLength(1);
        expect(resolved.ipv4Addresses[0]?.canonical).toBe('93.184.216.34');
    });

    test('blocks cname chain that ends in private target', async () => {
        setupDNSMock({
            aRecords: {
                'internal.test': ['127.0.0.1'],
            },
            cnameRecords: {
                'start.test': ['internal.test'],
            },
        });

        const resolver = await import('../../src/core/dns-resolver');

        resolver.clearDNSCache();
        resolver.configureDNSResolver({ allowIPv6: false });

        await expect(
            resolver.resolveAndValidate('start.test', 'http://start.test')
        ).rejects.toMatchObject({
            code: 'RANGE_BLOCKED',
        });
    });

    test('detects cname loops', async () => {
        setupDNSMock({
            cnameRecords: {
                'a.test': ['b.test'],
                'b.test': ['a.test'],
            },
        });

        const resolver = await import('../../src/core/dns-resolver');

        resolver.clearDNSCache();
        resolver.configureDNSResolver({ allowIPv6: false });

        await expect(
            resolver.resolveHost('a.test', 'http://a.test')
        ).rejects.toMatchObject({
            code: 'DNS_ERROR',
            reason: 'RESOLUTION_FAILED',
        });
    });

    test('enforces max cname depth', async () => {
        setupDNSMock({
            aRecords: {
                'd.test': ['93.184.216.34'],
            },
            cnameRecords: {
                'a.test': ['b.test'],
                'b.test': ['c.test'],
                'c.test': ['d.test'],
            },
        });

        const resolver = await import('../../src/core/dns-resolver');

        resolver.clearDNSCache();
        resolver.configureDNSResolver({
            allowIPv6: false,
            maxCNAMEDepth: 2,
        });

        await expect(
            resolver.resolveHost('a.test', 'http://a.test')
        ).rejects.toMatchObject({
            code: 'DNS_ERROR',
            reason: 'RESOLUTION_FAILED',
        });
    });

    test('evicts oldest cache entry when max entries exceeded', async () => {
        const resolver = await import('../../src/core/dns-resolver');

        let calls = 0;

        resolver.clearDNSCache();
        resolver.configureDNSResolver({
            dnsCacheTTLFloor: 60_000,
            dnsCacheMaxEntries: 2,
            dnsResolver: async (hostname: string) => {
                calls++;
                if (hostname === 'one.test') return { ipv4: ['93.184.216.34'], ipv6: [] };
                if (hostname === 'two.test') return { ipv4: ['1.1.1.1'], ipv6: [] };
                return { ipv4: ['8.8.8.8'], ipv6: [] };
            },
        });

        await resolver.resolveHost('one.test', 'http://one.test');
        await resolver.resolveHost('two.test', 'http://two.test');
        await resolver.resolveHost('three.test', 'http://three.test');
        await resolver.resolveHost('one.test', 'http://one.test');

        expect(calls).toBe(4);
    });

    test('applies additional blocked ranges from resolver config', async () => {
        const resolver = await import('../../src/core/dns-resolver');

        resolver.clearDNSCache();
        resolver.configureDNSResolver({
            additionalBlockedRanges: ['203.0.114.0/24'],
            dnsResolver: async () => ({ ipv4: ['203.0.114.9'], ipv6: [] }),
        });

        await expect(
            resolver.resolveAndValidate('custom.test', 'http://custom.test')
        ).rejects.toMatchObject({
            code: 'RANGE_BLOCKED',
        });

        // restore defaults for following tests
        resolver.configureDNSResolver({});
    });
});
