/**
 * nullspace - ssrf prevention library
 * 
 * security tests - comprehensive bypass vector testing
 */

import {
    validateURL,
    configureDNSResolver,
    clearDNSCache,
    ValidationError
} from '../../src/index';

import { RangeError } from '../../src/utils/errors';

describe('ssrf bypass vectors', () => {
    beforeEach(() => {
        clearDNSCache();
        configureDNSResolver({});
    });

    /* ─────────────────── ip encoding bypasses ─────────────────── */

    describe('ip encoding bypasses', () => {
        test('blocks decimal ip (2130706433 = 127.0.0.1)', async () => {
            const r = await validateURL('http://2130706433');
            expect(r.valid).toBe(false);
        });

        test('blocks hex ip (0x7f000001 = 127.0.0.1)', async () => {
            const r = await validateURL('http://0x7f000001');
            expect(r.valid).toBe(false);
        });

        test('blocks octal ip (0177.0.0.1 = 127.0.0.1)', async () => {
            const r = await validateURL('http://0177.0.0.1');
            expect(r.valid).toBe(false);
        });

        test('blocks mixed radix (0x7f.0.0.1)', async () => {
            const r = await validateURL('http://0x7f.0.0.1');
            expect(r.valid).toBe(false);
        });

        test('blocks short-form ip (127.1)', async () => {
            const r = await validateURL('http://127.1');
            expect(r.valid).toBe(false);
        });

        test('rejects overflowed octets (127.0.0.256)', async () => {
            const r = await validateURL('http://127.0.0.256');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('MALFORMED_URL');
        });
    });

    /* ─────────────────── ipv6 bypasses ─────────────────── */

    describe('ipv6 bypasses', () => {
        test('blocks ipv6 loopback (::1)', async () => {
            const r = await validateURL('http://[::1]/');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('RANGE_BLOCKED');
        });

        test('blocks expanded ipv6 loopback', async () => {
            const r = await validateURL('http://[0:0:0:0:0:0:0:1]/');
            expect(r.valid).toBe(false);
        });

        test('blocks ipv4-mapped ipv6 loopback', async () => {
            const r = await validateURL('http://[::ffff:127.0.0.1]');
            expect(r.valid).toBe(false);
        });

        test('blocks ipv4-mapped cloud metadata', async () => {
            const r = await validateURL('http://[::ffff:169.254.169.254]/');
            expect(r.valid).toBe(false);
        });
    });

    /* ─────────────────── cloud metadata ─────────────────── */

    describe('cloud metadata endpoints', () => {
        test('blocks aws metadata (169.254.169.254)', async () => {
            const r = await validateURL('http://169.254.169.254/');
            expect(r.valid).toBe(false);
        });

        test('blocks decimal-encoded metadata (2852039166)', async () => {
            const r = await validateURL('http://2852039166/');
            expect(r.valid).toBe(false);
        });

        test('blocks hex-encoded metadata (0xa9fea9fe)', async () => {
            const r = await validateURL('http://0xa9fea9fe/');
            expect(r.valid).toBe(false);
        });
    });

    /* ─────────────────── dns rebinding ─────────────────── */

    describe('dns rebinding protection', () => {
        test('ttl floor prevents rebinding', async () => {
            let calls = 0;
            let returnHostile = false;

            configureDNSResolver({
                dnsCacheTTLFloor: 60000,
                dnsResolver: async () => {
                    calls++;
                    return returnHostile
                        ? { ipv4: ['127.0.0.1'], ipv6: [] }
                        : { ipv4: ['93.184.216.34'], ipv6: [] };
                }
            });

            // first call caches public ip
            const r1 = await validateURL('http://rebind.test');
            expect(r1.valid).toBe(true);
            expect(calls).toBe(1);

            // attacker changes dns
            returnHostile = true;

            // second call uses cached result
            const r2 = await validateURL('http://rebind.test');
            expect(r2.valid).toBe(true);
            expect(calls).toBe(1);
        });

        test('rejects if any resolved ip is hostile', async () => {
            configureDNSResolver({
                dnsResolver: async () => ({
                    ipv4: ['1.1.1.1', '127.0.0.1'],
                    ipv6: []
                })
            });

            const r = await validateURL('http://multi.test');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('RANGE_BLOCKED');
        });
    });

    /* ─────────────────── protocol attacks ─────────────────── */

    describe('protocol attacks', () => {
        const dangerous = [
            'file:///etc/passwd',
            'gopher://localhost:25/',
            'dict://localhost:11211/',
            'ftp://internal/sensitive',
            'data:text/html,<script>alert(1)</script>',
            'javascript:alert(1)'
        ];

        for (const url of dangerous) {
            const proto = url.split(':')[0];
            test(`blocks ${proto}://`, async () => {
                const r = await validateURL(url);
                expect(r.valid).toBe(false);
            });
        }
    });

    /* ─────────────────── null byte injection ─────────────────── */

    describe('null byte injection', () => {
        test('blocks %00 null byte', async () => {
            const r = await validateURL('http://example.com%00.evil.com');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('NULL_BYTE_DETECTED');
        });

        test('blocks %2500 double-encoded null byte', async () => {
            const r = await validateURL('http://example.com%2500.evil.com');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('NULL_BYTE_DETECTED');
        });
    });

    /* ─────────────────── url parser tricks ─────────────────── */

    describe('url parser tricks', () => {
        test('blocks ambiguous userinfo (multiple @)', async () => {
            const r = await validateURL('http://google.com@evil.com@another.com');
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('AMBIGUOUS_USERINFO');
        });

        test('ignores fragment-based host smuggling', async () => {
            configureDNSResolver({
                dnsResolver: async () => ({ ipv4: ['93.184.216.34'], ipv6: [] })
            });
            const r = await validateURL('http://example.com#@127.0.0.1');
            expect(r.valid).toBe(true);
            expect(r.parsedURL?.hostname).toBe('example.com');
        });

        test('handles backslash ambiguity safely', async () => {
            try {
                const r = await validateURL('http://evil.com\\@google.com');
                if (r.valid) {
                    expect(r.parsedURL?.hostname).not.toBe('google.com');
                }
            } catch (e) {
                expect(e).toBeInstanceOf(ValidationError);
            }
        });
    });

    /* ─────────────────── private ranges ─────────────────── */

    describe('private ip ranges', () => {
        test('blocks 10.x.x.x', async () => {
            const r = await validateURL('http://10.0.0.1/');
            expect(r.valid).toBe(false);
        });

        test('blocks 172.16.x.x', async () => {
            const r = await validateURL('http://172.16.0.1/');
            expect(r.valid).toBe(false);
        });

        test('blocks 192.168.x.x', async () => {
            const r = await validateURL('http://192.168.1.1/');
            expect(r.valid).toBe(false);
        });

        test('blocks carrier-grade nat (100.64.x.x)', async () => {
            const r = await validateURL('http://100.64.0.1/');
            expect(r.valid).toBe(false);
        });
    });

    describe('hostname policy', () => {
        test('enforces optional hostname allowlist', async () => {
            const r = await validateURL('http://blocked.example', {
                allowedHostnames: ['allowed.example'],
            });
            expect(r.valid).toBe(false);
            expect(r.errorCode).toBe('HOST_NOT_ALLOWED');
        });
    });
});
