/**
 * nullspace - SSRF Prevention Library
 * 
 * Range Classifier Unit Tests
 * 
 * Tests that all private/reserved ranges are correctly blocked.
 */

import { checkIPRange, getBlockedRanges } from '../../src/core/range-classifier';
import { canonicalizeIP } from '../../src/core/ip-canonicalizer';
import type { CanonicalIP } from '../../src/types';

function checkIP(ip: string): { allowed: boolean; reason?: string } {
    const canonical = canonicalizeIP(ip);
    const result = checkIPRange(canonical);
    return {
        allowed: result.allowed,
        reason: result.blockedRange?.description,
    };
}

describe('IPv4 Range Classification', () => {
    describe('Loopback (127.0.0.0/8)', () => {
        test('blocks 127.0.0.1', () => {
            expect(checkIP('127.0.0.1').allowed).toBe(false);
        });

        test('blocks 127.255.255.255', () => {
            expect(checkIP('127.255.255.255').allowed).toBe(false);
        });

        test('blocks 127.1 (short form)', () => {
            expect(checkIP('127.1').allowed).toBe(false);
        });

        test('blocks 0x7f000001 (hex)', () => {
            expect(checkIP('0x7f000001').allowed).toBe(false);
        });

        test('blocks 2130706433 (decimal)', () => {
            expect(checkIP('2130706433').allowed).toBe(false);
        });

        test('blocks 0177.0.0.1 (octal)', () => {
            expect(checkIP('0177.0.0.1').allowed).toBe(false);
        });
    });

    describe('Private - 10.0.0.0/8', () => {
        test('blocks 10.0.0.1', () => {
            expect(checkIP('10.0.0.1').allowed).toBe(false);
        });

        test('blocks 10.255.255.255', () => {
            expect(checkIP('10.255.255.255').allowed).toBe(false);
        });

        test('allows 11.0.0.1', () => {
            expect(checkIP('11.0.0.1').allowed).toBe(true);
        });
    });

    describe('Private - 172.16.0.0/12', () => {
        test('blocks 172.16.0.1', () => {
            expect(checkIP('172.16.0.1').allowed).toBe(false);
        });

        test('blocks 172.31.255.255', () => {
            expect(checkIP('172.31.255.255').allowed).toBe(false);
        });

        test('allows 172.15.0.1', () => {
            expect(checkIP('172.15.0.1').allowed).toBe(true);
        });

        test('allows 172.32.0.1', () => {
            expect(checkIP('172.32.0.1').allowed).toBe(true);
        });
    });

    describe('Private - 192.168.0.0/16', () => {
        test('blocks 192.168.0.1', () => {
            expect(checkIP('192.168.0.1').allowed).toBe(false);
        });

        test('blocks 192.168.255.255', () => {
            expect(checkIP('192.168.255.255').allowed).toBe(false);
        });

        test('allows 192.167.0.1', () => {
            expect(checkIP('192.167.0.1').allowed).toBe(true);
        });
    });

    describe('Link-local / Cloud Metadata - 169.254.0.0/16', () => {
        test('blocks 169.254.0.1', () => {
            expect(checkIP('169.254.0.1').allowed).toBe(false);
        });

        test('blocks AWS metadata 169.254.169.254', () => {
            expect(checkIP('169.254.169.254').allowed).toBe(false);
        });

        test('blocks 169.254.169.254 as decimal', () => {
            // 169.254.169.254 = 2852039166
            expect(checkIP('2852039166').allowed).toBe(false);
        });

        test('blocks 169.254.169.254 as hex', () => {
            expect(checkIP('0xa9fea9fe').allowed).toBe(false);
        });
    });

    describe('Carrier-grade NAT - 100.64.0.0/10', () => {
        test('blocks 100.64.0.1', () => {
            expect(checkIP('100.64.0.1').allowed).toBe(false);
        });

        test('blocks 100.127.255.255', () => {
            expect(checkIP('100.127.255.255').allowed).toBe(false);
        });

        test('allows 100.63.0.1', () => {
            expect(checkIP('100.63.0.1').allowed).toBe(true);
        });
    });

    describe('This host - 0.0.0.0/8', () => {
        test('blocks 0.0.0.0', () => {
            expect(checkIP('0.0.0.0').allowed).toBe(false);
        });

        test('blocks 0.255.255.255', () => {
            expect(checkIP('0.255.255.255').allowed).toBe(false);
        });
    });

    describe('Broadcast - 255.255.255.255', () => {
        test('blocks 255.255.255.255', () => {
            expect(checkIP('255.255.255.255').allowed).toBe(false);
        });
    });

    describe('Multicast - 224.0.0.0/4', () => {
        test('blocks 224.0.0.1', () => {
            expect(checkIP('224.0.0.1').allowed).toBe(false);
        });

        test('blocks 239.255.255.255', () => {
            expect(checkIP('239.255.255.255').allowed).toBe(false);
        });
    });

    describe('Reserved - 240.0.0.0/4', () => {
        test('blocks 240.0.0.1', () => {
            expect(checkIP('240.0.0.1').allowed).toBe(false);
        });
    });

    describe('Public IPs are allowed', () => {
        test('allows 8.8.8.8 (Google DNS)', () => {
            expect(checkIP('8.8.8.8').allowed).toBe(true);
        });

        test('allows 1.1.1.1 (Cloudflare DNS)', () => {
            expect(checkIP('1.1.1.1').allowed).toBe(true);
        });

        test('allows 93.184.216.34 (example.com)', () => {
            expect(checkIP('93.184.216.34').allowed).toBe(true);
        });

        test('allows 142.250.185.14 (google.com)', () => {
            expect(checkIP('142.250.185.14').allowed).toBe(true);
        });
    });
});

describe('IPv6 Range Classification', () => {
    describe('Loopback (::1/128)', () => {
        test('blocks ::1', () => {
            expect(checkIP('::1').allowed).toBe(false);
        });

        test('blocks 0:0:0:0:0:0:0:1', () => {
            expect(checkIP('0:0:0:0:0:0:0:1').allowed).toBe(false);
        });

        test('blocks [::1]', () => {
            expect(checkIP('[::1]').allowed).toBe(false);
        });
    });

    describe('Unspecified (::/128)', () => {
        test('blocks ::', () => {
            expect(checkIP('::').allowed).toBe(false);
        });
    });

    describe('Link-local (fe80::/10)', () => {
        test('blocks fe80::1', () => {
            expect(checkIP('fe80::1').allowed).toBe(false);
        });

        test('blocks fe80::1%eth0', () => {
            expect(checkIP('fe80::1%eth0').allowed).toBe(false);
        });

        test('blocks febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
            expect(checkIP('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff').allowed).toBe(false);
        });
    });

    describe('Unique Local Address (fc00::/7)', () => {
        test('blocks fc00::1', () => {
            expect(checkIP('fc00::1').allowed).toBe(false);
        });

        test('blocks fd00::1', () => {
            expect(checkIP('fd00::1').allowed).toBe(false);
        });

        test('blocks fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
            expect(checkIP('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').allowed).toBe(false);
        });
    });

    describe('Multicast (ff00::/8)', () => {
        test('blocks ff00::1', () => {
            expect(checkIP('ff00::1').allowed).toBe(false);
        });

        test('blocks ff02::1', () => {
            expect(checkIP('ff02::1').allowed).toBe(false);
        });
    });

    describe('IPv4-mapped IPv6 (::ffff:0:0/96)', () => {
        test('blocks ::ffff:127.0.0.1', () => {
            expect(checkIP('::ffff:127.0.0.1').allowed).toBe(false);
        });

        test('blocks ::ffff:192.168.1.1', () => {
            expect(checkIP('::ffff:192.168.1.1').allowed).toBe(false);
        });

        test('blocks ::ffff:169.254.169.254', () => {
            expect(checkIP('::ffff:169.254.169.254').allowed).toBe(false);
        });

        test('allows ::ffff:8.8.8.8 (public IP)', () => {
            expect(checkIP('::ffff:8.8.8.8').allowed).toBe(true);
        });
    });

    describe('Public IPv6 is allowed', () => {
        test('allows 2001:4860:4860::8888 (Google DNS)', () => {
            expect(checkIP('2001:4860:4860::8888').allowed).toBe(true);
        });

        test('allows 2606:4700:4700::1111 (Cloudflare DNS)', () => {
            expect(checkIP('2606:4700:4700::1111').allowed).toBe(true);
        });
    });
});

describe('Edge Cases', () => {
    test('all documented ranges are present', () => {
        const { ipv4, ipv6 } = getBlockedRanges();

        // ipv4 critical ranges (lowercase descriptions)
        expect(ipv4.some(r => r.description.toLowerCase().includes('loopback'))).toBe(true);
        expect(ipv4.some(r => r.description.toLowerCase().includes('private'))).toBe(true);
        expect(ipv4.some(r => r.description.toLowerCase().includes('link-local'))).toBe(true);
        expect(ipv4.some(r => r.description.toLowerCase().includes('carrier-grade'))).toBe(true);

        // ipv6 critical ranges (lowercase descriptions)
        expect(ipv6.some(r => r.description.toLowerCase().includes('loopback'))).toBe(true);
        expect(ipv6.some(r => r.description.toLowerCase().includes('link-local'))).toBe(true);
        expect(ipv6.some(r => r.description.toLowerCase().includes('unique local'))).toBe(true);
    });
});
