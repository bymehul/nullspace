/**
 * nullspace - SSRF Prevention Library
 * 
 * IP Utilities Unit Tests
 * 
 * Tests all known IP encoding bypass vectors.
 */

import {
    parseIPv4ToBinary,
    parseIPv6ToBinary,
    ipv4BytesToString,
    ipv6BytesToString,
    ipMatchesCIDR,
    parseCIDR,
    extractMappedIPv4,
    extractNAT64IPv4,
} from '../../src/utils/ip-utils';

describe('IPv4 Parsing', () => {
    describe('Standard dotted decimal', () => {
        test('parses 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('127.0.0.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 192.168.1.1', () => {
            const bytes = parseIPv4ToBinary('192.168.1.1');
            expect(bytes).toEqual(new Uint8Array([192, 168, 1, 1]));
        });

        test('parses 0.0.0.0', () => {
            const bytes = parseIPv4ToBinary('0.0.0.0');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0]));
        });

        test('parses 255.255.255.255', () => {
            const bytes = parseIPv4ToBinary('255.255.255.255');
            expect(bytes).toEqual(new Uint8Array([255, 255, 255, 255]));
        });
    });

    describe('Short-form IPv4 (inet_aton style)', () => {
        test('parses 127.1 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('127.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 127.0.1 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('127.0.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 10.1 as 10.0.0.1', () => {
            const bytes = parseIPv4ToBinary('10.1');
            expect(bytes).toEqual(new Uint8Array([10, 0, 0, 1]));
        });

        test('parses single decimal 2130706433 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('2130706433');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses single decimal 3232235777 as 192.168.1.1', () => {
            const bytes = parseIPv4ToBinary('3232235777');
            expect(bytes).toEqual(new Uint8Array([192, 168, 1, 1]));
        });
    });

    describe('Octal encoding', () => {
        test('parses 0177.0.0.01 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('0177.0.0.01');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 0300.0250.01.01 as 192.168.1.1', () => {
            const bytes = parseIPv4ToBinary('0300.0250.01.01');
            expect(bytes).toEqual(new Uint8Array([192, 168, 1, 1]));
        });

        test('parses 0177.0.0.0 as 127.0.0.0', () => {
            const bytes = parseIPv4ToBinary('0177.0.0.0');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 0]));
        });

        test('rejects invalid octal (contains 8 or 9)', () => {
            const bytes = parseIPv4ToBinary('0189.0.0.1');
            expect(bytes).toBeNull();
        });
    });

    describe('Hexadecimal encoding', () => {
        test('parses 0x7f.0x0.0x0.0x1 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('0x7f.0x0.0x0.0x1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 0x7f000001 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('0x7f000001');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 0xc0a80101 as 192.168.1.1', () => {
            const bytes = parseIPv4ToBinary('0xc0a80101');
            expect(bytes).toEqual(new Uint8Array([192, 168, 1, 1]));
        });

        test('parses uppercase hex 0X7F.0X0.0X0.0X1', () => {
            const bytes = parseIPv4ToBinary('0X7F.0X0.0X0.0X1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });
    });

    describe('Mixed encoding', () => {
        test('parses 0x7f.1 as 127.0.0.1', () => {
            const bytes = parseIPv4ToBinary('0x7f.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 127.0x0.0.1', () => {
            const bytes = parseIPv4ToBinary('127.0x0.0.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });

        test('parses 0177.0x0.0.1', () => {
            const bytes = parseIPv4ToBinary('0177.0x0.0.1');
            expect(bytes).toEqual(new Uint8Array([127, 0, 0, 1]));
        });
    });

    describe('Invalid inputs', () => {
        test('rejects empty string', () => {
            expect(parseIPv4ToBinary('')).toBeNull();
        });

        test('rejects too many octets', () => {
            expect(parseIPv4ToBinary('1.2.3.4.5')).toBeNull();
        });

        test('rejects negative numbers', () => {
            expect(parseIPv4ToBinary('-1.0.0.1')).toBeNull();
        });

        test('rejects values > 255 in dotted form', () => {
            expect(parseIPv4ToBinary('256.0.0.1')).toBeNull();
        });

        test('rejects hostname strings', () => {
            expect(parseIPv4ToBinary('localhost')).toBeNull();
        });

        test('rejects special characters', () => {
            expect(parseIPv4ToBinary('127.0.0.1;')).toBeNull();
        });
    });
});

describe('IPv6 Parsing', () => {
    describe('Full form', () => {
        test('parses ::1 loopback', () => {
            const bytes = parseIPv6ToBinary('::1');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });

        test('parses full form loopback', () => {
            const bytes = parseIPv6ToBinary('0:0:0:0:0:0:0:1');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });

        test('parses unspecified address ::', () => {
            const bytes = parseIPv6ToBinary('::');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        });
    });

    describe('Bracketed form', () => {
        test('parses [::1]', () => {
            const bytes = parseIPv6ToBinary('[::1]');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });
    });

    describe('Link-local', () => {
        test('parses fe80::1', () => {
            const bytes = parseIPv6ToBinary('fe80::1');
            expect(bytes).toEqual(new Uint8Array([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });

        test('parses fe80::1%eth0 (strips scope)', () => {
            const bytes = parseIPv6ToBinary('fe80::1%eth0');
            expect(bytes).toEqual(new Uint8Array([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });
    });

    describe('IPv4-mapped IPv6', () => {
        test('parses ::ffff:127.0.0.1', () => {
            const bytes = parseIPv6ToBinary('::ffff:127.0.0.1');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]));
        });

        test('parses ::ffff:192.168.1.1', () => {
            const bytes = parseIPv6ToBinary('::ffff:192.168.1.1');
            expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]));
        });
    });

    describe('Unique Local Address (private)', () => {
        test('parses fc00::1', () => {
            const bytes = parseIPv6ToBinary('fc00::1');
            expect(bytes).toEqual(new Uint8Array([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });

        test('parses fd00::1', () => {
            const bytes = parseIPv6ToBinary('fd00::1');
            expect(bytes).toEqual(new Uint8Array([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        });
    });

    describe('Invalid inputs', () => {
        test('rejects malformed brackets', () => {
            expect(parseIPv6ToBinary('[::1')).toBeNull();
        });

        test('rejects too many groups', () => {
            expect(parseIPv6ToBinary('1:2:3:4:5:6:7:8:9')).toBeNull();
        });

        test('rejects multiple ::', () => {
            expect(parseIPv6ToBinary('::1::2')).toBeNull();
        });
    });
});

describe('IP String Conversion', () => {
    test('ipv4BytesToString', () => {
        expect(ipv4BytesToString(new Uint8Array([127, 0, 0, 1]))).toBe('127.0.0.1');
        expect(ipv4BytesToString(new Uint8Array([192, 168, 1, 1]))).toBe('192.168.1.1');
    });

    test('ipv6BytesToString compresses zeros', () => {
        expect(ipv6BytesToString(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))).toBe('::1');
        expect(ipv6BytesToString(new Uint8Array([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))).toBe('fe80::1');
    });
});

describe('CIDR Matching', () => {
    test('matches IP in /8 range', () => {
        const range = parseCIDR('127.0.0.0/8', 'Loopback')!;
        expect(ipMatchesCIDR(new Uint8Array([127, 0, 0, 1]), range)).toBe(true);
        expect(ipMatchesCIDR(new Uint8Array([127, 255, 255, 255]), range)).toBe(true);
        expect(ipMatchesCIDR(new Uint8Array([128, 0, 0, 1]), range)).toBe(false);
    });

    test('matches IP in /16 range', () => {
        const range = parseCIDR('192.168.0.0/16', 'Private')!;
        expect(ipMatchesCIDR(new Uint8Array([192, 168, 0, 1]), range)).toBe(true);
        expect(ipMatchesCIDR(new Uint8Array([192, 168, 255, 255]), range)).toBe(true);
        expect(ipMatchesCIDR(new Uint8Array([192, 169, 0, 1]), range)).toBe(false);
    });

    test('matches IPv6 in range', () => {
        const range = parseCIDR('fc00::/7', 'ULA')!;
        expect(ipMatchesCIDR(
            new Uint8Array([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            range
        )).toBe(true);
        expect(ipMatchesCIDR(
            new Uint8Array([0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            range
        )).toBe(true);
    });
});

describe('IPv4-Mapped IPv6 Extraction', () => {
    test('extracts IPv4 from ::ffff:127.0.0.1', () => {
        const ipv6 = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        const ipv4 = extractMappedIPv4(ipv6);
        expect(ipv4).toEqual(new Uint8Array([127, 0, 0, 1]));
    });

    test('returns null for non-mapped IPv6', () => {
        const ipv6 = new Uint8Array([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        expect(extractMappedIPv4(ipv6)).toBeNull();
    });
});

describe('NAT64 IPv4 Extraction', () => {
    test('extracts IPv4 from 64:ff9b::127.0.0.1', () => {
        const ipv6 = new Uint8Array([0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]);
        const ipv4 = extractNAT64IPv4(ipv6);
        expect(ipv4).toEqual(new Uint8Array([127, 0, 0, 1]));
    });

    test('returns null for non-NAT64 IPv6', () => {
        const ipv6 = new Uint8Array([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        expect(extractNAT64IPv4(ipv6)).toBeNull();
    });
});
