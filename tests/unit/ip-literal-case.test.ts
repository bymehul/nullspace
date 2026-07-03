import { parseURL } from '../../src/core/url-parser';
import { isIPAddress as canonicalizerIsIP, tryCanonicalizeIP } from '../../src/core/ip-canonicalizer';
import { parseIPv4ToBinary } from '../../src/utils/ip-utils';

// Re-implement url-parser.ts isIPAddress exactly as written
function urlParserIsIPAddress(hostname: string): boolean {
    if (hostname.startsWith('[') || hostname.includes(':')) {
        return true;
    }

    const parts = hostname.split('.');
    if (parts.length >= 1 && parts.length <= 4) {
        const allNumeric = parts.every(p => /^(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*|0)$/.test(p));
        if (allNumeric) {
            return true;
        }
    }

    return false;
}

describe('IP literal hex prefix case sensitivity', () => {
    const testCases = [
        { input: '0x7f000001', label: 'lowercase 0x' },
        { input: '0X7F000001', label: 'uppercase 0X' },
        { input: '0xABCDEF01', label: 'lowercase 0x, hex digits' },
        { input: '0XABCDEF01', label: 'uppercase 0X, hex digits' },
        { input: '127.0.0.1', label: 'dotted decimal' },
        { input: '0177.0.0.1', label: 'octal' },
        { input: '0x7f.0x00.0x00.0x01', label: 'dotted hex' },
        { input: '0X7F.0X00.0X00.0X01', label: 'dotted hex uppercase' },
        { input: '0x7f.0.0.1', label: 'mixed dotted hex+decimal' },
        { input: '0X7F.0.0.1', label: 'mixed dotted uppercase hex+decimal' },
        { input: 'example.com', label: 'domain' },
        { input: 'not-an-ip', label: 'plain string' },
    ];

    test.each(testCases)('$label ($input): all implementations agree', ({ input }) => {
        const urlResult = urlParserIsIPAddress(input);
        const canonicalResult = canonicalizerIsIP(input);
        const tryResult = tryCanonicalizeIP(input) !== null;
        const directParse = parseIPv4ToBinary(input) !== null;

        if (directParse) {
            expect(urlResult).toBe(true);
            expect(canonicalResult).toBe(true);
            expect(tryResult).toBe(true);
        } else {
            expect(urlResult).toBe(false);
            expect(canonicalResult).toBe(false);
            expect(tryResult).toBe(false);
        }
    });

    test('0X prefix recognized as IP literal', () => {
        expect(urlParserIsIPAddress('0X7F000001')).toBe(true);
        expect(canonicalizerIsIP('0X7F000001')).toBe(true);
        expect(tryCanonicalizeIP('0X7F000001')).not.toBeNull();
    });

    test('0x prefix recognized as IP literal', () => {
        expect(urlParserIsIPAddress('0x7f000001')).toBe(true);
        expect(canonicalizerIsIP('0x7f000001')).toBe(true);
        expect(tryCanonicalizeIP('0x7f000001')).not.toBeNull();
    });

    test('parseURL normalizes uppercase hex to canonical form', () => {
        const result = parseURL('http://0X7F000001/');
        expect(result.isIPLiteral).toBe(true);
        expect(result.hostname).toBe('127.0.0.1');
    });
});
