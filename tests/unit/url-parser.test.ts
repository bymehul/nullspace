/**
 * nullspace - SSRF Prevention Library
 * 
 * URL Parser Unit Tests
 * 
 * Tests URL parsing and security validation.
 */

import { parseURL, reconstructURL } from '../../src/core/url-parser';
import { ValidationError } from '../../src/utils/errors';

describe('URL Parsing', () => {
    describe('Valid URLs', () => {
        test('parses simple HTTP URL', () => {
            const result = parseURL('http://example.com');
            expect(result.protocol).toBe('http:');
            expect(result.hostname).toBe('example.com');
            expect(result.port).toBe(80);
            expect(result.pathname).toBe('/');
        });

        test('parses simple HTTPS URL', () => {
            const result = parseURL('https://example.com');
            expect(result.protocol).toBe('https:');
            expect(result.hostname).toBe('example.com');
            expect(result.port).toBe(443);
        });

        test('parses URL with path', () => {
            const result = parseURL('https://example.com/api/v1/users');
            expect(result.pathname).toBe('/api/v1/users');
        });

        test('parses URL with query string', () => {
            const result = parseURL('https://example.com/search?q=test&limit=10');
            expect(result.search).toBe('?q=test&limit=10');
        });

        test('parses URL with explicit port', () => {
            const result = parseURL('http://example.com:8080/api');
            expect(result.port).toBe(8080);
        });

        test('parses URL with hash', () => {
            const result = parseURL('https://example.com/page#section');
            expect(result.hash).toBe('#section');
        });

        test('parses IPv4 literal', () => {
            const result = parseURL('http://192.168.1.1/');
            expect(result.hostname).toBe('192.168.1.1');
            expect(result.isIPLiteral).toBe(true);
        });

        test('parses IPv6 literal', () => {
            const result = parseURL('http://[::1]/');
            expect(result.hostname).toBe('::1');
            expect(result.isIPLiteral).toBe(true);
        });

        test('normalizes hostname to lowercase', () => {
            const result = parseURL('https://EXAMPLE.COM/Path');
            expect(result.hostname).toBe('example.com');
        });
    });

    describe('Protocol Validation', () => {
        test('rejects file:// protocol', () => {
            expect(() => parseURL('file:///etc/passwd')).toThrow(ValidationError);
        });

        test('rejects ftp:// protocol', () => {
            expect(() => parseURL('ftp://example.com/file')).toThrow(ValidationError);
        });

        test('rejects gopher:// protocol', () => {
            expect(() => parseURL('gopher://localhost:25/')).toThrow(ValidationError);
        });

        test('rejects javascript: protocol', () => {
            expect(() => parseURL('javascript:alert(1)')).toThrow(ValidationError);
        });

        test('rejects data: protocol', () => {
            expect(() => parseURL('data:text/html,<h1>test</h1>')).toThrow(ValidationError);
        });

        test('rejects dict:// protocol', () => {
            expect(() => parseURL('dict://localhost:11211/')).toThrow(ValidationError);
        });
    });

    describe('Security Validations', () => {
        test('rejects null bytes in URL', () => {
            expect(() => parseURL('http://example.com/path\x00/file')).toThrow(ValidationError);
            expect(() => parseURL('http://example.com%00.evil.com')).toThrow(ValidationError);
        });

        test('rejects tabs in URL', () => {
            expect(() => parseURL('http://exa\tmple.com/')).toThrow(ValidationError);
        });

        test('rejects newlines in URL', () => {
            expect(() => parseURL('http://example.com\n/')).toThrow(ValidationError);
        });

        test('rejects carriage returns in URL', () => {
            expect(() => parseURL('http://example.com\r/')).toThrow(ValidationError);
        });

        test('rejects empty URL', () => {
            expect(() => parseURL('')).toThrow(ValidationError);
        });

        test('rejects null input', () => {
            expect(() => parseURL(null as unknown as string)).toThrow(ValidationError);
        });

        test('rejects undefined input', () => {
            expect(() => parseURL(undefined as unknown as string)).toThrow(ValidationError);
        });

        test('rejects malformed URLs', () => {
            expect(() => parseURL('not-a-url')).toThrow(ValidationError);
            expect(() => parseURL('://missing-protocol')).toThrow(ValidationError);
        });
    });

    describe('Userinfo Handling', () => {
        test('rejects multiple @ symbols (ambiguous)', () => {
            expect(() => parseURL('http://google.com@evil.com@another.com')).toThrow(ValidationError);
        });

        // Note: Single @ with userinfo is handled by URL API and may or may not throw
        // depending on whether it creates ambiguity
    });

    describe('Port Validation', () => {
        test('accepts valid port range', () => {
            expect(parseURL('http://example.com:1').port).toBe(1);
            expect(parseURL('http://example.com:65535').port).toBe(65535);
        });
    });
});

describe('URL Reconstruction', () => {
    test('reconstructs simple URL', () => {
        const parsed = parseURL('https://example.com/api');
        expect(reconstructURL(parsed)).toBe('https://example.com/api');
    });

    test('omits default ports', () => {
        const httpParsed = parseURL('http://example.com:80/');
        expect(reconstructURL(httpParsed)).toBe('http://example.com/');

        const httpsParsed = parseURL('https://example.com:443/');
        expect(reconstructURL(httpsParsed)).toBe('https://example.com/');
    });

    test('includes non-default ports', () => {
        const parsed = parseURL('http://example.com:8080/');
        expect(reconstructURL(parsed)).toBe('http://example.com:8080/');
    });

    test('includes query string', () => {
        const parsed = parseURL('https://example.com/search?q=test');
        expect(reconstructURL(parsed)).toBe('https://example.com/search?q=test');
    });

    test('handles IPv6 with brackets', () => {
        const parsed = parseURL('http://[::1]:8080/');
        expect(reconstructURL(parsed)).toContain('[');
        expect(reconstructURL(parsed)).toContain(']');
    });
});
