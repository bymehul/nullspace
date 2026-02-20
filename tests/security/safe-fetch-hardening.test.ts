/**
 * nullspace - SSRF Prevention Library
 *
 * Safe Fetch Hardening Tests
 *
 * Tests redirect semantics and DoS-oriented guardrails.
 */

import * as http from 'http';
import { EventEmitter } from 'events';
import { safeFetch, configureDNSResolver, clearDNSCache } from '../../src/index';

jest.mock('http', () => {
    const actual = jest.requireActual('http');
    return {
        ...actual,
        request: jest.fn(),
    };
});

interface MockResponseSpec {
    status: number;
    headers?: Record<string, string>;
    rawHeaders?: string[];
    bodyChunks?: Buffer[];
    delayMs?: number;
}

function mockHTTPResponses(specs: MockResponseSpec[]): {
    requestOptions: http.RequestOptions[];
    requestWrites: Buffer[][];
} {
    const requestOptions: http.RequestOptions[] = [];
    const requestWrites: Buffer[][] = [];
    let callIndex = 0;

    (http.request as unknown as jest.Mock).mockImplementation(((options: http.RequestOptions, callback: (res: http.IncomingMessage) => void) => {
        requestOptions.push(options);

        const writes: Buffer[] = [];
        requestWrites.push(writes);

        const req = new EventEmitter() as http.ClientRequest;

        (req as unknown as { write: (chunk: string | Buffer) => void }).write = (chunk: string | Buffer): void => {
            writes.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        };

        (req as unknown as { end: () => void }).end = (): void => {
            const spec = specs[Math.min(callIndex, specs.length - 1)] as MockResponseSpec;
            callIndex++;

            const res = new EventEmitter() as http.IncomingMessage;
            (res as unknown as { statusCode?: number }).statusCode = spec.status;
            (res as unknown as { statusMessage?: string }).statusMessage = 'OK';
            (res as unknown as { headers: http.IncomingHttpHeaders }).headers = spec.headers ?? {};
            (res as unknown as { rawHeaders: string[] }).rawHeaders = spec.rawHeaders ?? Object.entries(spec.headers ?? {}).flat();

            callback(res);

            const emitBody = (): void => {
                for (const chunk of spec.bodyChunks ?? []) {
                    (res as unknown as EventEmitter).emit('data', chunk);
                }
                (res as unknown as EventEmitter).emit('end');
            };

            if (spec.delayMs && spec.delayMs > 0) {
                setTimeout(emitBody, spec.delayMs);
            } else {
                process.nextTick(emitBody);
            }
        };

        (req as unknown as { destroy: (error?: Error) => void }).destroy = (error?: Error): void => {
            if (error) {
                process.nextTick(() => {
                    (req as unknown as EventEmitter).emit('error', error);
                });
            }
        };

        return req;
    }) as unknown as typeof http.request);

    return { requestOptions, requestWrites };
}

describe('safeFetch hardening', () => {
    beforeEach(() => {
        (http.request as unknown as jest.Mock).mockReset();
        clearDNSCache();
        configureDNSResolver({
            dnsResolver: async () => ({ ipv4: ['93.184.216.34'], ipv6: [] }),
        });
    });

    afterEach(() => {
        (http.request as unknown as jest.Mock).mockReset();
    });

    test('changes method to GET after 302 redirect', async () => {
        const mock = mockHTTPResponses([
            { status: 302, headers: { location: '/next' } },
            { status: 200, bodyChunks: [Buffer.from('ok')] },
        ]);

        await safeFetch('http://redirect.test/start', {
            method: 'POST',
            body: 'payload',
            followRedirects: true,
            maxRedirects: 2,
        });

        expect(mock.requestOptions[0]?.method).toBe('POST');
        expect(mock.requestOptions[1]?.method).toBe('GET');
        expect(mock.requestWrites[0]?.length).toBe(1);
        expect(mock.requestWrites[1]?.length).toBe(0);
    });

    test('preserves method and body on 307 redirect', async () => {
        const mock = mockHTTPResponses([
            { status: 307, headers: { location: '/next' } },
            { status: 200, bodyChunks: [Buffer.from('ok')] },
        ]);

        await safeFetch('http://redirect.test/start', {
            method: 'POST',
            body: 'payload',
            followRedirects: true,
            maxRedirects: 2,
        });

        expect(mock.requestOptions[0]?.method).toBe('POST');
        expect(mock.requestOptions[1]?.method).toBe('POST');
        expect(mock.requestWrites[0]?.length).toBe(1);
        expect(mock.requestWrites[1]?.length).toBe(1);
    });

    test('enforces max redirects', async () => {
        mockHTTPResponses([
            { status: 302, headers: { location: '/loop' } },
            { status: 302, headers: { location: '/loop' } },
        ]);

        await expect(
            safeFetch('http://redirect.test/start', {
                followRedirects: true,
                maxRedirects: 1,
            })
        ).rejects.toMatchObject({
            code: 'REDIRECT_BLOCKED',
        });
    });

    test('enforces max response body size', async () => {
        mockHTTPResponses([
            { status: 200, bodyChunks: [Buffer.from('123456')] },
        ]);

        await expect(
            safeFetch('http://size.test', {
                maxResponseSize: 4,
            })
        ).rejects.toMatchObject({
            code: 'REQUEST_ERROR',
            reason: 'RESPONSE_TOO_LARGE',
        });
    });

    test('enforces max response header size', async () => {
        mockHTTPResponses([
            {
                status: 200,
                headers: { 'x-test': 'ok' },
                rawHeaders: ['x-big', 'a'.repeat(128)],
            },
        ]);

        await expect(
            safeFetch('http://headers.test', {
                maxResponseHeadersSize: 16,
            })
        ).rejects.toMatchObject({
            code: 'REQUEST_ERROR',
            reason: 'HEADERS_TOO_LARGE',
        });
    });

    test('enforces absolute total timeout', async () => {
        mockHTTPResponses([
            {
                status: 200,
                bodyChunks: [Buffer.from('ok')],
                delayMs: 80,
            },
        ]);

        await expect(
            safeFetch('http://timeout.test', {
                responseTimeout: 500,
                totalTimeout: 30,
            })
        ).rejects.toMatchObject({
            code: 'REQUEST_ERROR',
            reason: 'RESPONSE_TIMEOUT',
        });
    });

    test('supports strict hostname allowlist mode', async () => {
        mockHTTPResponses([
            { status: 200, bodyChunks: [Buffer.from('ok')] },
        ]);

        await expect(
            safeFetch('http://blocked.test', {
                allowedHostnames: ['allowed.test'],
            })
        ).rejects.toMatchObject({
            code: 'HOST_NOT_ALLOWED',
        });
    });
});
