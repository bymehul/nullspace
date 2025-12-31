/**
 * nullspace - ssrf prevention library
 * 
 * socket pinner module
 * 
 * creates custom http/https agents that pin connections to specific validated ips.
 * this prevents dns re-resolution by node.js internals.
 */

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import type { Duplex } from 'stream';
import type { CanonicalIP } from '../types';

// options for creating a pinned agent
export interface PinnedAgentOptions {
    // the validated ip to connect to
    targetIP: CanonicalIP;

    // the port to connect to
    targetPort: number;

    // original hostname for sni and host header
    originalHost: string;

    // connection timeout in milliseconds
    connectTimeout: number;
}

// custom http agent that pins to a specific ip address
class PinnedHttpAgent extends http.Agent {
    private readonly targetIP: string;
    private readonly targetPort: number;
    private readonly connectTimeoutMs: number;

    constructor(options: PinnedAgentOptions) {
        super({ keepAlive: false });
        this.targetIP = options.targetIP.canonical;
        this.targetPort = options.targetPort;
        this.connectTimeoutMs = options.connectTimeout;
    }

    createConnection(
        options: http.ClientRequestArgs,
        callback?: (err: Error | null, stream: Duplex) => void
    ): Duplex | null | undefined {
        const socket = net.createConnection({
            host: this.targetIP,
            port: this.targetPort,
            timeout: this.connectTimeoutMs,
        });

        // handle connection timeout
        socket.on('timeout', () => {
            socket.destroy(new Error(`connection timed out after ${this.connectTimeoutMs}ms`));
        });

        // set timeout for initial connection
        socket.setTimeout(this.connectTimeoutMs);

        // once connected, clear the timeout (response timeout is handled separately)
        socket.on('connect', () => {
            socket.setTimeout(0);
            if (callback) {
                callback(null, socket);
            }
        });

        socket.on('error', (err) => {
            if (callback) {
                callback(err, socket);
            }
        });

        return socket;
    }
}

// custom https agent that pins to a specific ip address
// properly handles sni (server name indication) for tls
class PinnedHttpsAgent extends https.Agent {
    private readonly targetIP: string;
    private readonly targetPort: number;
    private readonly originalHost: string;
    private readonly connectTimeoutMs: number;

    constructor(options: PinnedAgentOptions) {
        super({ keepAlive: false });
        this.targetIP = options.targetIP.canonical;
        this.targetPort = options.targetPort;
        this.originalHost = options.originalHost;
        this.connectTimeoutMs = options.connectTimeout;
    }

    createConnection(
        options: https.RequestOptions,
        callback?: (err: Error | null, stream: Duplex) => void
    ): Duplex | null | undefined {
        // create tls socket directly with the pinned ip
        const tlsSocket = tls.connect({
            host: this.targetIP,
            port: this.targetPort,
            servername: this.originalHost, // sni - critical for virtual hosting
            rejectUnauthorized: true, // always verify tls certificates
            timeout: this.connectTimeoutMs,
        });

        // handle connection timeout
        tlsSocket.on('timeout', () => {
            tlsSocket.destroy(new Error(`connection timed out after ${this.connectTimeoutMs}ms`));
        });

        tlsSocket.setTimeout(this.connectTimeoutMs);

        tlsSocket.on('secureConnect', () => {
            tlsSocket.setTimeout(0);
            if (callback) {
                callback(null, tlsSocket);
            }
        });

        tlsSocket.on('error', (err) => {
            if (callback) {
                callback(err, tlsSocket);
            }
        });

        return tlsSocket;
    }
}

/**
 * creates an http agent that pins connections to a specific ip.
 */
export function createPinnedHttpAgent(options: PinnedAgentOptions): http.Agent {
    return new PinnedHttpAgent(options);
}

/**
 * creates an https agent that pins connections to a specific ip.
 * properly handles sni (server name indication) for tls.
 */
export function createPinnedHttpsAgent(options: PinnedAgentOptions): https.Agent {
    return new PinnedHttpsAgent(options);
}

/**
 * creates a pinned agent for either http or https based on protocol.
 */
export function createPinnedAgent(
    protocol: 'http' | 'https',
    options: PinnedAgentOptions
): http.Agent | https.Agent {
    if (protocol === 'https') {
        return createPinnedHttpsAgent(options);
    }
    return createPinnedHttpAgent(options);
}

/**
 * cleans up an agent after use.
 * should be called when the request is complete.
 */
export function destroyAgent(agent: http.Agent | https.Agent): void {
    agent.destroy();
}
