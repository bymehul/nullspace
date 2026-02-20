/**
 * nullspace - ssrf prevention library
 * 
 * custom error types for precise error handling and security auditing.
 * each error type represents a specific category of security violation.
 */

/**
 * base error class for all nullspace security errors.
 * provides structured error information for logging and debugging.
 */
export abstract class NullspaceError extends Error {
    // error category for programmatic handling
    readonly code: string;

    // original input that triggered the error
    readonly input: string;

    // timestamp when error occurred
    readonly timestamp: number;

    constructor(message: string, input: string, code: string) {
        super(message);
        this.name = this.constructor.name;
        this.input = input;
        this.code = code;
        this.timestamp = Date.now();

        // maintains proper stack trace in v8 environments
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }

    /**
     * returns a safe, serializable representation for logging.
     * intentionally omits potentially sensitive stack traces.
     */
    toJSON(): Record<string, unknown> {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            input: this.input,
            timestamp: this.timestamp,
        };
    }
}

/**
 * thrown when url parsing or validation fails.
 * covers malformed urls, encoding issues, and ambiguous inputs.
 */
export class ValidationError extends NullspaceError {
    // specific validation failure reason
    readonly reason: ValidationFailureReason;

    constructor(message: string, input: string, reason: ValidationFailureReason) {
        super(message, input, reason);
        this.reason = reason;
    }
}

export type ValidationFailureReason =
    | 'MALFORMED_URL'
    | 'INVALID_PROTOCOL'
    | 'INVALID_HOSTNAME'
    | 'INVALID_PORT'
    | 'AMBIGUOUS_USERINFO'
    | 'NULL_BYTE_DETECTED'
    | 'WHITESPACE_IN_HOST'
    | 'HOST_NOT_ALLOWED'
    | 'UNICODE_NORMALIZATION_FAILED';

/**
 * thrown when dns resolution fails or returns invalid results.
 */
export class DNSError extends NullspaceError {
    // dns-specific failure reason
    readonly reason: DNSFailureReason;

    // hostname that failed to resolve
    readonly hostname: string;

    constructor(message: string, input: string, hostname: string, reason: DNSFailureReason) {
        super(message, input, 'DNS_ERROR');
        this.hostname = hostname;
        this.reason = reason;
    }
}

export type DNSFailureReason =
    | 'RESOLUTION_FAILED'
    | 'RESOLUTION_TIMEOUT'
    | 'NO_RECORDS'
    | 'NXDOMAIN';

/**
 * thrown when a resolved ip falls within a blocked range.
 * this is the primary ssrf prevention error.
 */
export class RangeError extends NullspaceError {
    // the blocked ip address (in canonical form)
    readonly blockedIP: string;

    // which rfc or range category triggered the block
    readonly blockedRange: string;

    // whether this was ipv4 or ipv6
    readonly ipVersion: 4 | 6;

    constructor(
        message: string,
        input: string,
        blockedIP: string,
        blockedRange: string,
        ipVersion: 4 | 6
    ) {
        super(message, input, 'RANGE_BLOCKED');
        this.blockedIP = blockedIP;
        this.blockedRange = blockedRange;
        this.ipVersion = ipVersion;
    }
}

/**
 * thrown when protocol validation fails.
 * only http:// and https:// are allowed.
 */
export class ProtocolError extends NullspaceError {
    // the blocked protocol scheme
    readonly protocol: string;

    constructor(message: string, input: string, protocol: string) {
        super(message, input, 'PROTOCOL_BLOCKED');
        this.protocol = protocol;
    }
}

/**
 * thrown when redirect handling fails or is blocked.
 */
export class RedirectError extends NullspaceError {
    // the blocked redirect target
    readonly redirectTarget: string;

    // reason for blocking
    readonly reason: RedirectFailureReason;

    // number of redirects before this one
    readonly redirectCount: number;

    constructor(
        message: string,
        input: string,
        redirectTarget: string,
        reason: RedirectFailureReason,
        redirectCount: number
    ) {
        super(message, input, 'REDIRECT_BLOCKED');
        this.redirectTarget = redirectTarget;
        this.reason = reason;
        this.redirectCount = redirectCount;
    }
}

export type RedirectFailureReason =
    | 'MAX_REDIRECTS_EXCEEDED'
    | 'PROTOCOL_DOWNGRADE'
    | 'CROSS_PROTOCOL'
    | 'INVALID_LOCATION'
    | 'SSRF_IN_REDIRECT';

/**
 * thrown when request hardening limits are exceeded.
 */
export class RequestError extends NullspaceError {
    // specific failure reason
    readonly reason: RequestFailureReason;

    constructor(message: string, input: string, reason: RequestFailureReason) {
        super(message, input, 'REQUEST_ERROR');
        this.reason = reason;
    }
}

export type RequestFailureReason =
    | 'CONNECT_TIMEOUT'
    | 'RESPONSE_TIMEOUT'
    | 'HEADERS_TOO_LARGE'
    | 'RESPONSE_TOO_LARGE'
    | 'CONNECTION_REFUSED'
    | 'CONNECTION_RESET';

// union type of all ssrf-related errors for catch handling
export type SSRFError =
    | ValidationError
    | DNSError
    | RangeError
    | ProtocolError
    | RedirectError
    | RequestError;

/**
 * type guard to check if an error is an ssrf-related error.
 */
export function isSSRFError(error: unknown): error is SSRFError {
    return error instanceof NullspaceError;
}
