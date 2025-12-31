/**
 * nullspace - ssrf prevention library
 * 
 * ip utility functions for binary manipulation and canonicalization.
 * all ip comparisons happen at the binary level to prevent encoding bypasses.
 */

// represents a canonicalized ip address in binary form
export interface CanonicalIP {
    // ip version: 4 or 6
    version: 4 | 6;

    // binary representation: 4 bytes for ipv4, 16 bytes for ipv6
    bytes: Uint8Array;

    // human-readable canonical form (e.g., "127.0.0.1" or "::1")
    canonical: string;
}

// represents a cidr range for ip matching
export interface CIDRRange {
    // base ip address in binary form
    base: Uint8Array;

    // prefix length (0-32 for ipv4, 0-128 for ipv6)
    prefixLength: number;

    // ip version
    version: 4 | 6;

    // human-readable description
    description: string;
}

/**
 * parses an ipv4 address in various formats to binary.
 * handles: dotted decimal, short form, decimal, octal, hex, and mixed.
 */
export function parseIPv4ToBinary(input: string): Uint8Array | null {
    const trimmed = input.trim();

    if (trimmed.length === 0) {
        return null;
    }

    // check for forbidden characters (only allow ., digits, x, X, a-f, A-F)
    if (!/^[0-9a-fA-FxX.]+$/.test(trimmed)) {
        return null;
    }

    // split by dots
    const parts = trimmed.split('.');

    if (parts.length === 0 || parts.length > 4) {
        return null;
    }

    // parse each part
    const parsedParts: number[] = [];

    for (const part of parts) {
        if (part.length === 0) {
            return null;
        }

        const value = parseIPv4Part(part);
        if (value === null || value < 0) {
            return null;
        }

        parsedParts.push(value);
    }

    // handle short-form ipv4 (e.g., 127.1 -> 127.0.0.1)
    // according to inet_aton behavior:
    // - 1 part: treat as 32-bit number
    // - 2 parts: a.b -> a.0.0.b (first is 8-bit, last is 24-bit)
    // - 3 parts: a.b.c -> a.b.0.c (first two are 8-bit, last is 16-bit)
    // - 4 parts: a.b.c.d (each is 8-bit)

    let fullAddress: number;

    switch (parsedParts.length) {
        case 1: {
            // single 32-bit value
            const val = parsedParts[0];
            if (val === undefined || val > 0xFFFFFFFF) {
                return null;
            }
            fullAddress = val;
            break;
        }
        case 2: {
            // a.b where a is 8-bit and b is 24-bit
            const [a, b] = parsedParts;
            if (a === undefined || b === undefined || a > 0xFF || b > 0xFFFFFF) {
                return null;
            }
            fullAddress = (a << 24) | b;
            break;
        }
        case 3: {
            // a.b.c where a,b are 8-bit and c is 16-bit
            const [a, b, c] = parsedParts;
            if (a === undefined || b === undefined || c === undefined ||
                a > 0xFF || b > 0xFF || c > 0xFFFF) {
                return null;
            }
            fullAddress = (a << 24) | (b << 16) | c;
            break;
        }
        case 4: {
            // a.b.c.d where each is 8-bit
            const [a, b, c, d] = parsedParts;
            if (a === undefined || b === undefined || c === undefined || d === undefined ||
                a > 0xFF || b > 0xFF || c > 0xFF || d > 0xFF) {
                return null;
            }
            fullAddress = (a << 24) | (b << 16) | (c << 8) | d;
            break;
        }
        default:
            return null;
    }

    // convert to bytes
    const bytes = new Uint8Array(4);
    bytes[0] = (fullAddress >>> 24) & 0xFF;
    bytes[1] = (fullAddress >>> 16) & 0xFF;
    bytes[2] = (fullAddress >>> 8) & 0xFF;
    bytes[3] = fullAddress & 0xFF;

    return bytes;
}

// parses a single part of an ipv4 address
// handles decimal, octal (0-prefix), and hex (0x-prefix)
function parseIPv4Part(part: string): number | null {
    if (part.length === 0) {
        return null;
    }

    let value: number;

    if (part.startsWith('0x') || part.startsWith('0X')) {
        // hexadecimal
        const hex = part.slice(2);
        if (hex.length === 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
            return null;
        }
        value = parseInt(hex, 16);
    } else if (part.startsWith('0') && part.length > 1) {
        // octal (but check it's valid octal)
        if (!/^[0-7]+$/.test(part)) {
            // contains 8 or 9, invalid octal - reject
            return null;
        }
        value = parseInt(part, 8);
    } else {
        // decimal
        if (!/^[0-9]+$/.test(part)) {
            return null;
        }
        value = parseInt(part, 10);
    }

    if (isNaN(value) || value < 0) {
        return null;
    }

    return value;
}

/**
 * parses an ipv6 address to binary form.
 * handles: full form, compressed (::), ipv4-mapped, scoped (with %).
 */
export function parseIPv6ToBinary(input: string): Uint8Array | null {
    let addr = input.trim();

    // remove brackets if present
    if (addr.startsWith('[') && addr.endsWith(']')) {
        addr = addr.slice(1, -1);
    } else if (addr.startsWith('[')) {
        // malformed - has opening but no closing bracket
        return null;
    }

    // remove scope id (e.g., %eth0) - we don't need it for range checking
    const scopeIndex = addr.indexOf('%');
    if (scopeIndex !== -1) {
        addr = addr.slice(0, scopeIndex);
    }

    if (addr.length === 0) {
        return null;
    }

    // check for ipv4-mapped or ipv4-compatible format
    // e.g., ::ffff:192.168.1.1 or ::192.168.1.1
    const lastColon = addr.lastIndexOf(':');
    if (lastColon !== -1) {
        const afterLastColon = addr.slice(lastColon + 1);
        if (afterLastColon.includes('.')) {
            // has embedded ipv4
            return parseIPv6WithEmbeddedIPv4(addr);
        }
    }

    // pure ipv6 parsing
    return parsePureIPv6(addr);
}

// parses pure ipv6 (no embedded ipv4)
function parsePureIPv6(addr: string): Uint8Array | null {
    // split by ::
    const doubleColonParts = addr.split('::');

    if (doubleColonParts.length > 2) {
        // only one :: allowed
        return null;
    }

    let groups: number[];

    if (doubleColonParts.length === 2) {
        // has ::
        const [left, right] = doubleColonParts;

        if (left === undefined || right === undefined) {
            return null;
        }

        const leftGroups = left.length > 0 ? left.split(':') : [];
        const rightGroups = right.length > 0 ? right.split(':') : [];

        const totalExplicit = leftGroups.length + rightGroups.length;
        if (totalExplicit > 8) {
            return null;
        }

        const zerosNeeded = 8 - totalExplicit;

        // parse left groups
        const leftParsed: number[] = [];
        for (const g of leftGroups) {
            const val = parseIPv6Group(g);
            if (val === null) return null;
            leftParsed.push(val);
        }

        // parse right groups
        const rightParsed: number[] = [];
        for (const g of rightGroups) {
            const val = parseIPv6Group(g);
            if (val === null) return null;
            rightParsed.push(val);
        }

        // combine with zeros in the middle
        groups = [...leftParsed, ...Array(zerosNeeded).fill(0), ...rightParsed];
    } else {
        // no ::, must have exactly 8 groups
        const parts = addr.split(':');
        if (parts.length !== 8) {
            return null;
        }

        groups = [];
        for (const p of parts) {
            const val = parseIPv6Group(p);
            if (val === null) return null;
            groups.push(val);
        }
    }

    if (groups.length !== 8) {
        return null;
    }

    // convert to bytes
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
        const group = groups[i];
        if (group === undefined) return null;
        bytes[i * 2] = (group >> 8) & 0xFF;
        bytes[i * 2 + 1] = group & 0xFF;
    }

    return bytes;
}

// parses ipv6 with embedded ipv4 address
function parseIPv6WithEmbeddedIPv4(addr: string): Uint8Array | null {
    const lastColon = addr.lastIndexOf(':');
    if (lastColon === -1) return null;

    const ipv6Part = addr.slice(0, lastColon);
    const ipv4Part = addr.slice(lastColon + 1);

    // parse the ipv4 part
    const ipv4Bytes = parseIPv4ToBinary(ipv4Part);
    if (!ipv4Bytes) return null;

    // parse the ipv6 prefix
    // the ipv4 replaces the last two groups (4 bytes = 2 groups of 16 bits)
    let prefix: string;

    if (ipv6Part.endsWith(':')) {
        // e.g., "::ffff:" -> ":ffff"
        prefix = ipv6Part.slice(0, -1);
    } else {
        prefix = ipv6Part;
    }

    // handle double colon
    const doubleColonParts = prefix.split('::');

    let groups: number[];

    if (doubleColonParts.length === 2) {
        const [left, right] = doubleColonParts;
        if (left === undefined || right === undefined) return null;

        const leftGroups = left.length > 0 ? left.split(':') : [];
        const rightGroups = right.length > 0 ? right.split(':') : [];

        const totalExplicit = leftGroups.length + rightGroups.length;
        // ipv4 takes 2 groups, so we need 6 groups total
        if (totalExplicit > 6) return null;

        const zerosNeeded = 6 - totalExplicit;

        const leftParsed: number[] = [];
        for (const g of leftGroups) {
            const val = parseIPv6Group(g);
            if (val === null) return null;
            leftParsed.push(val);
        }

        const rightParsed: number[] = [];
        for (const g of rightGroups) {
            const val = parseIPv6Group(g);
            if (val === null) return null;
            rightParsed.push(val);
        }

        groups = [...leftParsed, ...Array(zerosNeeded).fill(0), ...rightParsed];
    } else if (doubleColonParts.length === 1) {
        const parts = prefix.split(':').filter(p => p.length > 0);
        if (parts.length !== 6) return null;

        groups = [];
        for (const p of parts) {
            const val = parseIPv6Group(p);
            if (val === null) return null;
            groups.push(val);
        }
    } else {
        return null;
    }

    if (groups.length !== 6) return null;

    // build the final 16 bytes
    const bytes = new Uint8Array(16);

    for (let i = 0; i < 6; i++) {
        const group = groups[i];
        if (group === undefined) return null;
        bytes[i * 2] = (group >> 8) & 0xFF;
        bytes[i * 2 + 1] = group & 0xFF;
    }

    // add ipv4 bytes at the end
    bytes[12] = ipv4Bytes[0] ?? 0;
    bytes[13] = ipv4Bytes[1] ?? 0;
    bytes[14] = ipv4Bytes[2] ?? 0;
    bytes[15] = ipv4Bytes[3] ?? 0;

    return bytes;
}

// parses a single ipv6 group (up to 4 hex digits)
function parseIPv6Group(group: string): number | null {
    if (group.length === 0 || group.length > 4) {
        return null;
    }

    if (!/^[0-9a-fA-F]+$/.test(group)) {
        return null;
    }

    return parseInt(group, 16);
}

// converts ipv4 binary to canonical string form
export function ipv4BytesToString(bytes: Uint8Array): string {
    if (bytes.length !== 4) {
        throw new Error('ipv4 address must be 4 bytes');
    }
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

// converts ipv6 binary to canonical string form (compressed)
export function ipv6BytesToString(bytes: Uint8Array): string {
    if (bytes.length !== 16) {
        throw new Error('ipv6 address must be 16 bytes');
    }

    // convert to groups
    const groups: number[] = [];
    for (let i = 0; i < 16; i += 2) {
        const b1 = bytes[i];
        const b2 = bytes[i + 1];
        if (b1 === undefined || b2 === undefined) {
            throw new Error('invalid bytes');
        }
        groups.push((b1 << 8) | b2);
    }

    // find longest run of zeros for compression
    let longestStart = -1;
    let longestLength = 0;
    let currentStart = -1;
    let currentLength = 0;

    for (let i = 0; i < 8; i++) {
        if (groups[i] === 0) {
            if (currentStart === -1) {
                currentStart = i;
                currentLength = 1;
            } else {
                currentLength++;
            }
        } else {
            if (currentLength > longestLength) {
                longestStart = currentStart;
                longestLength = currentLength;
            }
            currentStart = -1;
            currentLength = 0;
        }
    }

    // check final run
    if (currentLength > longestLength) {
        longestStart = currentStart;
        longestLength = currentLength;
    }

    // build string
    const parts: string[] = [];
    let i = 0;

    while (i < 8) {
        if (i === longestStart && longestLength > 1) {
            parts.push('');
            if (i === 0) parts.push(''); // leading ::
            i += longestLength;
            if (i === 8) parts.push(''); // trailing ::
        } else {
            const g = groups[i];
            if (g === undefined) throw new Error('invalid group');
            parts.push(g.toString(16));
            i++;
        }
    }

    return parts.join(':');
}

// checks if an ip matches a cidr range
export function ipMatchesCIDR(ip: Uint8Array, range: CIDRRange): boolean {
    if (ip.length !== range.base.length) {
        return false;
    }

    const prefixBytes = Math.floor(range.prefixLength / 8);
    const remainingBits = range.prefixLength % 8;

    // check full bytes
    for (let i = 0; i < prefixBytes; i++) {
        if (ip[i] !== range.base[i]) {
            return false;
        }
    }

    // check remaining bits
    if (remainingBits > 0 && prefixBytes < ip.length) {
        const mask = 0xFF << (8 - remainingBits);
        const ipByte = ip[prefixBytes];
        const baseByte = range.base[prefixBytes];
        if (ipByte === undefined || baseByte === undefined) {
            return false;
        }
        if ((ipByte & mask) !== (baseByte & mask)) {
            return false;
        }
    }

    return true;
}

// creates a cidr range from string notation
export function parseCIDR(notation: string, description: string): CIDRRange | null {
    const parts = notation.split('/');
    if (parts.length !== 2) {
        return null;
    }

    const [ipStr, prefixStr] = parts;
    if (!ipStr || !prefixStr) {
        return null;
    }

    const prefixLength = parseInt(prefixStr, 10);
    if (isNaN(prefixLength) || prefixLength < 0) {
        return null;
    }

    // try ipv4 first
    const ipv4Bytes = parseIPv4ToBinary(ipStr);
    if (ipv4Bytes) {
        if (prefixLength > 32) {
            return null;
        }
        return {
            base: ipv4Bytes,
            prefixLength,
            version: 4,
            description,
        };
    }

    // try ipv6
    const ipv6Bytes = parseIPv6ToBinary(ipStr);
    if (ipv6Bytes) {
        if (prefixLength > 128) {
            return null;
        }
        return {
            base: ipv6Bytes,
            prefixLength,
            version: 6,
            description,
        };
    }

    return null;
}

// checks if the ip is an ipv4-mapped ipv6 address (::ffff:x.x.x.x)
// returns the embedded ipv4 bytes if so, null otherwise
export function extractMappedIPv4(ipv6Bytes: Uint8Array): Uint8Array | null {
    if (ipv6Bytes.length !== 16) {
        return null;
    }

    // check for ::ffff: prefix (first 10 bytes zero, bytes 10-11 are 0xff)
    for (let i = 0; i < 10; i++) {
        if (ipv6Bytes[i] !== 0) {
            return null;
        }
    }

    if (ipv6Bytes[10] !== 0xff || ipv6Bytes[11] !== 0xff) {
        return null;
    }

    // extract ipv4 part
    return ipv6Bytes.slice(12, 16);
}

// checks if the ip is an ipv6 in nat64 format (64:ff9b::/96)
// returns the embedded ipv4 bytes if so, null otherwise
export function extractNAT64IPv4(ipv6Bytes: Uint8Array): Uint8Array | null {
    if (ipv6Bytes.length !== 16) {
        return null;
    }

    // check for 64:ff9b:: prefix (first 12 bytes)
    // 64:ff9b = 0x0064:0xff9b followed by zeros
    if (ipv6Bytes[0] !== 0x00 || ipv6Bytes[1] !== 0x64) {
        return null;
    }
    if (ipv6Bytes[2] !== 0xff || ipv6Bytes[3] !== 0x9b) {
        return null;
    }
    for (let i = 4; i < 12; i++) {
        if (ipv6Bytes[i] !== 0) {
            return null;
        }
    }

    // extract ipv4 part
    return ipv6Bytes.slice(12, 16);
}
