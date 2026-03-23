/**
 * VoxLink Custom Cipher
 * ─────────────────────
 * Shared between server (Node.js) and Android app (Java).
 * No base64, no standard encoding — custom XOR + 5-bit packing.
 *
 * Algorithm:
 *  1. payload  = "server|roomId|password"  (UTF-8, ASCII only)
 *  2. XOR each byte with a position-derived key (seeded with SECRET_SEED)
 *  3. Prepend payload length byte
 *  4. Pack every 8 bits into groups of 5 → map to custom 32-char ALPHABET
 *  5. Append 5-char checksum (rotate-XOR of original bytes, mapped to ALPHABET)
 *
 * Result: uppercase string like  KWWVFEHH5J3S6QM23SLLNSW9LF5FYFZXLH6XAE8VKE15AGGXGF19C
 */

'use strict';

// ── Secret seed — MUST match Android HashUtil.java ──────────────────────────
const SECRET_SEED = 0x56584C4B; // 'VXLK' as int

// ── Custom 32-char alphabet — NOT base64, no ambiguous chars ────────────────
const ALPHA = 'VXLK9B2P7NM4GRJQ8CZYFW3H5T6ASD1E'; // exactly 32 chars

// ── Key derivation ────────────────────────────────────────────────────────────
function xorKey(i) {
    let k = (SECRET_SEED ^ (Math.imul(i, 0x9E3779B9) >>> 0)) >>> 0;
    k = (k ^ (k >>> 16)) >>> 0;
    k = (Math.imul(k, 0x45D9F3B) >>> 0);
    k = (k ^ (k >>> 16)) >>> 0;
    return k & 0xFF;
}

// ── 5-char checksum ───────────────────────────────────────────────────────────
function checksum(bytes) {
    let cs = SECRET_SEED >>> 0;
    for (const b of bytes)
        cs = ((((cs << 5) | (cs >>> 27)) ^ b) >>> 0);
    return ALPHA[(cs >>> 27) & 31]
         + ALPHA[(cs >>> 22) & 31]
         + ALPHA[(cs >>> 17) & 31]
         + ALPHA[(cs >>> 12) & 31]
         + ALPHA[(cs >>>  7) & 31];
}

// ── Encode ────────────────────────────────────────────────────────────────────
function encode(server, roomId, password) {
    const payload = server + '|' + roomId + '|' + (password || '');
    if (payload.length > 255) throw new Error('Payload too long');

    // To byte array
    const raw = [];
    for (let i = 0; i < payload.length; i++)
        raw.push(payload.charCodeAt(i) & 0xFF);

    // XOR each byte
    const xored = raw.map((b, i) => (b ^ xorKey(i)) & 0xFF);

    // Prepend length + pack to 5-bit groups
    const data = [raw.length, ...xored];
    let bits = '';
    for (const b of data) bits += b.toString(2).padStart(8, '0');
    while (bits.length % 5 !== 0) bits += '0';

    let result = '';
    for (let i = 0; i < bits.length; i += 5)
        result += ALPHA[parseInt(bits.slice(i, i + 5), 2)];

    return result + checksum(raw);
}

// ── Decode ────────────────────────────────────────────────────────────────────
function decode(hash) {
    try {
        const h     = String(hash).trim().toUpperCase();
        const check = h.slice(-5);
        const body  = h.slice(0, -5);

        // Map alphabet chars back to 5-bit groups
        let bits = '';
        for (const c of body) {
            const idx = ALPHA.indexOf(c);
            if (idx < 0) return null;
            bits += idx.toString(2).padStart(5, '0');
        }

        // Unpack to bytes
        const allBytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8)
            allBytes.push(parseInt(bits.slice(i, i + 8), 2));

        if (allBytes.length < 2) return null;

        const payloadLen = allBytes[0];
        const xored = allBytes.slice(1, 1 + payloadLen);
        if (xored.length < payloadLen) return null;

        // Reverse XOR
        const raw = xored.map((b, i) => (b ^ xorKey(i)) & 0xFF);

        // Verify checksum
        if (checksum(raw) !== check) return null;

        let payload = '';
        for (const b of raw) payload += String.fromCharCode(b);

        const parts = payload.split('|');
        if (parts.length < 2) return null;

        return {
            server:   parts[0],
            roomId:   parts[1],
            password: parts[2] || '',
        };
    } catch (e) {
        return null;
    }
}

module.exports = { encode, decode };
