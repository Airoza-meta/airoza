import * as crypto from 'crypto';

const firstNames = [
  'James', 'Michael', 'John', 'David', 'Robert',
  'William', 'Daniel', 'Matthew', 'Christopher', 'Andrew',
  'Joseph', 'Joshua', 'Anthony', 'Ryan', 'Nicholas',
  'Alexander', 'Benjamin', 'Samuel', 'Lucas', 'Henry',
  'Oliver', 'Jack', 'Ethan', 'Liam'
];

const lastNames = [
  'Smith', 'Johnson', 'Brown', 'Taylor', 'Anderson',
  'Thomas', 'Jackson', 'White', 'Harris', 'Martin',
  'Thompson', 'Garcia', 'Martinez', 'Robinson', 'Clark',
  'Lewis', 'Walker', 'Hall', 'Allen', 'Young'
];

export function generateIdentity() {
    const fn = firstNames[Math.floor(Math.random() * firstNames.length)] || 'User';
    const ln = lastNames[Math.floor(Math.random() * lastNames.length)] || 'Agent';
    const fullName = `${fn} ${ln}`;

    // Generate username like fn_ln_123 or fnln_99
    const suffix = Math.floor(Math.random() * 1000);
    const separators = ['', '_', '.'];
    const sep = separators[Math.floor(Math.random() * separators.length)];
    const username = `${fn.toLowerCase()}${sep}${ln.toLowerCase()}${suffix}`.replace(/[^a-z0-9._]/g, '');

    // Static-ish but unique password
    const password = `InstaForge!${crypto.randomBytes(4).toString('hex')}`;

    return { fullName, username, password };
}

// --- TOTP UTILS (Custom Implementation to avoid dependencies) ---

// Simplified and standard Base32 decode
function decodeBase32(encoded: string): Buffer {
    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let val = 0;
    let bits = 0;
    const output: number[] = [];

    const clean = (encoded || '').toUpperCase().replace(/[^A-Z2-7]/g, '');

    for (let i = 0; i < clean.length; i++) {
        const char = clean[i] || '';
        const idx = base32chars.indexOf(char);
        if (idx === -1) continue;

        val = (val << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            output.push((val >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return Buffer.from(output);
}

export function generateTOTP(secret: string, timestamp?: number): string {
    if (!secret) return '';
    try {
        const now = timestamp || Date.now();
        const epoch = Math.floor(now / 1000);
        const timeStep = 30;
        const time = Buffer.alloc(8);

        let counter = Math.floor(epoch / timeStep);

        // Write counter to buffer (Big Endian)
        time.writeUInt32BE(0, 0); // High 32 bits (0)
        time.writeUInt32BE(counter, 4); // Low 32 bits

        // Debug Key Decoding
        const key = decodeBase32(secret);
        // console.log(`[TOTP] Secret: ${secret.substring(0, 5)}... Decoded Hex: ${key.toString('hex')}`); // Uncomment for deep debug
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(time);
        const hash = hmac.digest();

        // Dynamic truncation
        if (hash.length < 20) return ''; // Should be 20 bytes for SHA1

        const offset = (hash[hash.length - 1] ?? 0) & 0xf;

        // Safe access with fallbacks (though with offset & 0xf, it should be within bounds of 20 bytes, max 15+3=18)
        const binary =
            (((hash[offset] ?? 0) & 0x7f) << 24) |
            (((hash[offset + 1] ?? 0) & 0xff) << 16) |
            (((hash[offset + 2] ?? 0) & 0xff) << 8) |
            ((hash[offset + 3] ?? 0) & 0xff);

        const otp = (binary % 1000000).toString();
        return otp.padStart(6, '0');
    } catch (e) {
        console.error('[TOTP] Generation failed:', e);
        return '';
    }
}
