import sodium from 'libsodium-wrappers';
import * as crypto from 'crypto';

export class InstagramEncryption {
    static async encrypt(password: string, publicKey: string, keyId: string, timeOffset: number = 0): Promise<string | null> {
        await sodium.ready;
        // @ts-ignore
        const api = sodium.crypto_box_seal ? sodium : sodium.default;

        if (!api || typeof api.crypto_box_seal !== 'function') return null;

        const time = Math.floor((Date.now() + timeOffset) / 1000).toString();
        const sessionKey = crypto.randomBytes(32);
        const iv = Buffer.alloc(12, 0);
        const keyIdInt = parseInt(keyId, 10);

        const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
        cipher.setAAD(Buffer.from(time));

        const encryptedPassword = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();

        const pubKeyBytes = api.from_hex(publicKey);
        const encryptedKey = api.crypto_box_seal(sessionKey, pubKeyBytes);

        const encKeyLen = encryptedKey.length;
        const payloadLength = 1 + 1 + 2 + encKeyLen + authTag.length + encryptedPassword.length;
        const payload = Buffer.alloc(payloadLength);

        let offset = 0;
        payload.writeUInt8(1, offset++);
        payload.writeUInt8(keyIdInt, offset++);
        payload.writeUInt16LE(encKeyLen, offset);
        offset += 2;

        payload.set(encryptedKey, offset);
        offset += encKeyLen;
        payload.set(authTag, offset);
        offset += authTag.length;
        payload.set(encryptedPassword, offset);

        return `#PWD_INSTAGRAM_BROWSER:10:${time}:${payload.toString('base64')}`;
    }
}
