import { InstagramConnection } from '../Core/Connection';
import { InstagramEncryption } from './Encryption';
import { EncryptionParams, LoginResult } from '../Types';
import { sleep } from '../Utils';

export class InstagramAuth extends InstagramConnection {
    private static sharedEncryption: EncryptionParams | null = null;

    protected async getSharedData() {
        try {
            const response = await this.client.get('/accounts/login/', {
                headers: {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                    'referer': 'https://www.instagram.com/'
                }
            });

            if (response.headers['date']) {
                const serverTime = Date.parse(response.headers['date']);
                this.serverTimeDiff = serverTime - Date.now();
            }

            const html = response.data;
            if (typeof html === 'string') {
                const keyMatch = html.match(/\"encryption\":{\"key_id\":\"(\d+)\",\"public_key\":\"([a-f0-9]+)\"/i);
                if (keyMatch?.[1] && keyMatch?.[2]) {
                    InstagramAuth.sharedEncryption = { keyId: keyMatch[1], publicKey: keyMatch[2], timestamp: Date.now() };
                }
            }
            return true;
        } catch {
            return false;
        }
    }

    protected async getEncryptionParams(): Promise<EncryptionParams | null> {
        if (InstagramAuth.sharedEncryption && (Date.now() - InstagramAuth.sharedEncryption.timestamp) < 4 * 3600 * 1000) {
            return InstagramAuth.sharedEncryption;
        }

        await this.getSharedData();
        return InstagramAuth.sharedEncryption || {
            keyId: '216',
            publicKey: 'f39188e898231c52a35360668d29b1f7956a8775438a0f9379ec8f12660a9f5f',
            timestamp: Date.now()
        };
    }

    public async verifySession(): Promise<boolean> {
        try {
            console.log(`[AUTH] Verifying session for ${this.username}...`);
            const res = await this.client.get('/data/shared_data/');
            if (res.data?.config?.viewerId) {
                this.userId = res.data.config.viewerId;
                return true;
            }
            return false;
        } catch (e: any) {
            console.error(`[AUTH] Session verification failed: ${e.message}`);
            return false;
        }
    }

    public async login(usernameOrPassword: string, password?: string): Promise<LoginResult> {
        const targetPassword = password || usernameOrPassword;
        const params = await this.getEncryptionParams();
        if (!params) return { authenticated: false, message: 'Encryption failed' };

        const encPassword = await InstagramEncryption.encrypt(targetPassword, params.publicKey, params.keyId, this.serverTimeDiff);
        if (!encPassword) return { authenticated: false, message: 'Encryption processing failed' };

        const body = new URLSearchParams();
        body.append('enc_password', encPassword);
        body.append('username', this.username);
        body.append('queryParams', '{}');
        body.append('optIntoOneTap', 'false');
        body.append('device_id', this.deviceId);
        body.append('ig_did', this.igDid);

        try {
            const response = await this.client.post('/api/v1/web/accounts/login/ajax/', body.toString(), {
                headers: {
                    'referer': 'https://www.instagram.com/accounts/login/',
                    'x-csrftoken': this.csrfToken,
                }
            });

            const data = response.data;
            if (data.authenticated) {
                this.userId = data.userId || this.userId;
                this.emit('creds.update', this.getAuthStates());
                return { authenticated: true };
            }

            if (data.checkpoint_url || data.message === 'checkpoint_required') {
                return { authenticated: false, message: 'checkpoint_required', checkpointUrl: data.checkpoint_url };
            }

            if (data.two_factor_required) {
                return { authenticated: false, message: 'two_factor_required', two_factor_info: data.two_factor_info };
            }

            return { authenticated: false, message: data.message || 'Unknown error' };
        } catch (e: any) {
            return { authenticated: false, message: e.message, error: e.response?.data };
        }
    }
}
