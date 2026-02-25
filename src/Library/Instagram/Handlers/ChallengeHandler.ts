import { InstagramAuth } from '../Auth/InstagramAuth';

export class InstagramChallenge extends InstagramAuth {
    public async verifyTwoFactor(code: string, twoFactorInfo: any): Promise<any> {
        const identifier = twoFactorInfo.two_factor_identifier;
        const body = new URLSearchParams();
        body.append('verification_code', code);
        body.append('two_factor_identifier', identifier);
        body.append('queryParams', '{}');
        body.append('device_id', this.deviceId);

        try {
            const res = await this.client.post('/api/v1/web/accounts/login/ajax/two_factor/', body.toString(), {
                headers: { 'x-csrftoken': this.csrfToken }
            });
            if (res.data.authenticated) {
                this.userId = res.data.userId || this.userId;
                this.emit('creds.update', this.getAuthStates());
                return { authenticated: true };
            }
            return { authenticated: false, message: res.data.message };
        } catch (e: any) {
            return { authenticated: false, message: e.message };
        }
    }

    public async sendChallengeOTP(checkpointUrl: string, choice: string = '1'): Promise<boolean> {
        return this.resolveAutoChallenge(checkpointUrl, choice);
    }

    public async submitChallengeCode(checkpointUrl: string, code: string): Promise<any> {
        const body = new URLSearchParams();
        body.append('security_code', code);

        try {
            const res = await this.client.post('/api/v1/challenge/web/submit/', body.toString(), {
                headers: {
                    'x-csrftoken': this.csrfToken,
                    'referer': `https://www.instagram.com${checkpointUrl}`
                }
            });
            return { success: res.data.status === 'ok', data: res.data };
        } catch (e: any) {
            return { success: false, message: e.message };
        }
    }

    public async resolveAutoChallenge(checkpointUrl: string, choice: string = '0'): Promise<boolean> {
        try {
            const params = new URLSearchParams();
            params.append('choice', choice);
            const res = await this.client.post('/api/v1/challenge/web/action/', params, {
                headers: { 'x-csrftoken': this.csrfToken, 'referer': `https://www.instagram.com${checkpointUrl}` }
            });
            return res.data.status === 'ok';
        } catch {
            return false;
        }
    }
}
