import axios, { AxiosInstance } from 'axios';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { CONFIG } from '../../../config';
import { InstagramAuthState } from '../Types';
import { generateIGDid, generateUUID, generateWebSessionId, parseCookie } from '../Utils';
import EventEmitter from 'events';

export class InstagramConnection extends EventEmitter {
    protected client: AxiosInstance;
    protected username: string;
    protected proxy: string;
    protected cookieStore: Map<string, string> = new Map();
    protected csrfToken: string = '';
    protected wwwClaim: string = '0';
    protected userId: string = '';
    protected deviceId: string;
    protected igDid: string;
    protected webSessionId: string = generateWebSessionId();
    protected serverTimeDiff: number = 0;

    constructor(username: string, proxy?: string, initialState?: Partial<InstagramAuthState>) {
        super();
        this.username = username;
        this.proxy = proxy || '';
        this.deviceId = initialState?.deviceId || generateUUID();
        this.igDid = initialState?.igDid || generateIGDid();
        if (initialState?.cookie) {
            const cookies = initialState.cookie.split(';');
            cookies.forEach(c => {
                const p = parseCookie(c);
                if (p?.key === 'ds_user_id') this.userId = p.value;
            });
        }

        const headers = {
            'authority': 'www.instagram.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': initialState?.userAgent || CONFIG.USER_AGENT,
            'x-ig-app-id': initialState?.appId || '936619743392459',
            'x-ig-www-claim': '0',
            'x-instagram-ajax': '1032611956',
            'x-requested-with': 'XMLHttpRequest',
        };

        const axiosConfig: any = {
            baseURL: CONFIG.BASE_URL,
            headers,
            maxRedirects: 0,
            timeout: 30000,
            validateStatus: (status: number) => status >= 200 && status < 400
        };

        if (this.proxy) {
            this.setupProxy(axiosConfig);
        }

        this.client = axios.create(axiosConfig);
        this.setupInterceptors();

        if (initialState?.cookie) {
            this.updateCookies(initialState.cookie.split(';'));
        }
    }

    private setupProxy(config: any) {
        try {
            const cleanProxy = this.proxy.replace('http://', '').replace('https://', '');
            const parts = cleanProxy.split(':');
            let agentUrl = this.proxy;

            if (parts.length === 4) {
                const [p0, p1, p2, p3] = parts;
                if (/^\d+$/.test(p1)) agentUrl = `http://${p2}:${p3}@${p0}:${p1}`;
                else if (/^\d+$/.test(p3)) agentUrl = `http://${p0}:${p1}@${p2}:${p3}`;
            }

            config.httpsAgent = new HttpsProxyAgent(agentUrl, { keepAlive: true });
            config.proxy = false;
        } catch (e: any) {
            console.error(`[CORE] Proxy Error: ${e.message}`);
        }
    }

    private setupInterceptors() {
        this.client.interceptors.response.use((response) => {
            if (response.headers['set-cookie']) {
                this.updateCookies(response.headers['set-cookie']);
            }
            const claim = response.headers['x-ig-set-www-claim'];
            if (claim) this.updateWwwClaim(claim);
            return response;
        }, (error) => {
            if (error.response?.headers?.['set-cookie']) {
                this.updateCookies(error.response.headers['set-cookie']);
            }
            const claim = error.response?.headers?.['x-ig-set-www-claim'];
            if (claim) this.updateWwwClaim(claim);
            return Promise.reject(error);
        });
    }

    protected updateCookies(cookies: string[]) {
        cookies.forEach(c => {
            const parsed = parseCookie(c);
            if (parsed) {
                this.cookieStore.set(parsed.key, parsed.value);
                if (parsed.key === 'csrftoken') this.csrfToken = parsed.value;
            }
        });

        const cookieString = Array.from(this.cookieStore.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
        this.client.defaults.headers.common['cookie'] = cookieString;
        this.emit('creds.update', this.getAuthStates());
    }

    protected updateWwwClaim(claim: string) {
        this.wwwClaim = claim;
        this.client.defaults.headers.common['x-ig-www-claim'] = claim;
    }

    public getAuthStates(): InstagramAuthState {
        return {
            cookie: Array.from(this.cookieStore.entries()).map(([k, v]) => `${k}=${v}`).join('; '),
            userAgent: this.client.defaults.headers.common['user-agent'] as string,
            appId: this.client.defaults.headers.common['x-ig-app-id'] as string,
            asbdId: '359341',
            deviceId: this.deviceId,
            igDid: this.igDid
        };
    }
}
