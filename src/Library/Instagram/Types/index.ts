export interface DeviceState {
    deviceId: string;
    igDid: string;
}

export interface EncryptionParams {
    keyId: string;
    publicKey: string;
    timestamp: number;
}

export interface InstagramAuthState {
    cookie: string;
    userAgent: string;
    appId: string;
    asbdId: string;
    deviceId: string;
    igDid: string;
}

export interface MediaDetail {
    id: string;
    like_count: number;
    comment_count: number;
    share_count: number;
    play_count: number;
    save_count: number;
    caption: string;
    user: any;
}

export interface LoginResult {
    authenticated: boolean;
    message?: string;
    checkpointUrl?: string;
    two_factor_info?: any;
    error?: any;
}
