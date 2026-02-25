import { InstagramAccount } from './AccountHandler';
import { MediaDetail } from '../Types';

export class InstagramClient extends InstagramAccount {
    public getUserId(): string {
        return this.userId;
    }

    public getTimeOffset(): number {
        return this.serverTimeDiff;
    }

    public getDeviceState() {
        return {
            deviceId: this.deviceId,
            igDid: this.igDid
        };
    }

    /** ACCOUNT HANDLERS **/
    public async getActivityFeed(): Promise<any[]> {
        try {
            const res = await this.client.get('/api/v1/news/inbox/?activity_module=all');
            return res.data?.news_stories || [];
        } catch { return []; }
    }

    /** MEDIA HANDLERS **/
    public async getMediaDetail(mediaId: string): Promise<MediaDetail | null> {
        return this.getMediaInfo(mediaId);
    }

    public async getMediaIdFromUrl(url: string): Promise<string | null> {
        const match = url.match(/\/(p|reel|tv)\/([A-Za-z0-9_-]+)/);
        if (!match?.[2]) return null;

        const details = await this.getMediaInfo(match[2]);
        return details?.id || null;
    }

    public async getMediaInfo(urlOrShortcode: string): Promise<MediaDetail | null> {
        let shortcode = urlOrShortcode;
        const match = urlOrShortcode.match(/\/(p|reel|tv)\/([A-Za-z0-9_-]+)/);
        if (match?.[2]) shortcode = match[2];

        try {
            const res = await this.client.get(`/p/${shortcode}/?__a=1&__d=dis`);
            const item = res.data?.graphql?.shortcode_media || res.data?.items?.[0];
            if (!item) return null;
            return {
                id: item.id || item.pk,
                like_count: item.like_count || 0,
                comment_count: item.comment_count || 0,
                share_count: item.share_count || 0,
                play_count: item.play_count || item.view_count || 0,
                save_count: item.save_count || 0,
                caption: item.edge_media_to_caption?.edges?.[0]?.node?.text || item.caption?.text || '',
                user: item.owner || item.user
            };
        } catch { return null; }
    }

    public async likeMedia(mediaId: string, _url?: string): Promise<boolean> {
        try {
            const res = await this.client.post(`/api/v1/web/likes/${mediaId}/like/`, '', {
                headers: { 'x-csrftoken': this.csrfToken }
            });
            return res.data.status === 'ok';
        } catch { return false; }
    }

    /** USER HANDLERS **/
    public async followUser(userId: string, _username?: string): Promise<boolean> {
        try {
            const res = await this.client.post(`/api/v1/web/friendships/${userId}/follow/`, '', {
                headers: { 'x-csrftoken': this.csrfToken }
            });
            return res.data.status === 'ok';
        } catch { return false; }
    }

    public async unfollowUser(userId: string, _username?: string): Promise<boolean> {
        try {
            const res = await this.client.post(`/api/v1/web/friendships/${userId}/unfollow/`, '', {
                headers: { 'x-csrftoken': this.csrfToken }
            });
            return res.data.status === 'ok';
        } catch { return false; }
    }

    /** INTERACTION HANDLERS **/
    public async commentMedia(mediaId: string, text: string, repliedToCommentId?: string): Promise<boolean> {
        try {
            const params = new URLSearchParams();
            params.append('comment_text', text);
            if (repliedToCommentId) {
                params.append('replied_to_comment_id', repliedToCommentId);
            }
            const res = await this.client.post(`/api/v1/web/comments/${mediaId}/add/`, params.toString(), {
                headers: { 'x-csrftoken': this.csrfToken }
            });
            return res.data.status === 'ok';
        } catch { return false; }
    }

    public async getMediaComments(mediaId: string): Promise<any[]> {
        try {
            const res = await this.client.get(`/api/v1/web/comments/${mediaId}/all/`);
            return res.data?.comments || [];
        } catch { return []; }
    }

    /** SEARCH & INFO HANDLERS **/
    public async searchUser(query: string): Promise<any[]> {
        try {
            const res = await this.client.get(`/api/v1/web/search/topsearch/?context=blended&query=${query}&rank_token=0.1`);
            return res.data?.users || [];
        } catch { return []; }
    }

    public async getUserDetailExtended(username: string): Promise<any> {
        try {
            const res = await this.client.get(`/api/v1/users/web_profile_info/?username=${username}`);
            return res.data?.data?.user;
        } catch { return null; }
    }
}

export const makeInstagramSocket = (config: { username: string, proxy?: string | undefined, state?: any }) => {
    return new InstagramClient(config.username, config.proxy, config.state);
};
