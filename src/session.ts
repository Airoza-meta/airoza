import { makeInstagramSocket, InstagramClient } from './Library/Instagram';
import { updateAccountState } from './database';

export class SessionManager {
    public sessions: Map<string, InstagramClient> = new Map();

    constructor() { }

    /**
     * Get an existing session or create a new one if not exists
     */
    getSession(username: string, proxy?: string, initialState?: any): InstagramClient {
        if (!this.sessions.has(username)) {
            console.log(`[SESSION] Creating new modular client instance for ${username}`);

            const client = makeInstagramSocket({
                username,
                proxy,
                state: initialState
            });

            // Set up modular state sync using Baileys-style event
            client.on('creds.update', (state) => {
                updateAccountState(username, state);
            });

            this.sessions.set(username, client);
        }
        return this.sessions.get(username)!;
    }

    restoreSession(username: string, proxy: string | undefined, accountData: any) {
        if (this.sessions.has(username)) return;

        console.log(`[SESSION] Restoring modular session for ${username}`);

        const client = makeInstagramSocket({
            username,
            proxy,
            state: accountData
        });

        client.on('creds.update', (state) => {
            updateAccountState(username, state);
        });

        this.sessions.set(username, client);
    }

    /**
     * Check if a session is active (has user ID set implies some login success)
     */
    isLoggedIn(username: string): boolean {
        const session = this.sessions.get(username);
        return !!(session && session.getUserId());
    }

    removeSession(username: string) {
        this.sessions.delete(username);
    }

    /**
     * Creates a transient, stateless client for registration or guest actions.
     * This client is NOT tracked in the global session map.
     */
    createGuestClient(proxy?: string): InstagramClient {
        return new InstagramClient(`guest_${Date.now()}`, proxy);
    }

    getAllActiveSessions(): string[] {
        return Array.from(this.sessions.keys());
    }
}

export const sessionManager = new SessionManager();
