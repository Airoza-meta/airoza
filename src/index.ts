import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import axios from 'axios';
import { CONFIG } from './config';
import {
    initDb, addAccount, getAllAccounts, deleteAccount, getAccount,
    onAccountChange, logAction, getUser, addUser, getAccountsByOwner,
    updateAccountState, updateUserCredits, generateNewApiKey, getUserByApiKey,
    getAllAutomationTasks, addOrder, getOrdersByUser, pruneOldOrders
} from './database';
import { OrderManager } from './orders';
import { sessionManager } from './session';
import { automationService } from './automation';
import { MailService } from './mail';
import { generateIdentity, generateTOTP } from './utils';
import pushWebhook from './webhook_service';
import multer from 'multer';

const upload = multer({ storage: multer.memoryStorage() });
const app = express();
const PORT = process.env.PORT || 3000;
const orderManager = new OrderManager(sessionManager);

process.on('uncaughtException', (err) => console.error('[SYSTEM] Uncaught Exception:', err));
process.on('unhandledRejection', (reason) => console.error('[SYSTEM] Unhandled Rejection:', reason));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

app.use((req, res, next) => {
    console.log(`[REQ] ${req.method} ${req.url}`);
    next();
});

// --- HELPERS ---

const syncingUsers = new Set<string>();

async function syncProfile(username: string) {
    if (!username || username === 'undefined') {
        console.warn(`[SYNC] Aborted: Username is ${username}`);
        return;
    }
    if (syncingUsers.has(username)) return;
    syncingUsers.add(username);

    try {
        const bot = sessionManager.getSession(username);
        if (!bot) return;

        console.log(`[SYNC] Starting identity synchronization for ${username}`);
        const profile = await bot.getProfile();

        if (profile) {
            const limits = await bot.getNeuralTrustLimits();

            // Fetch extra stats (followers, following)
            let followers = 0;
            let following = 0;
            try {
                const userDetail = await bot.getUserMedia(username);
                if (userDetail) {
                    followers = userDetail.edge_followed_by?.count ?? userDetail.follower_count ?? 0;
                    following = userDetail.edge_follow?.count ?? userDetail.following_count ?? 0;
                }
            } catch (e) {
                console.warn(`[SYNC] Could not fetch follower stats for ${username}`);
            }

            await updateAccountState(username, {
                profile_pic_url: profile.profile_pic_base64 || profile.profile_pic_url,
                full_name: profile.first_name || profile.full_name,
                biography: profile.biography,
                trust_limits: limits,
                followers_count: followers,
                following_count: following
            });
            console.log(`[SYNC] Identity, Stats (${followers} followers), and Neural Limits synchronized for ${username}`);
        }
    } catch (e: any) {
        console.error(`[SYNC] Failed for ${username}:`, e.message);
        const errData = e.response?.data;
        if (errData?.message === 'feedback_required' || e.response?.status === 400) {
            await updateAccountState(username, {
                last_error: 'Rate Limited (400)',
                status_note: 'Cooling Down...'
            });
        }
    } finally {
        syncingUsers.delete(username);
    }
}

// --- AUTH MIDDLEWARE ---

const requireAuth = async (req: Request, res: Response, next: () => void) => {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;

    if (apiKey) {
        const user = await getUserByApiKey(apiKey as string);
        if (user) {
            (req as any).user = user;
            return next();
        }
    }

    const token = req.query.token || (authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null);
    if (!token) return res.status(401).json({ error: 'Identity verification required' });

    const parts = (token as string).split('-');
    if (parts.length < 5) return res.status(401).json({ error: 'Invalid or legacy session format' });

    const timestampPart = parts[4];
    const timestamp = timestampPart ? parseInt(timestampPart) : 0;
    const now = Date.now();
    const tenHours = 10 * 60 * 60 * 1000;

    if (isNaN(timestamp) || (now - timestamp) > tenHours) {
        return res.status(401).json({ error: 'Session expired due to 10h inactivity' });
    }

    const username = parts[2] as string;
    const role = parts[3] as string;
    const user = await getUser(username);
    if (!user) return res.status(401).json({ error: 'User not found' });

    // Sliding Expiration: Provide a refreshed token in headers
    const newToken = `v1-session-${username}-${role}-${now}`;
    res.setHeader('x-refresh-token', newToken);

    (req as any).user = user;
    next();
};

const deductCredit = (amount: number) => async (req: Request, res: Response, next: () => void) => {
    const user = (req as any).user;
    if (user.role === 'admin') return next();

    const success = await updateUserCredits(user.username, -amount);
    if (!success) return res.status(402).json({ error: 'Insufficient credits (Payment Required)' });
    next();
};

const requireAccountOwnership = async (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    const username = req.params?.username || req.body?.username || req.body?.botUsername;

    if (!username) return res.status(400).json({ error: 'Username/Bot Handle required for authorization' });
    if (user.role === 'admin') return next();

    try {
        const account = await getAccount(username);
        if (!account) return res.status(404).json({ error: 'Node not found' });
        if (account.ownerId !== user.username) {
            return res.status(403).json({ error: 'Strategic Denial: You do not own this neural node' });
        }
        next();
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
};

// --- CORE ROUTES ---

app.get('/', (req, res) => res.json({ status: 'ok', message: 'Airoza Neural Engine Active' }));

// --- MULTI-USER AUTH ---

app.get('/auth/me', requireAuth, (req, res) => {
    res.json({ status: 'success', user: (req as any).user });
});

app.post('/auth/generate-key', requireAuth, async (req, res) => {
    const user = (req as any).user;
    const newKey = await generateNewApiKey(user.username);
    res.json({ status: 'success', apiKey: newKey });
});

app.post('/auth/register', async (req, res) => {
    const { username, password, proxy } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const existing = await getUser(username);
    if (existing) return res.status(400).json({ error: 'User identity already exists' });

    try {
        const isAdmin = username.toLowerCase() === 'admin';
        const created = await addUser({ username, password, role: isAdmin ? 'admin' : 'user' });
        if (!created) return res.status(500).json({ error: 'Failed to create user identity' });

        if (isAdmin) {
            return res.json({
                status: 'success',
                message: 'Admin identity established.',
                token: `v1-session-${username}-admin-${Date.now()}`,
                role: 'admin',
                username: username
            });
        }

        const result = await performSmartLogin(username, password, proxy, undefined, username);

        if (result.status === 'checkpoint') {
            const isSuspended = result.checkpointUrl?.includes('suspended');
            return res.status(401).json({
                status: 'checkpoint',
                error: isSuspended ? 'Instagram account is suspended.' : 'Security Checkpoint detected.',
                message: isSuspended ? 'This account cannot be used as it is suspended by Instagram.' : 'Please resolve the checkpoint on your device or try logging in again to trigger verification.',
                checkpointUrl: result.checkpointUrl
            });
        }

        if (result.status === 'error') {
            return res.status(401).json({
                status: 'error',
                error: `Instagram Authentication Failed: ${result.message}`
            });
        }

        const user = await getUser(username);
        if (!user) throw new Error('User synchronization failed after creation.');

        res.json({
            status: 'success',
            message: 'Registration successful. Instagram node linked.',
            token: `v1-session-${user.username}-${user.role}-${Date.now()}`,
            role: user.role,
            username: user.username,
            ...result
        });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await getUser(username);

    if (user && user.password === password) {
        if (user.role === 'admin') {
            return res.json({
                status: 'success',
                token: `v1-session-${user.username}-${user.role}-${Date.now()}`,
                role: user.role,
                username: user.username,
                credits: user.credits
            });
        }

        try {
            // Re-verify Instagram status on login to ensure node is healthy
            const result = await performSmartLogin(username, password, undefined, undefined, username);

            if (result.status === 'checkpoint') {
                const isSuspended = result.checkpointUrl?.includes('suspended');
                return res.status(401).json({
                    status: 'checkpoint',
                    error: isSuspended ? 'Instagram account is suspended.' : 'Security Checkpoint detected.',
                    message: isSuspended ? 'This account is suspended and cannot be used.' : 'Please resolve the checkpoint on your device then try again.',
                    checkpointUrl: result.checkpointUrl
                });
            }

            if (result.status === 'error') {
                return res.status(401).json({
                    status: 'error',
                    error: `Instagram Authentication Error: ${result.message}`
                });
            }

            res.json({
                status: 'success',
                token: `v1-session-${user.username}-${user.role}-${Date.now()}`,
                role: user.role,
                username: user.username,
                credits: user.credits,
                ...result
            });
        } catch (e: any) {
            res.status(500).json({ error: `Login verification failed: ${e.message}` });
        }
    } else {
        res.status(401).json({ error: 'Invalid platform credentials' });
    }
});

// --- ACCOUNT MGMT ---

app.get('/accounts', requireAuth, async (req, res) => {
    const { ownerId, role } = req.query;
    const user = (req as any).user;
    try {
        // SECURITY: Non-admins can NEVER see accounts owned by others
        const effectiveOwner = (user.role === 'admin') ? (ownerId as string || user.username) : user.username;
        let accounts = (user.role === 'admin') ? await getAllAccounts() : await getAccountsByOwner(effectiveOwner);
        const activeSessions = sessionManager.getAllActiveSessions();
        const result = accounts.map((acc: any) => ({
            ...acc,
            is_active: activeSessions.includes(acc.username),
            daily_counts: acc.daily_stats || { likes: 0, follows: 0, comments: 0, posts: 0 },
            trust_limits: acc.neural_limits || { likes: 50, follows: 30, comments: 15, posts: 5 }
        }));
        res.json({ status: 'success', accounts: result });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/accounts', requireAuth, async (req, res) => {
    const { username, password, proxy, webhook, ownerId } = req.body;
    const user = (req as any).user;
    const owner = user.role === 'admin' ? (ownerId || user.username) : user.username;

    if (!username) return res.status(400).json({ error: 'Username required' });
    try {
        // Verification: If account exists, check ownership before re-adding/updating
        const existing = await getAccount(username);
        if (existing && existing.ownerId !== owner && user.role !== 'admin') {
            return res.status(403).json({ error: 'Identity Collision: This account is already managed by another user' });
        }

        await addAccount(username, password, proxy, webhook, owner);
        res.json({ status: 'success', message: `Account ${username} saved.` });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.patch('/accounts/:username', requireAuth, requireAccountOwnership, async (req, res) => {
    const username = req.params.username as string;
    const updates = req.body;
    try {
        await updateAccountState(username, updates);
        res.json({ status: 'success' });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/accounts/:username', requireAuth, requireAccountOwnership, async (req, res) => {
    const username = req.params.username as string;
    try {
        sessionManager.removeSession(username);
        const success = await deleteAccount(username);
        res.json({ status: success ? 'success' : 'error', message: success ? 'Deleted' : 'Not found' });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/accounts/bulk-delete', requireAuth, async (req, res) => {
    const { usernames } = req.body;
    const user = (req as any).user;
    if (!Array.isArray(usernames) || usernames.length === 0) {
        return res.status(400).json({ error: 'Array of usernames required' });
    }
    try {
        const adminMode = user.role === 'admin';
        for (const username of usernames) {
            if (!adminMode) {
                const acc = await getAccount(username);
                if (!acc || acc.ownerId !== user.username) continue; // Skip unauthorized
            }
            sessionManager.removeSession(username);
            await deleteAccount(username);
        }
        res.json({ status: 'success', message: `Accounts decommissioned.` });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/auth/instagram-logout', requireAuth, requireAccountOwnership, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    try {
        await revokeRewardIfApplicable(username);
        automationService.stopTask(username);
        sessionManager.removeSession(username);
        res.json({ status: 'success', message: 'Logged out' });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

// --- ORDERS ---

app.post('/api/orders/create', requireAuth, async (req, res) => {
    const { type, target, quantity, comments } = req.body;
    const user = (req as any).user;

    if (!type || !target || !quantity) return res.status(400).json({ error: 'Missing required fields' });

    // Pricing Reduced (1/10)
    const costPerItem = type === 'COMMENT' ? 0.05 : 0.01;
    const totalCost = quantity * costPerItem;

    if (user.role !== 'admin' && (user.credits || 0) < totalCost) {
        return res.status(402).json({ error: 'Insufficient credits' });
    }

    const orderId = await addOrder({
        user_id: user.username,
        type,
        target,
        quantity,
        comments,
        cost: totalCost,
        cost_per_item: costPerItem
    });

    if (orderId) {
        if (user.role !== 'admin') {
            await updateUserCredits(user.username, -totalCost);
        }
        res.json({ status: 'success', orderId });
    } else {
        res.status(500).json({ error: 'Failed to create order' });
    }
});

app.get('/api/orders/history', requireAuth, async (req, res) => {
    const user = (req as any).user;
    const orders = await getOrdersByUser(user.username);
    res.json({ status: 'success', orders });
});

app.post('/api/orders/bulk', requireAuth, async (req, res) => {
    const { orders } = req.body; // Array of { type, target, quantity, comments }
    const user = (req as any).user;

    if (!Array.isArray(orders)) return res.status(400).json({ error: 'Orders must be an array' });

    let successCount = 0;
    for (const ord of orders) {
        const costPerItem = ord.type === 'COMMENT' ? 0.05 : 0.01;
        const totalCost = ord.quantity * costPerItem;

        if (user.role !== 'admin' && (user.credits || 0) < totalCost) continue;

        const orderId = await addOrder({
            user_id: user.username,
            ...ord,
            cost: totalCost,
            cost_per_item: costPerItem
        });

        if (orderId) {
            if (user.role !== 'admin') {
                await updateUserCredits(user.username, -totalCost);
                user.credits -= totalCost; // Update local for next iteration
            }
            successCount++;
        }
    }

    res.json({ status: 'success', created: successCount });
});

// --- INSTAGRAM ACTIONS ---

const getBotOrError = (res: Response, username?: string) => {
    if (!username) { res.status(400).json({ error: 'botUsername required' }); return null; }
    if (!sessionManager.isLoggedIn(username)) { res.status(401).json({ error: `Bot ${username} not logged in` }); return null; }
    return sessionManager.getSession(username);
};

app.get('/auth/sessions', requireAuth, (req, res) => {
    res.json({ status: 'success', sessions: sessionManager.getAllActiveSessions() });
});

// --- HELPER: Handle Bot Action Errors & Update DB ---
async function handleBotActionError(botUsername: string, error: any, res: Response) {
    const msg = error.message || 'Unknown error';
    console.error(`[ACTION_ERROR] ${botUsername}: ${msg}`);

    if (msg === 'IG_SUSPENDED') {
        await updateAccountState(botUsername, { status_note: 'SUSPENDED', last_error: 'Account suspended by Instagram', is_active: false });
        return res.status(403).json({ error: 'Account Suspended', code: 'SUSPENDED' });
    }
    if (msg.startsWith('IG_CHECKPOINT')) {
        const url = msg.split(':')[1];
        await updateAccountState(botUsername, { status_note: 'CHECKPOINT', last_error: 'Security checkpoint required', is_active: false });
        return res.status(403).json({ error: 'Security Checkpoint Required', checkpointUrl: url, code: 'CHECKPOINT' });
    }
    if (msg.startsWith('IG_LIMIT_EXCEEDED')) {
        const reason = msg.split(':')[1];
        await updateAccountState(botUsername, { last_error: `Action Limit: ${reason}` });
        return res.status(429).json({ error: 'Action Limit Exceeded', reason, code: 'LIMIT' });
    }
    if (msg === 'IG_SESSION_EXPIRED') {
        await updateAccountState(botUsername, { status_note: 'EXPIRED', last_error: 'Session expired or invalid', is_active: false });
        sessionManager.removeSession(botUsername); // Clear from memory
        return res.status(401).json({ error: 'Session Expired', code: 'EXPIRED' });
    }

    res.status(500).json({ error: msg });
}

// --- REUSABLE LOGIN LOGIC ---
async function performSmartLogin(username: string, password?: string, proxy?: string, webhook?: string, ownerId?: string, twoFactorSecret?: string, bypassSessionCheck = false) {
    const account = await getAccount(username);
    const targetPassword = password || account?.password;
    if (!targetPassword) throw new Error('Password required for login');

    const targetProxy = proxy !== undefined ? proxy : account?.proxy;
    const targetWebhook = webhook !== undefined ? webhook : account?.webhook;
    const targetOwner = ownerId || account?.ownerId || 'admin';
    const targetSecret = twoFactorSecret || account?.two_factor_secret;

    const bot = sessionManager.getSession(username, targetProxy, account);

    // PERSIST IMMEDIATELY: Ensure the login account is always in the 'accounts' database
    await addAccount(username, targetPassword, targetProxy, targetWebhook, targetOwner, targetSecret);

    // 1. Session Recovery Attempt
    if (!bypassSessionCheck && account?.cookie) {
        console.log(`[LOGIN] Recovering existing session for ${username}...`);
        const isValid = await bot.verifySession();
        if (isValid) {
            console.log(`[LOGIN] Session for ${username} is still valid.`);
            await updateAccountState(username, { last_error: null, status_note: 'Active and Linked', is_active: true });
            await syncProfile(username);
            return { status: 'success', message: 'Session restored', recovered: true };
        }
    }

    // 2. Full Password Login
    const result = await bot.login(username, targetPassword);

    if (result.authenticated) {

        // SMART REWARD: +1 Credit per account, once. Clawback if < 24h active.
        const wasActive = account?.is_active === true;
        let awarded = 0;
        if (!account?.reward_claimed && !account?.reward_revoked) {
            await updateUserCredits(targetOwner, 1);
            awarded = 1;
            console.log(`[CREDITS] Awarded +1 to ${targetOwner} for ${username}. 24h clock started.`);
            await updateAccountState(username, {
                reward_claimed: true,
                reward_at: Date.now()
            });
        }

        await updateAccountState(username, { last_error: null, status_note: 'Active and Linked', is_active: true });
        await syncProfile(username);
        return { status: 'success', message: 'Logged in and saved', creditsAwarded: awarded };
    }

    if (result.checkpointUrl) {

        // If it was active and now hit checkpoint/suspend, revoke if < 24h
        if (account?.is_active) await revokeRewardIfApplicable(username);

        const isSuspended = result.checkpointUrl.includes('suspended');
        await updateAccountState(username, {
            last_error: isSuspended ? 'Account Suspended' : 'Checkpoint Required',
            status_note: isSuspended ? 'SUSPENDED' : 'CHECKPOINT',
            checkpoint_url: result.checkpointUrl,
            is_active: false
        });
        return { status: 'checkpoint', checkpointUrl: result.checkpointUrl };
    }

    if (result.message === 'two_factor_required') {
        if (targetSecret) {
            const timeOffset = bot.getTimeOffset();
            console.log(`[LOGIN] Auto-resolving 2FA for ${username}...`);
            const code = generateTOTP(targetSecret, Date.now() + timeOffset);
            if (code) {
                const tfResult = await bot.verifyTwoFactor(code, result.two_factor_info);
                if (tfResult.authenticated) {

                    // SMART REWARD: Same for 2FA Bypass
                    let awarded = 0;
                    if (!account?.reward_claimed && !account?.reward_revoked) {
                        await updateUserCredits(targetOwner, 1);
                        awarded = 1;
                        await updateAccountState(username, { reward_claimed: true, reward_at: Date.now() });
                    }

                    await updateAccountState(username, { last_error: null, status_note: 'Active (2FA Bypass)', is_active: true });
                    await syncProfile(username);
                    return { status: 'success', message: 'Logged in via Automated 2FA', creditsAwarded: awarded };
                }
            }
        }
    }

    const errorMsg = result.message || 'Unknown authentication error';

    // If it was active and now failed, check for reward revocation
    if (account?.is_active) await revokeRewardIfApplicable(username);

    await updateAccountState(username, { last_error: errorMsg, status_note: 'Auth Failed', is_active: false });
    return { status: 'error', message: errorMsg, ...result };
}

async function revokeRewardIfApplicable(username: string) {
    const acc = await getAccount(username) as any;
    if (acc?.reward_claimed && !acc?.reward_revoked) {
        const ageHours = (Date.now() - (acc.reward_at || 0)) / (1000 * 3600);
        if (ageHours < 24) {
            const owner = acc.ownerId || 'admin';
            console.log(`[CREDITS] Clawback: Revoking reward from ${owner} for ${username} (Active < 24h)`);
            await updateUserCredits(owner, -1);
            await updateAccountState(username, {
                reward_claimed: false,
                reward_revoked: true,
                status_note: (acc.status_note || '') + ' (Reward Revoked)'
            });
        }
    }
}

async function startSessionSentinel() {
    console.log('[SENTINEL] Initializing Global Session Protector...');

    setInterval(async () => {
        try {
            const accounts = await getAllAccounts() as any[];
            console.log(`[SENTINEL] Scanning ${accounts.length} potential nodes for session health...`);

            for (const acc of accounts) {
                // Only watch accounts that were supposed to be active
                if (acc.is_active && acc.cookie && acc.password) {
                    const bot = sessionManager.getSession(acc.username, acc.proxy, acc);
                    const isValid = await bot.verifySession();

                    if (!isValid) {
                        console.warn(`[SENTINEL] Detected dead session for ${acc.username}. Triggering Auto-Recovery...`);
                        try {
                            const recovery = await performSmartLogin(acc.username, acc.password, acc.proxy, acc.webhook, acc.ownerId, acc.two_factor_secret, true);
                            if (recovery.status === 'success') {
                                console.log(`[SENTINEL] Auto-Recovery SUCCESS for ${acc.username}. Session restored.`);
                            } else {
                                console.error(`[SENTINEL] Auto-Recovery FAILED for ${acc.username}: ${recovery.message}`);
                            }
                        } catch (err: any) {
                            console.error(`[SENTINEL] Critical error during recovery of ${acc.username}:`, err.message);
                        }
                    }

                    // Small stagger to avoid network spikes
                    await new Promise(r => setTimeout(r, 2000));
                }
            }
        } catch (e: any) {
            console.error('[SENTINEL] Runner error:', e.message);
        }
    }, 900000); // Pulse every 15 minutes
}

async function startHistorySentinel() {
    console.log('[SENTINEL] Initializing Order History Pruner (7-Day Policy)...');

    // Run once on startup
    await pruneOldOrders(7).catch(e => console.error('[SENTINEL] Initial prune failed:', e.message));

    // Then run every 24 hours
    setInterval(async () => {
        try {
            await pruneOldOrders(7);
        } catch (e: any) {
            console.error('[SENTINEL] History Pruner Error:', e.message);
        }
    }, 86400000); // 24 Hours
}

app.post('/auth/instagram-login', requireAuth, async (req, res) => {
    const { username, password, proxy, webhook, ownerId, twoFactorSecret } = req.body;
    try {
        const result = await performSmartLogin(username, password, proxy, webhook, ownerId, twoFactorSecret);
        if (result.status === 'checkpoint') {
            return res.status(401).json(result);
        }
        if (result.status === 'error') {
            return res.status(401).json(result);
        }
        res.json(result);
    } catch (e: any) {
        console.error(`[LOGIN-API] Error for ${username}:`, e.message);
        res.status(500).json({ error: e.message });
    }
});

app.post('/auth/instagram-2fa', requireAuth, requireAccountOwnership, async (req, res) => {
    const { username, code, twoFactorIdentifier, method } = req.body;
    if (!username || !code || !twoFactorIdentifier) {
        return res.status(400).json({ error: 'Username, code, and identifier required' });
    }

    try {
        const bot = sessionManager.getSession(username);
        if (!bot) return res.status(404).json({ error: 'Bot session not found' });

        const result = await bot.verifyTwoFactor(code, {
            two_factor_identifier: twoFactorIdentifier,
            method: method || '1'
        });
        if (result.authenticated) {
            await updateAccountState(username, { last_error: null, status_note: 'Active and Linked' });
            await syncProfile(username);
            res.json({ status: 'success', message: '2FA Verified' });
        } else {
            res.status(401).json({ status: 'error', message: result.message || '2FA Failed' });
        }
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/auth/challenge-send-otp', requireAuth, requireAccountOwnership, async (req, res) => {
    const { username, checkpointUrl, choice } = req.body;
    try {
        const bot = sessionManager.getSession(username);
        if (!bot) return res.status(404).json({ error: 'Bot session not found' });
        const result = await bot.sendChallengeOTP(checkpointUrl, choice || '1');
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/auth/challenge-submit-code', requireAuth, requireAccountOwnership, async (req, res) => {
    const { username, checkpointUrl, code } = req.body;
    try {
        const bot = sessionManager.getSession(username);
        if (!bot) return res.status(404).json({ error: 'Bot session not found' });
        const result = await bot.submitChallengeCode(checkpointUrl, code);
        if (result.success) {
            await updateAccountState(username, { last_error: null, status_note: 'Active and Linked' });
            await syncProfile(username);
        }
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/upload-profile-pic', requireAuth, upload.single('image'), requireAccountOwnership, async (req, res) => {
    const { botUsername } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot || !req.file) return res.status(400).json({ error: 'Bot and Image required' });

    try {
        const success = await bot.changeProfilePicture(req.file.buffer);
        if (success) await syncProfile(botUsername);
        res.json({ status: success ? 'success' : 'error' });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.post('/api/post', requireAuth, upload.single('image'), requireAccountOwnership, async (req, res) => {
    const { botUsername, caption } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot || !req.file) return res.status(400).json({ error: 'Bot and Image required' });

    try {
        const media = await bot.uploadPhoto(req.file.buffer, caption || '');
        if (media) await logAction(botUsername, 'POST', { mediaId: media.id, caption }, 'SUCCESS');
        res.json({ status: media ? 'success' : 'error', media });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.post('/api/update-status', requireAuth, requireAccountOwnership, async (req, res) => {
    const { botUsername, text } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot) return;

    try {
        const data = await bot.updateStatus(text);
        if (data) await logAction(botUsername, 'STATUS_UPDATE', { text }, 'SUCCESS');
        res.json({ status: 'success', data });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.post('/api/sync-profile', requireAuth, requireAccountOwnership, async (req, res) => {
    const { botUsername } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot) return;
    try {
        if (bot) await syncProfile(botUsername);
        res.json({ status: 'success' });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.get('/search', requireAuth, async (req, res) => {
    const { q, botUsername } = req.query;
    const bot = getBotOrError(res, botUsername as string);
    if (!bot) return;
    try {
        const result = await bot.searchUser(q as string);
        const users = result?.data?.xdt_api__v1__fbsearch__topsearch_connection?.users.map((u: any) => ({
            username: u.user.username,
            pk: u.user.pk,
            full_name: u.user.full_name
        })) || [];
        res.json({ status: 'success', users });
    } catch (e: any) {
        await handleBotActionError(botUsername as string, e, res);
    }
});

app.post('/api/follow', requireAuth, requireAccountOwnership, deductCredit(0.1), async (req, res) => {
    const { botUsername, targetUsername } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot) return;
    try {
        const user = await bot.getUserMedia(targetUsername);
        const success = await bot.followUser(user.id);
        if (success) await logAction(botUsername, 'FOLLOW', { target: targetUsername }, 'SUCCESS');
        res.json({ status: success ? 'success' : 'error' });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.post('/api/like', requireAuth, requireAccountOwnership, deductCredit(0.1), async (req, res) => {
    const { botUsername, targetUsername, mediaId } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot) return;
    try {
        let tid = mediaId;
        if (tid && tid.includes('http')) tid = await bot.getMediaIdFromUrl(tid);
        if (!tid) return res.status(400).json({ error: 'Could not resolve Media ID from URL or User feed' });

        const success = await bot.likeMedia(tid);
        if (success) await logAction(botUsername, 'LIKE', { mediaId: tid }, 'SUCCESS');
        res.json({ status: success ? 'success' : 'error', mediaId: tid });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

app.post('/api/comment', requireAuth, requireAccountOwnership, deductCredit(0.2), async (req, res) => {
    const { botUsername, targetUsername, mediaId, text, replyToId } = req.body;
    const bot = getBotOrError(res, botUsername);
    if (!bot) return;
    try {
        let tid = mediaId;
        if (tid && tid.includes('http')) tid = await bot.getMediaIdFromUrl(tid);

        if (!tid && targetUsername) {
            const user = await bot.getUserMedia(targetUsername);
            tid = user.edge_owner_to_timeline_media.edges[0].node.id;
        }

        if (!tid) return res.status(400).json({ error: 'Could not resolve Media ID' });

        const success = await bot.commentMedia(tid, text, replyToId);
        if (success) await logAction(botUsername, 'COMMENT', { mediaId: tid, text, replyToId }, 'SUCCESS');
        res.json({ status: success ? 'success' : 'error', mediaId: tid });
    } catch (e: any) {
        await handleBotActionError(botUsername, e, res);
    }
});

// --- AUTOMATION ---

app.post('/auto/start', requireAuth, requireAccountOwnership, (req, res) => {
    const { botUsername, targets, intervalMinutes, type } = req.body;
    if (!botUsername || !targets) return res.status(400).json({ error: 'botUsername and targets required' });
    if (!sessionManager.isLoggedIn(botUsername)) return res.status(401).json({ error: 'Bot not logged in' });
    const taskType = type === 'FOLLOW' ? 'AUTO_FOLLOW_TARGETS' : 'AUTO_LIKE_TARGETS';
    automationService.startTask(botUsername, taskType, targets, intervalMinutes || 10);
    res.json({ status: 'success' });
});

app.get('/auto/tasks', requireAuth, (req, res) => {
    const user = (req as any).user;
    const allTasks = automationService.getAllTasks();

    // Filter tasks if not admin
    const filteredTasks = (user.role === 'admin')
        ? allTasks
        : allTasks.filter(t => {
            // Check if the bot being automated belongs to the user
            const session = sessionManager.sessions.get(t.botUsername);
            return session?.ownerId === user.username;
        });

    res.json({ status: 'success', tasks: filteredTasks });
});

app.post('/auto/stop', requireAuth, requireAccountOwnership, (req, res) => {
    const { botUsername } = req.body;
    const stopped = automationService.stopTask(botUsername);
    res.json({ status: stopped ? 'success' : 'error' });
});

app.post('/auth/forge-account', requireAuth, async (req, res) => {
    const { parentUsername } = req.body;
    const userRole = (req as any).user?.role;

    if (userRole?.toLowerCase() !== 'admin') {
        return res.status(403).json({ error: 'Only admins can forge new nodes' });
    }

    try {
        const anchorBot = sessionManager.getSession(parentUsername);
        if (!anchorBot) return res.status(404).json({ error: 'Anchor Node (parent session) not found. Login a bot first.' });

        console.log(`[FORGE] Initiating Secondary Identity Forge (Accounts Center Strategy)...`);

        // 1. Generate Identity
        const identity = generateIdentity();
        console.log(`[FORGE] Forging new identity: @${identity.username} (${identity.fullName})`);

        const parentPk = anchorBot.getUserId();
        const forgeRes = await anchorBot.createAdditionalAccount(identity.username, identity.password);

        if (!forgeRes.success) {
            throw new Error(forgeRes.message || 'Accounts Center Forge failed.');
        }

        let newUserPk = forgeRes.user?.pk || forgeRes.user?.id;
        if (newUserPk === parentPk) {
            console.warn(`[FORGE] ID Collision detected. Extracted ID is parent's ID (${parentPk}). Marking as pending.`);
            newUserPk = 'pending';
        }

        console.log(`[FORGE] Identity Forged Successfully! New Node: @${identity.username} (ID: ${newUserPk})`);

        // 3. Registry & Session Setup
        const forgedCookies = anchorBot.getCookieString();
        const deviceState = anchorBot.getDeviceState();
        let twoFactorSecret = '';

        // --- NEW: AUTO-ENABLE 2FA ---
        console.log(`[FORGE] Auto-enabling 2FA for @${identity.username}...`);
        const seedRes = await anchorBot.getTOTPSeed();
        if (seedRes.success && seedRes.seed) {
            twoFactorSecret = seedRes.seed;
            // Generate verification code
            const timeOffset = anchorBot.getTimeOffset();
            const code = generateTOTP(twoFactorSecret, Date.now() + timeOffset);

            if (code) {
                const enableRes = await anchorBot.enableTwoFactorTOTP(code, seedRes.identifier);
                if (enableRes.success) {
                    console.log(`[FORGE] 2FA Enabled and Secret captured for @${identity.username}`);
                } else {
                    console.warn(`[FORGE] 2FA Enablement failed: ${enableRes.message}`);
                    twoFactorSecret = ''; // Clear if failed to enable
                }
            }
        } else {
            console.warn(`[FORGE] Could not get TOTP seed: ${seedRes.message}`);
        }

        await addAccount(
            identity.username,
            identity.password,
            anchorBot.getProxy?.() || '',
            undefined, // No webhook for forged account initially
            (req as any).user?.username || 'admin',
            twoFactorSecret,
            forgedCookies // <--- Correct: 7th argument is the session cookie
        );

        // Stamp metadata
        await updateAccountState(identity.username, {
            ...deviceState,
            two_factor_secret: twoFactorSecret,
            date_joined: Math.floor(Date.now() / 1000),
            account_age_days: 0,
            status_note: 'Freshly Forged (Linked)',
            full_name: identity.fullName
        });

        res.json({
            status: 'success',
            message: 'Identity Forged via Accounts Center',
            account: {
                username: identity.username,
                password: identity.password,
                user_id: newUserPk
            }
        });

        // Success response was sent above.
        // Optional: Perform async background polish (avatar/2fa) after first login
    } catch (e: any) {
        console.error(`[FORGE] Forge Logic failed:`, e.message);
        if (!res.headersSent) {
            res.status(500).json({ status: 'error', error: e.message });
        }
    }
});

app.get('/api/comments/:mediaId', requireAuth, async (req, res) => {
    const { botUsername } = req.query;
    const { mediaId } = req.params;
    const bot = getBotOrError(res, botUsername as string);
    if (!bot) return;
    try {
        let tid = mediaId;
        if (tid && tid.includes('http')) tid = await bot.getMediaIdFromUrl(tid);
        const comments = await bot.getMediaComments(tid);
        res.json({ status: 'success', comments });
    } catch (e: any) {
        await handleBotActionError(botUsername as string, e, res);
    }
});

app.post('/auth/bulk-import', requireAuth, async (req, res) => {
    const { data } = req.body;
    if (!data) return res.status(400).json({ status: 'error', error: 'No data provided' });

    const lines = data.split('\n').map((l: string) => l.trim()).filter((l: string) => l);
    const results = { success: 0, failed: 0 };

    for (const line of lines) {
        try {
            const parts = line.split(':');
            if (parts.length < 2) {
                results.failed++;
                continue;
            }

            const username = parts[0];
            const password = parts[1];
            let proxy = '';
            let twoFactorSecret = '';

            if (parts.length >= 3) {
                const lastPart = parts[parts.length - 1];
                // Check if last part is a 2FA secret (typically 32 or 16 chars Base32)
                const is2FA = /^[A-Z2-7]{16,32}$/i.test(lastPart);

                if (is2FA) {
                    twoFactorSecret = lastPart.toUpperCase();
                    // Proxy is everything between password and 2fa
                    proxy = parts.slice(2, -1).join(':');
                } else {
                    // No 2FA at the end, everything from part 2 onwards is proxy
                    proxy = parts.slice(2).join(':');
                }
            }

            // Cleanup proxy: if it starts with 'http', don't add extra colons if we re-joined incorrectly
            // Actually parts.slice(2, -1).join(':') will preserve the 'http://' correctly.

            const success = await addAccount(
                username,
                password,
                proxy || undefined,
                '',
                (req as any).user?.username || 'admin',
                twoFactorSecret || undefined
            );

            if (success) {
                results.success++;
                console.log(`[BULK] Imported Node: @${username}`);
            } else {
                results.failed++;
            }
        } catch (e: any) {
            results.failed++;
            console.error(`[BULK] Parse error for line: ${line} -> ${e.message}`);
        }
    }

    res.json({
        status: 'success',
        message: `Bulk Import sequence completed.`,
        summary: results
    });
});

// --- INITIALIZATION ---

async function start() {
    await initDb();
    const existingAdmin = await getUser('admin');
    if (!existingAdmin) await addUser({ username: 'admin', password: 'admin123', role: 'admin' });

    const accounts = await getAllAccounts() as any[];
    for (const acc of accounts) {
        if (acc.cookie) {
            sessionManager.restoreSession(acc.username, acc.proxy, acc);
            if (sessionManager.isLoggedIn(acc.username)) {
                syncProfile(acc.username).catch(e => console.error(`[INIT-SYNC] Failed for ${acc.username}:`, e.message));
            }
        }
    }

    const tasks = await getAllAutomationTasks();
    for (const t of tasks) {
        if (t.isRunning && sessionManager.isLoggedIn(t.botUsername)) {
            automationService.startTask(t.botUsername, t.type, t.targets, t.intervalMs / 60000, t.webhookUrl);
        }
    }

    onAccountChange((type, account) => {
        if ((type === 'ADDED' || type === 'MODIFIED') && account.cookie) {
            const activeSessions = sessionManager.getAllActiveSessions();
            const sessionExists = activeSessions.includes(account.username);

            if (!sessionExists) {
                console.log(`[LISTENER] Restoring new session found in DB for ${account.username}`);
                sessionManager.restoreSession(account.username, account.proxy, account);
                if (sessionManager.isLoggedIn(account.username)) {
                    syncProfile(account.username).catch(() => { });
                }
            }
        } else if (type === 'REMOVED') {
            automationService.stopTask(account.username);
            sessionManager.removeSession(account.username);
        }
    });


    orderManager.startPolling(30000); // Poll every 30s
    startSessionSentinel(); // Monitor session health periodically
    startHistorySentinel(); // Autho-prune old orders daily

    // --- START GLOBAL WEBHOOK SENTINEL (Autonomous Notification Stream) ---
    // Frequency: 60s with Neural Jitter for maximum stealth
    setInterval(async () => {
        const accounts = await getAllAccounts();
        for (const acc of (accounts as any[])) {
            if (acc.webhook && sessionManager.isLoggedIn(acc.username)) {
                // Add Neural Jitter: Random 0-10s delay to avoid "mechanical" pattern
                const jitter = Math.floor(Math.random() * 10000);
                setTimeout(() => {
                    pushWebhook(acc.username, { event: 'POLL_ACTIVITY' }).catch(() => { });
                }, jitter);
            }
        }
    }, 60000); // 1 minute frequency

    app.listen(PORT, () => console.log(`[SERVER] Running at http://localhost:${PORT}`));
}

start();
