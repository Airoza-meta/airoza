import * as admin from 'firebase-admin';
import path from 'path';
import fs from 'fs';

let db: admin.firestore.Firestore;

// Initialize Firebase & Firestore
export async function initDb() {
    try {
        if (admin.apps.length === 0) {
            const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT || './serviceAccountKey.json';
            let credential;

            if (fs.existsSync(serviceAccountPath)) {
                console.log(`[DB] Using service account file: ${serviceAccountPath}`);
                credential = admin.credential.cert(require(path.resolve(serviceAccountPath)));
            } else {
                console.log('[DB] No service account file found. Attempting to use default application credentials...');
                credential = admin.credential.applicationDefault();
            }

            admin.initializeApp({ credential });
        }

        db = admin.firestore();
        db.settings({ ignoreUndefinedProperties: true });
        console.log('[DB] Database initialized (Firebase Firestore).');
        return db;
    } catch (error) {
        console.error('[DB] Failed to initialize Firebase:', error);
        throw error;
    }
}

// --- helpers ---
function getAccountCollection() {
    if (!db) throw new Error("Database not initialized. Call initDb() first.");
    return db.collection('accounts');
}

function getUserCollection() {
    if (!db) throw new Error("Database not initialized. Call initDb() first.");
    return db.collection('users');
}

// --- Account Operations ---

export async function addAccount(username: string, password: string, proxy?: string, webhook?: string, ownerId?: string, twoFactorSecret?: string, cookie?: string) {
    try {
        const collection = getAccountCollection();
        const docRef = collection.doc(username);
        const doc = await docRef.get();
        const oldData = doc.exists ? doc.data() : {};

        await docRef.set({
            ...oldData,
            username,
            password,
            proxy: proxy || null,
            webhook: webhook || null,
            cookie: cookie || (oldData as any)?.cookie || null,
            ownerId: ownerId || (oldData as any)?.ownerId || null,
            two_factor_secret: twoFactorSecret || (oldData as any)?.two_factor_secret || null,
            last_updated: new Date().toISOString(),
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return true;
    } catch (e) {
        console.error('[DB] Add Account Error:', e);
        return false;
    }
}

export async function updateAccountState(username: string, data: any) {
    if (!username) {
        console.error('[DB] Cannot update state: username is empty/undefined');
        return false;
    }
    try {
        const collection = getAccountCollection();
        await collection.doc(username).set({
            ...data,
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        return true;
    } catch (e) {
        console.error('[DB] Update Account State Error:', e);
        return false;
    }
}

export async function updateAccountCookie(username: string, cookie: string) {
    return updateAccountState(username, { cookie });
}

export async function incrementAccountDailyAction(username: string, actionType: 'likes' | 'follows' | 'comments' | 'posts') {
    const today = new Date().toISOString().split('T')[0];
    try {
        const collection = getAccountCollection();
        const docRef = collection.doc(username);
        const doc = await docRef.get();
        if (!doc.exists) return false;

        const data = doc.data() as any;
        const currentStats = data.daily_stats || {};

        if (currentStats.date !== today) {
            // New day, reset
            await docRef.update({
                daily_stats: {
                    date: today,
                    likes: actionType === 'likes' ? 1 : 0,
                    follows: actionType === 'follows' ? 1 : 0,
                    comments: actionType === 'comments' ? 1 : 0,
                    posts: actionType === 'posts' ? 1 : 0
                }
            });
        } else {
            // Same day, increment
            await docRef.update({
                [`daily_stats.${actionType}`]: admin.firestore.FieldValue.increment(1)
            });
        }
        return true;
    } catch (e) {
        console.error('[DB] Increment Daily Action Error:', e);
        return false;
    }
}

export async function getAccount(username: string) {
    try {
        const collection = getAccountCollection();
        const doc = await collection.doc(username).get();
        return doc.exists ? doc.data() : null;
    } catch (e) {
        console.error('[DB] Get Account Error:', e);
        return null;
    }
}

export async function getAllAccounts() {
    try {
        const collection = getAccountCollection();
        const snapshot = await collection.get();
        return snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                ...data,
                username: data.username || doc.id // Ensure username is always present
            };
        });
    } catch (e) {
        console.error('[DB] Get All Accounts Error:', e);
        return [];
    }
}

export async function getAccountsByOwner(ownerId: string) {
    try {
        const collection = getAccountCollection();
        const snapshot = await collection.where('ownerId', '==', ownerId).get();
        return snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                ...data,
                username: data.username || doc.id
            };
        });
    } catch (e) {
        console.error('[DB] Get Accounts By Owner Error:', e);
        return [];
    }
}

export async function deleteAccount(username: string) {
    try {
        const collection = getAccountCollection();
        await collection.doc(username).delete();
        return true;
    } catch (e) {
        console.error('[DB] Delete Account Error:', e);
        return false;
    }
}

export function onAccountChange(callback: (type: 'ADDED' | 'MODIFIED' | 'REMOVED', account: any) => void) {
    try {
        const collection = getAccountCollection();
        return collection.onSnapshot((snapshot: any) => {
            snapshot.docChanges().forEach((change: any) => {
                const account = change.doc.data();
                if (!account.username) account.username = change.doc.id;

                if (change.type === 'added') callback('ADDED', account);
                else if (change.type === 'modified') callback('MODIFIED', account);
                else if (change.type === 'removed') callback('REMOVED', account);
            });
        }, (error: any) => console.error('[DB] Listener Error:', error));
    } catch (e) {
        console.error('[DB] Setup Listener Error:', e);
        return () => { };
    }
}

export async function logAction(username: string, actionType: string, details: any, status: 'SUCCESS' | 'FAILED' = 'SUCCESS') {
    try {
        const historyRef = getAccountCollection().doc(username).collection('history');
        await historyRef.add({
            action: actionType,
            details: details,
            status: status,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        if (status === 'SUCCESS') {
            await incrementActionCount(username, actionType.toLowerCase());
        }
        return true;
    } catch (e) {
        console.error('[DB] Log Action Error:', e);
        return false;
    }
}

export async function incrementActionCount(username: string, type: string) {
    try {
        const today = new Date().toISOString().split('T')[0];
        const accountRef = getAccountCollection().doc(username);

        // Map types to standard keys
        let key = type.toLowerCase();
        if (key.includes('like')) key = 'likes';
        else if (key.includes('follow')) key = 'follows';
        else if (key.includes('comment')) key = 'comments';
        else if (key.includes('post')) key = 'posts';
        else return;

        await db.runTransaction(async (t) => {
            const doc = await t.get(accountRef);
            if (!doc.exists) return;

            const data = doc.data() || {};
            const dailyCounts = data.daily_counts || { likes: 0, follows: 0, comments: 0, posts: 0 };
            const lastReset = data.last_count_reset || '';

            let newCounts = { ...dailyCounts };
            if (lastReset !== today) {
                newCounts = { likes: 0, follows: 0, comments: 0, posts: 0 };
            }

            newCounts[key] = (newCounts[key] || 0) + 1;

            t.update(accountRef, {
                daily_counts: newCounts,
                last_count_reset: today,
                updated_at: admin.firestore.FieldValue.serverTimestamp()
            });
        });
        return true;
    } catch (e) {
        console.error('[DB] Increment Action Count Error:', e);
        return false;
    }
}

// --- User Operations ---

export async function addUser(userData: { username: string; password: string; role: 'admin' | 'user' }) {
    try {
        const collection = getUserCollection();
        await collection.doc(userData.username).set({
            ...userData,
            credits: 1, // Start with 1, +1 more for the first IG Link = 2 Total reward
            apiKey: `sk-${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
            created_at: admin.firestore.FieldValue.serverTimestamp()
        });
        return true;
    } catch (e) {
        console.error('[DB] Add User Error:', e);
        return false;
    }
}

export async function getUser(username: string) {
    try {
        const collection = getUserCollection();
        const doc = await collection.doc(username).get();
        return doc.exists ? doc.data() : null;
    } catch (e) {
        console.error('[DB] Get User Error:', e);
        return null;
    }
}

export async function getUserByApiKey(apiKey: string) {
    try {
        const collection = getUserCollection();
        const snapshot = await collection.where('apiKey', '==', apiKey).limit(1).get();
        if (snapshot.empty) return null;
        const userDoc = snapshot.docs[0];
        return userDoc ? userDoc.data() : null;
    } catch (e) {
        console.error('[DB] Get User By API Key Error:', e);
        return null;
    }
}

export async function updateUserCredits(username: string, amount: number) {
    try {
        const collection = getUserCollection();
        const userRef = collection.doc(username);
        await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            if (!doc.exists) throw new Error('User not found');
            const data = doc.data();
            const newCredits = Math.max(0, parseFloat(((data?.credits || 0) + amount).toFixed(4)));
            if (newCredits < 0 && amount < 0) throw new Error('Insufficient credits');
            t.update(userRef, { credits: newCredits });
        });
        return true;
    } catch (e: any) {
        console.error('[DB] Update Credits Error:', e.message);
        return false;
    }
}

export async function generateNewApiKey(username: string) {
    try {
        const newKey = `sk-${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
        const collection = getUserCollection();
        await collection.doc(username).update({ apiKey: newKey });
        return newKey;
    } catch (e) {
        console.error('[DB] Generate API Key Error:', e);
        return null;
    }
}
// --- Automation Tasks ---

export async function saveAutomationTask(task: any) {
    try {
        const collection = db.collection('automation_tasks');
        await collection.doc(task.botUsername).set({
            ...task,
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        return true;
    } catch (e) {
        console.error('[DB] Save Automation Task Error:', e);
        return false;
    }
}

export async function getAllAutomationTasks() {
    try {
        const collection = db.collection('automation_tasks');
        const snapshot = await collection.get();
        return snapshot.docs.map(doc => doc.data());
    } catch (e) {
        console.error('[DB] Get All Automation Tasks Error:', e);
        return [];
    }
}

export async function deleteAutomationTask(botUsername: string) {
    try {
        const collection = db.collection('automation_tasks');
        await collection.doc(botUsername).delete();
        return true;
    } catch (e) {
        console.error('[DB] Delete Automation Task Error:', e);
        return false;
    }
}

// --- Order Operations ---

export async function addOrder(orderData: any) {
    try {
        const collection = db.collection('orders');
        const docRef = await collection.add({
            ...orderData,
            status: 'PENDING',
            start_count: 0,
            current_count: 0,
            created_at: admin.firestore.FieldValue.serverTimestamp(),
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        });
        return docRef.id;
    } catch (e) {
        console.error('[DB] Add Order Error:', e);
        return null;
    }
}

export async function getOrdersByUser(userId: string) {
    try {
        const collection = db.collection('orders');
        const snapshot = await collection.where('user_id', '==', userId)
            .limit(50)
            .get();

        const orders = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() as any }));
        // Sort in memory to avoid index requirement
        return orders.sort((a, b) => {
            const timeA = a.created_at?.toMillis?.() || 0;
            const timeB = b.created_at?.toMillis?.() || 0;
            return timeB - timeA;
        });
    } catch (e) {
        console.error('[DB] Get Orders By User Error:', e);
        return [];
    }
}

export async function updateOrder(orderId: string, data: any) {
    try {
        const collection = db.collection('orders');
        await collection.doc(orderId).update({
            ...data,
            updated_at: admin.firestore.FieldValue.serverTimestamp()
        });
        return true;
    } catch (e) {
        console.error('[DB] Update Order Error:', e);
        return false;
    }
}

export async function getPendingOrders() {
    try {
        const collection = db.collection('orders');
        const snapshot = await collection.where('status', 'in', ['PENDING', 'PROCESSING']).get();
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (e) {
        console.error('[DB] Get Pending Orders Error:', e);
        return [];
    }
}

export async function pruneOldOrders(days: number = 7) {
    console.log(`[DB] Pruning orders older than ${days} days...`);
    try {
        const collection = db.collection('orders');
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - days);

        const snapshot = await collection
            .where('created_at', '<', admin.firestore.Timestamp.fromDate(cutoff))
            .get();

        if (snapshot.empty) {
            console.log('[DB] No old orders found to prune.');
            return 0;
        }

        const batch = db.batch();
        snapshot.docs.forEach(doc => {
            batch.delete(doc.ref);
        });

        await batch.commit();
        console.log(`[DB] Successfully pruned ${snapshot.size} old orders.`);
        return snapshot.size;
    } catch (e: any) {
        console.error('[DB] Prune Old Orders Error:', e.message);
        return 0;
    }
}
