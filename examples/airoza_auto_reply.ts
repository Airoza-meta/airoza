/**
 * Airoza AI Auto-Reply Agent
 * 
 * This script monitors an Instagram post for new comments and 
 * automatically generates AI replies.
 */

import axios from 'axios';
import OpenAI from 'openai';

const AIROZA_BASE_URL = 'http://localhost:3000';
const AIROZA_API_KEY = 'your_token';
const OPENAI_API_KEY = 'your_openai_key';
const BOT_USERNAME = 'your_bot';
const TARGET_MEDIA_ID = 'post_url_or_id';

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
const airoza = axios.create({
    baseURL: AIROZA_BASE_URL,
    headers: { 'Authorization': `Bearer ${AIROZA_API_KEY}` }
});

async function autoReply() {
    console.log(`[AUTO-REPLY] Checking for new comments on ${TARGET_MEDIA_ID}...`);

    try {
        // 1. Fetch latest comments
        const res = await airoza.get(`/api/comments/${encodeURIComponent(TARGET_MEDIA_ID)}?botUsername=${BOT_USERNAME}`);
        const comments = res.data.comments || [];

        for (const comment of comments) {
            // Skip if it's our own comment or we already replied
            if (comment.user.username === BOT_USERNAME) continue;

            console.log(`[COMMENT] By @${comment.user.username}: "${comment.text}"`);

            // 2. Ask AI to generate a reply
            const aiRes = await openai.chat.completions.create({
                model: "gpt-3.5-turbo",
                messages: [
                    { role: "system", content: "You are a helpful assistant. Reply to this Instagram comment naturally and briefly." },
                    { role: "user", content: `Comment: ${comment.text}` }
                ]
            });

            const replyText = aiRes.choices[0].message.content || "Thanks! 😊";
            console.log(`[AI-REPLY] Generated: "${replyText}"`);

            // 3. Post the reply (Sub-comment)
            await airoza.post('/api/comment', {
                botUsername: BOT_USERNAME,
                mediaId: TARGET_MEDIA_ID,
                text: `@${comment.user.username} ${replyText}`,
                replyToId: comment.pk || comment.id // This creates a sub-comment/reply
            });

            console.log(`[SUCCESS] Replied to @${comment.user.username}`);
        }
    } catch (e: any) {
        console.error('[ERROR]', e.message);
    }
}

// Check every 5 minutes
setInterval(autoReply, 300000);
autoReply();
