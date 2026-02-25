/**
 * Airoza AI Agent Integration Example
 * 
 * This script demonstrates how to integrate an AI Model (OpenAI) with the Airoza API
 * to automatically generate and post context-aware comments on Instagram.
 */

import axios from 'axios';
import OpenAI from 'openai'; // npm install openai

// --- CONFIGURATION ---
const AIROZA_BASE_URL = 'http://localhost:3000';
const AIROZA_API_KEY = 'your_airoza_api_key'; // Generate this via /auth/generate-key
const OPENAI_API_KEY = 'your_openai_api_key';

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

async function runAIAgent() {
    console.log('--- Airoza AI Agent Started ---');

    try {
        // 1. Setup Airoza Client
        const airoza = axios.create({
            baseURL: AIROZA_BASE_URL,
            headers: { 'Authorization': `Bearer ${AIROZA_API_KEY}` }
        });

        // 2. Identify Target Post
        const botUsername = 'your_ig_bot_username';
        const targetPostUrl = 'https://www.instagram.com/p/Cze0M_XpL1/';

        console.log(`[AGENT] Analyzing post: ${targetPostUrl}`);

        /**
         * 3. AI STRATEGY: 
         * In a real scenario, you would fetch the caption or use Vision API to see the image.
         * For this example, we'll assume we fetched a generic travel context.
         */
        const postContext = "A beautiful sunset at the beach in Bali with golden waves.";

        // 4. Generate Comment using AI
        console.log('[AGENT] Asking AI for a creative comment...');
        const aiResponse = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [
                {
                    role: "system",
                    content: "You are an enthusiastic Instagram follower. Generate a short, natural-sounding comment (max 10 words) with 1-2 emojis based on the post description provided. Do not use generic hashtags."
                },
                {
                    role: "user",
                    content: `Post Context: ${postContext}`
                }
            ]
        });

        const generatedComment = aiResponse.choices[0].message.content || "Amazing! 😍";
        console.log(`[AGENT] AI Result: "${generatedComment}"`);

        // 5. Post via Airoza Engine
        console.log(`[AGENT] Command sending to Neural Node @${botUsername}...`);

        const response = await airoza.post('/api/comment', {
            botUsername: botUsername,
            mediaId: targetPostUrl,
            text: generatedComment
        });

        if (response.data.status === 'success') {
            console.log('[SUCCESS] AI comment successfully bridged to Instagram via Airoza!');
        } else {
            console.error('[FAILED] Airoza Error:', response.data);
        }

    } catch (error: any) {
        console.error('[CRITICAL] Agent Fault:', error.response?.data || error.message);
    }
}

// Run the agent
runAIAgent();
