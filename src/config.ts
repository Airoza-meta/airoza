import dotenv from 'dotenv';
dotenv.config();

export const CONFIG = {
    COOKIE: process.env.INSTAGRAM_COOKIE || '',
    X_IG_APP_ID: process.env.X_IG_APP_ID || '936619743392459',
    X_CSRF_TOKEN: process.env.X_CSRF_TOKEN || '',
    USER_AGENT: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    BASE_URL: 'https://www.instagram.com',
};
