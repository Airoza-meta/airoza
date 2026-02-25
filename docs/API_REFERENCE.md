# 📡 Airoza API Reference

This document provides a comprehensive list of all available API endpoints for the Airoza Engine.

## 🔑 Authentication (User Management)

All requests except `/auth/register` and `/auth/login` require authentication via a Session Token or API Key.

### Register User
`POST /auth/register`
Creates a new user account and attempts to link an Instagram account simultaneously.
*   **Body**: `{ "username", "password", "proxy" (optional) }`

### User Login
`POST /auth/login`
Authenticates a user and returns a session token.
*   **Body**: `{ "username", "password" }`

### Get My Info
`GET /auth/me` (Auth Required)
Returns details of the currently logged-in user.

### Generate API Key
`POST /auth/generate-key` (Auth Required)
Generates a persistent API key for the user.

---

## 👥 Account Management (Instagram Nodes)

Manage the Instagram accounts (nodes) owned by the user.

### List Accounts
`GET /accounts` (Auth Required)
Returns a list of all Instagram accounts owned by the user.

### Add Account
`POST /accounts` (Auth Required)
Adds or updates an Instagram account in the database.
*   **Body**: `{ "username", "password", "proxy", "webhook", "ownerId" (admin only) }`

### Update Account
`PATCH /accounts/:username` (Auth Required/Owner)
Updates the state or settings of a specific node.

### Delete Account
`DELETE /accounts/:username` (Auth Required/Owner)
Removes an Instagram account and stops all associated tasks.

### Forge Account (Admin Only)
`POST /auth/forge-account` (Auth Required/Admin)
Exploits Accounts Center logic to create a brand new secondary Instagram account linked to an existing "anchor" node.

---

## ❤️ Instagram Actions

Direct interactions with Instagram. Most actions deduct credits (for non-admins).

### Like Media
`POST /api/like` (Auth Required/Owner)
Likes a post.
*   **Body**: `{ "botUsername", "mediaId" (URL or ID) }`
*   **Cost**: 0.1 Credit

### Comment on Media
`POST /api/comment` (Auth Required/Owner)
Posts a comment.
*   **Body**: `{ "botUsername", "mediaId" (URL or ID), "text", "targetUsername" (optional) }`
*   **Cost**: 0.2 Credit

### Follow User
`POST /api/follow` (Auth Required/Owner)
Follows a user.
*   **Body**: `{ "botUsername", "targetUsername" }`
*   **Cost**: 0.1 Credit

### Post Image
`POST /api/post` (Auth Required/Owner)
Uploads a photo to the feed.
*   **Body**: Multipart/form-data with `image` file, `botUsername`, and `caption`.

### Update Status (Notes)
`POST /api/update-status` (Auth Required/Owner)
Updates the Instagram "Note" (Status).
*   **Body**: `{ "botUsername", "text" }`

### Search Users
`GET /search` (Auth Required)
Searches for Instagram users.
*   **Query Params**: `q` (query), `botUsername`.

---

## 🤖 Automation Engine

Schedule recurring tasks for your accounts.

### Start Task
`POST /auto/start` (Auth Required/Owner)
Starts an automation task.
*   **Body**: `{ "botUsername", "targets" (Array), "intervalMinutes", "type" ("LIKE" or "FOLLOW") }`

### List Tasks
`GET /auto/tasks` (Auth Required)
Lists all active automation tasks for the user.

### Stop Task
`POST /auto/stop` (Auth Required/Owner)
Stops an active task.

---

## 🛒 Order System (Engagement Delivery)

Bulk delivery system for high-volume engagement.

### Create Order
`POST /api/orders/create` (Auth Required)
Creates a single engagement order.
*   **Body**: `{ "type" ("LIKE", "FOLLOW", "COMMENT"), "target", "quantity", "comments" (Array of strings) }`

### Bulk Orders
`POST /api/orders/bulk` (Auth Required)
Creates multiple orders at once.

### Order History
`GET /api/orders/history` (Auth Required)
Returns the history of orders created by the user.

---

## 🚧 Security & Challenges

Endpoints specifically for handling Instagram's security layers.

### Send Challenge OTP
`POST /auth/challenge-send-otp` (Auth Required/Owner)
Requests a code if hit by a checkpoint.

### Submit Challenge Code
`POST /auth/challenge-submit-code` (Auth Required/Owner)
Submits the 6-digit OTP code to clear a checkpoint.

### 2FA Verification
`POST /auth/instagram-2fa` (Auth Required/Owner)
Submit 2FA code during the initial login process if required.
