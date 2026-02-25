# 🚀 Airoza Setup Guide

This guide will walk you through the steps to get your Airoza Instagram Automation Engine up and running.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:
*   **Node.js**: v16.x or higher (v18+ recommended)
*   **NPM**: v8.x or higher
*   **Firebase Account**: To setup the Firestore database.

---

## 🛠️ Installation

### 1. Clone & Install
Clone the repository to your local machine and install the dependencies:

```bash
git clone https://github.com/Airoza-meta/airoza.git
cd airoza
npm install
```

### 2. Environment Configuration
Create a `.env` file in the root directory and add the following (optional if using defaults):

```env
PORT=3000
FIREBASE_SERVICE_ACCOUNT=./serviceAccountKey.json
# Optional: Instagram App ID if you want to override
# X_IG_APP_ID=936619743392459
```

---

## 📦 Database Setup (Firebase)

Airoza uses **Firebase Cloud Firestore** for its database. No local database installation is required.

1.  **Create a Project**: Go to [Firebase Console](https://console.firebase.google.com/) and create a new project named "Airoza" (or anything you like).
2.  **Enable Firestore**: In the sidebar, click **Firestore Database** and then **Create database**. Start in "Production" or "Test" mode. Choose a location close to your server.
3.  **Generate Service Account Key**:
    *   Go to **Project Settings** (gear icon) > **Service accounts**.
    *   Click **Generate new private key**.
    *   Download the JSON file.
4.  **Place the Key**: Rename the downloaded JSON file to `serviceAccountKey.json` and place it in the root directory of the Airoza project.

---

## 🏗️ Build & Execution

### Development Mode
Runs the server using `ts-node` for live development.

```bash
npm run dev
```

### Production Mode
1.  **Build the project**:
    ```bash
    npm run build
    ```
2.  **Start with PM2** (Recommended for stability):
    ```bash
    npm install -g pm2
    pm2 start ecosystem.config.js
    ```

---

## 🧪 Verification

Once started, the server will be available at `http://localhost:3000`. You can verify it by visiting the root URL in your browser or using `curl`:

```bash
curl http://localhost:3000
```
**Expected Response:**
```json
{ "status": "ok", "message": "Airoza Neural Engine Active" }
```

---

## 🔐 Initial Admin Login
The system initializes with a default admin account:
*   **Username**: `admin`
*   **Password**: `admin123`

You should change this password immediately via the API or the Firestore Console.
