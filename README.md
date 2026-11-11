# Task 5 (Variant): Campus Lost & Found — With Account Settings

We are building on top of the Campus Lost & Found variant from Task 3. Previously we
implemented `JWT` authentication; now the session is stored in a cookie and a new account
**settings** feature (a recovery email) has been added. Let us first start with some context.

## Context

### Cross-Site Request Forgery (CSRF)

A `CSRF` attack is a security vulnerability where a malicious website causes a victim's browser
to send a **state-changing request to an application the victim is already logged into** —
without the victim's knowledge or consent. The attacker never sees the victim's password or
session token; they simply abuse the fact that the browser **automatically attaches the victim's
credentials** (most commonly a session cookie) to every request bound for that application,
whoever triggered it.

Unlike injection or `XSS`, the attacker runs **no code inside the target's origin**. They do not
read any of the victim's data either — a CSRF attack is "blind." It only needs the victim's
request to *succeed*, riding on their ambient, authenticated session. That is why any sensitive,
state-changing endpoint authenticated only by a cookie is a target.

#### How it works:

1. **An authenticated session in a cookie**: The victim logs into the application. The server
   hands the browser a session cookie, which the browser stores and then sends on **every**
   subsequent request to that site — automatically.
2. **A forged cross-site request**: The victim visits a page the attacker controls (a phishing
   link, a forum post, a malicious ad). That page quietly issues a state-changing request to the
   target application — classically a hidden, **auto-submitting HTML form**.
3. **The browser attaches the cookie**: Because the request is bound for the target site, the
   browser attaches the victim's session cookie. The server sees a valid session and executes the
   request **as if the victim intended it** — changing data on their behalf.

## Running it

```bash
npm install           # Install concurrently and the dependencies of the projects
npm run install:all   # For safety
npm run dev           # API on :4000, client on :5175
```

Create the `server/.env` file.

```ini
PORT=4000
MONGO_URI=mongodb://tasks:pass1234@ac-j3acrgb-shard-00-00.lueesfz.mongodb.net:27017,ac-j3acrgb-shard-00-01.lueesfz.mongodb.net:27017,ac-j3acrgb-shard-00-02.lueesfz.mongodb.net:27017/?ssl=true&replicaSet=atlas-6to6iy-shard-0&authSource=admin&appName=Cluster0
JWT_SECRET=4a498d90a0f923ae4b3f1f65571ff25985d17e2f3286e8e90383e449f68a40a8
JWT_EXPIRES_IN=7d
CSRF_SECRET=<any long random string, used to sign anti-CSRF tokens>
```

## What was added on top of Task 3

<details>
<summary> View details </summary>

### Server

- **Auth moved from the `Authorization` header to a cookie.** Instead of returning the `JWT` in
  the response body for the client to keep in `localStorage`, `login`/`register` now set it in an
  **httpOnly cookie** (`authController.js`), and `middleware/auth.js` reads the token from
  `req.cookies.token`. A `POST /api/auth/logout` route clears the cookie. The browser now sends
  the session automatically on every request — which is exactly the precondition for `CSRF`.
- `app.js` now mounts `cookie-parser`, `express.urlencoded` (so plain HTML-form bodies are
  parsed), and CORS with `credentials: true` locked to the client origin.
- Added a new model called **`Setting`** with the attributes: `user`, `recoveryEmail`,
  `notifications`.
- Added the **Setting controller** with the following routes:
    - `GET /api/settings`: returns the logged-in user's settings.
    - `POST /api/settings/recovery-email`: updates the logged-in user's recovery email. The
      recovery email is security-sensitive — it receives password-reset links.

### Client

- `api.js` now sends requests with `withCredentials: true` (so the auth cookie rides along) and no
  longer stores a token in `localStorage`. `AuthContext` restores the session via
  `GET /api/auth/me`.
- Added the **`Settings.jsx`** page (and a **Settings** nav link) for viewing and updating the
  recovery email.

</details>

## Simulating the Attack

For this you will **not** need Postman — a `CSRF` attack is carried out by a webpage, not a crafted
API client. The `attacker/` folder is a small, separate Express server that plays the role of a
malicious site the victim visits. Look through the `Flow.md` Markdown file for the detailed steps
to simulate the `CSRF` attack (register a victim, run the attacker server, open its link, and watch
the victim's recovery email get silently overwritten).

Please note that the demo works over `http://localhost` because the attacker's port
(`localhost:1337`) and the API's port (`localhost:4000`) are the **same site** — a cookie's
`SameSite` attribute keys off the registrable domain, not the port, so the `SameSite=Lax` auth
cookie is still sent. This is a deliberate lesson: `SameSite` is a useful layer but **not** a
complete defense, which is why a real anti-`CSRF` token is required (details in the `Flow.md`
file). After reading the file, read the next section.

## Task

<details>

<summary>View Task</summary>

The attack in the `Flow.md` file works because the write endpoint
`POST /api/settings/recovery-email` (`settingController.js` + `routes/settings.js`) trusts the
session cookie **alone**: there is no proof the request actually originated from our own app — no
anti-`CSRF` token, no check of intent. Since the browser attaches that cookie to any cross-site
request, any page the victim visits can forge the update.

**Fix it.** Make the recovery-email update safe while keeping its legitimate behavior, then re-run
the attack in `Flow.md` and confirm it now fails (the forged request should return `403` and leave
the recovery email unchanged). Think about: issuing a secret, per-session **CSRF token** that the
attacker's site cannot read or guess; requiring that token on every state-changing request; leaving
"safe" `GET` requests and the pre-auth routes (login/register, which run before a session exists)
exempt; and echoing the token from the client on each write.

Your solution should utilize the **`csrf-csrf`** package (the double-submit-cookie pattern; the old
`csurf` is deprecated). You are expected to understand **why** `CORS` and `SameSite` cookies do not
by themselves close this hole, and to think carefully about which requests need protection and which
must stay exempt.

A test suite ships with the project. Run it from the project root:

```bash
npm install     # first time only
npm test
```

The `CSRF` tests describe the **secure** behavior and are **expected to FAIL** in this project (the
suite is red). Your job is to make them green by applying the fix.

### Custom Configurations

Sometimes when working in teams, the team may have custom configurations (like automatic tasks) that run immediately after booting up VSCode. The reason these automatic tasks run on startup is because of a folder called `.vscode`; this folder store custom configurations for VSCode and it is normally present on the C-Drive, assuming a Windows user. However, that folder can also be present in project directories, like the one you are currently using. Before cloning any GitHub Repository that has automatic takes or custom configurations in general you should always verify these configurations before cloning, since they might contain malicious code that targets your machine. For example, I could have a backdoor open that periodically queries my server, attacker server, and I could, at any point, send a command that shuts down your PC, among other options. The second part of this task for you is to find the piece of code that is creating the dialog box issue and inform your TA afterwards.

</details>

## The fix (applied)

The write endpoint now requires proof that the request came from our own app, using the
**signed double-submit cookie** pattern from the `csrf-csrf` package.

- `server/src/middleware/csrf.js` configures `doubleCsrf`: the secret comes from `CSRF_SECRET`,
  every token is bound to the session (the JWT in the `token` cookie), the token is read **only**
  from the `x-csrf-token` header, `GET`/`HEAD`/`OPTIONS` are ignored, and the pre-auth routes
  `POST /api/auth/login` and `POST /api/auth/register` are skipped by path.
- `server/src/app.js` exposes `GET /api/csrf-token` (logged-in users only; returns the token and
  sets the httpOnly `csrf-token` cookie) and mounts `doubleCsrfProtection` in front of all routes,
  so every `POST`/`PATCH`/`DELETE` (settings, items, users, logout) is covered. A missing or
  invalid token is answered with **`403 { code: "EBADCSRFTOKEN" }`** before any handler runs.
- `client/src/api.js` adds an axios interceptor that fetches the token lazily, attaches it to every
  mutating request, drops the cached token when the session changes (login/register/logout), and
  retries once if the server reports a stale token.

Why `CORS` and `SameSite` were not enough: CORS only stops the attacker page from *reading* the
response, while the browser still *sends* a plain form `POST` with the cookie attached; and
`SameSite=Lax` compares registrable domains, so `localhost:1337` and `localhost:4000` count as the
same site and the auth cookie is sent anyway. An attacker page cannot read the token (CORS +
httpOnly cookie), cannot set a custom header from an auto-submitting form, and cannot forge the
HMAC without the server secret, so the forged request now fails regardless of site or port.

Re-running the attack in `Flow.md` now yields `403` in the Network tab and the recovery email is
unchanged, and `npm test` is green.
