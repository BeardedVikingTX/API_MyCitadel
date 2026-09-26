# API_MyCitadel

> **The cryptographic backbone of MyCitadel. Zero‑knowledge. Always encrypted.**

API_MyCitadel powers the privacy‑first social platform [MyCitadel](https://github.com/BeardedVikingTX/MyCitadel). It is a RESTful API built with PHP that never sees your plaintext data. All sensitive information is encrypted **client‑side** before it reaches our servers. We store only ciphertext, and we like it that way.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Security: Argon2id](https://img.shields.io/badge/Security-Argon2id-blue)](https://www.argon2.com/)
[![API Version: v1](https://img.shields.io/badge/API-v1-blue)](https://api.mycitadel.lol/v1)

---

## 🔐 Core Principles

- **Zero‑Knowledge Architecture** – The API stores encrypted blobs. It cannot decrypt them.
- **Argon2id Password Hashing** – State‑of‑the‑art, memory‑hard hashing for credentials.
- **Client‑Side Encryption** – Encryption/decryption happens in the browser or app, never on the server.
- **No Plaintext Ever** – We don’t want your data; we can’t read it anyway.
- **Open Source** – Audit the code, verify the claims.

---

## 📡 API Endpoints (v1)

All endpoints are prefixed with `https://api.mycitadel.lol/v1/`.

| Method | Endpoint | Description | Status |
|--------|----------|-------------|--------|
| `POST` | `/auth/register` | Register a new user (client sends Argon2id hash + encrypted profile) | 🚧 Stub |
| `POST` | `/auth/login` | Authenticate and receive a session token | 🚧 Stub |
| `POST` | `/auth/logout` | Invalidate the current session | 🚧 Stub |
| `GET`  | `/users/dashboard` | Retrieve dashboard data (encrypted) | 🚧 Stub |
| `GET`  | `/users/me` | Get current user’s encrypted profile | 🚧 Stub |
| `GET`  | `/users/users` | List users (public encrypted identifiers only) | 🚧 Stub |
| `PUT`  | `/users/update` | Update user profile (encrypted payload) | 🚧 Stub |

> **Note:** Endpoints are currently stubs. Implementation is in active development.  
> Full interactive documentation will be available at [https://api.mycitadel.lol](https://api.mycitadel.lol) (coming soon).

### Example Request (Registration – conceptual)

```http
POST /v1/auth/register
Content-Type: application/json

{
  "username": "beardedviking",
  "argon2id_hash": "$argon2id$v=19$m=65536,t=4,p=2$...",
  "encrypted_profile": "base64_encoded_ciphertext",
  "public_key": "base64_encoded_public_key"
}
```
### Example Response
```
{
  "status": "success",
  "user_id": "uuid-v4",
  "token": "jwt_or_session_token"
}
```
## 🏗️ Architecture Overview
🏗️ Architecture Overview
-------------------------

| Component | Role |
| --- | --- |
| **Client (Web/App)** | Derives keys, encrypts data, sends ciphertext |
| **API_MyCitadel** | Receives ciphertext, stores it, handles auth, returns ciphertext |
| **secure_mycitadel.lol** | Private core -- key management, orchestration (not exposed publicly) |

The API never performs encryption or decryption. It is a **blind storage and authentication layer**.

* * * * *

🛡️ Security & Bug Bounty
-------------------------

Security is paramount. After our initial launch (friends & family) and the Android app release, we will open a **public bug bounty program on HackerOne**.

### Rewards

-   **Reputation Points** -- Earn points on MyCitadel for valid reports.

-   **Merch** -- Exclusive MyCitadel gear (limited availability).

-   **Critical Vulnerabilities** -- Up to **$1,000 USD** for extreme, critical issues (case‑by‑case basis).

We do **not** have a broad financial reward structure, but we deeply value responsible disclosure. Full details will be announced on HackerOne.

**Do not test vulnerabilities on production without permission.** Contact us first.

* * * * *

🚀 Getting Started (Local Development)
--------------------------------------

### Prerequisites

-   PHP 8.1+

-   Composer

-   MySQL 8+ or PostgreSQL 14+

-   Web server (Apache/Nginx) or PHP built‑in server

### Installation

1.  Clone the repository:
🏗️ Architecture Overview
-------------------------

| Component | Role |
| --- | --- |
| **Client (Web/App)** | Derives keys, encrypts data, sends ciphertext |
| **API_MyCitadel** | Receives ciphertext, stores it, handles auth, returns ciphertext |
| **secure_mycitadel.lol** | Private core -- key management, orchestration (not exposed publicly) |

The API never performs encryption or decryption. It is a **blind storage and authentication layer**.

* * * * *

🛡️ Security & Bug Bounty
-------------------------

Security is paramount. After our initial launch (friends & family) and the Android app release, we will open a **public bug bounty program on HackerOne**.

### Rewards

-   **Reputation Points** -- Earn points on MyCitadel for valid reports.

-   **Merch** -- Exclusive MyCitadel gear (limited availability).

-   **Critical Vulnerabilities** -- Up to **$1,000 USD** for extreme, critical issues (case‑by‑case basis).

We do **not** have a broad financial reward structure, but we deeply value responsible disclosure. Full details will be announced on HackerOne.

**Do not test vulnerabilities on production without permission.** Contact us first.

* * * * *

🚀 Getting Started (Local Development)
--------------------------------------

### Prerequisites

-   PHP 8.1+

-   Composer

-   MySQL 8+ or PostgreSQL 14+

-   Web server (Apache/Nginx) or PHP built‑in server

### Installation

1.  Clone the repository:
```
git clone https://github.com/BeardedVikingTX/API_MyCitadel.git
cd API_MyCitadel
```
2. Install dependencies:
```
composer install
```
3. Configure environment:
```
cp .env.example .env
# Edit .env with database credentials and secret keys
```
4. Set up the database (schema coming soon).

5. Run the development server:
```
php -S localhost:8080 -t public
```
> **Note:** The API is designed to work with the main MyCitadel frontend. See [MyCitadel](https://github.com/BeardedVikingTX/MyCitadel) for the web client.

## 📁 Directory Structure
```
API_MyCitadel/
├── v1/
│   ├── auth/
│   │   ├── register.php
│   │   ├── login.php
│   │   └── logout.php
│   ├── users/
│   │   ├── dashboard.php
│   │   ├── me.php
│   │   ├── users.php
│   │   └── update.php
│   └── bootstrap.php
├── composer.json
├── README.md
└── ...
```
* * * * *

## 🤝 Contributing
---------------

We welcome contributions! Please read the [Contributing Guidelines](https://github.com/BeardedVikingTX/MyCitadel/blob/main/CONTRIBUTING.md) in the main repository.

1.  Fork the repo.

2.  Create a feature branch.

3.  Commit your changes.

4.  Push and open a Pull Request.

* * * * *

## 📜 License
----------

This project is licensed under the MIT License -- see the [LICENSE](https://license/) file for details.

* * * * *

## 🔗 Links
--------

-   **Main Website:**  [https://mycitadel.lol](https://mycitadel.lol/)

-   **API Endpoint:**  [https://api.mycitadel.lol](https://api.mycitadel.lol/)

-   **Main GitHub Repo:**  [MyCitadel](https://github.com/BeardedVikingTX/MyCitadel)

-   **HackerOne:** (coming soon)

* * * * *

## 🙏 Acknowledgements
-------------------

-   Built with ❤️ by Bearded Viking and contributors.

-   Special thanks to the open‑source community.

* * * * *

**API_MyCitadel** -- *We store ciphertext. Nothing more. Nothing less.*