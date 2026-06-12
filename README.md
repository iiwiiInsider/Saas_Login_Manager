# Saas_Login_Manager

Simple SaaS-style login/signup + SQLite user store with **bcrypt** password hashes (non-retrievable) and a black/blue reactive dashboard.

## Admin credentials (seeded on first run)
- **Email:** `admin@test.local`
- **Password:** `Admin123`

Admin can delete users and change user password/email.

## Run locally
```bash
npm install
npm start
```

Then open:
- http://localhost:3000/login
- http://localhost:3000/signup

## Notes on security
- Passwords are stored as **bcrypt hashes** in `auth.db`.
- Hashes are one-way; they are not decryptable.
- Session cookies are `httpOnly` and use `sameSite=lax`.

