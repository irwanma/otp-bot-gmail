# 🤖 Telegram OTP Bot — Gmail Multi-Account

Bot Telegram untuk ambil OTP dari multiple Gmail accounts via Google API OAuth2.

## ✨ Fitur

- 🔐 **Auto-detect OTP** — 6 digit codes dari inbox Gmail
- 📋 **Copy button** — langsung tap untuk copy OTP atau email
- 📬 **Multi-account** — kelola banyak akun Gmail sekaligus
- ⏱️ **Age indicator** — tahu OTP baru atau lama
- 🔄 **Refresh** — refresh OTP tanpa ulang command
- 🔒 **Access control** — whitelist chat_id

## 📋 Commands

| Command | Deskripsi |
|---------|-----------|
| `/otp` | Pilih akun dari keyboard inline |
| `/otp <nomor>` | Cek langsung (misal: `/otp 3`) |
| `/list` | Lihat semua akun terdaftar |
| `/start` | Bantuan |

## 🚀 Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Buat Bot Telegram

- Chat ke [@BotFather](https://t.me/BotFather) di Telegram
- `/newbot` → kasih nama → copy token

### 3. Setup Gmail OAuth2

- Buka [Google Cloud Console](https://console.cloud.google.com/)
- Buat project baru → enable Gmail API
- Buat OAuth2 credentials (Desktop app) → download `credentials.json`
- Setup auth script untuk generate token per akun

### 4. Set Environment Variables

```bash
export BOT_TOKEN="your-telegram-bot-token"
export ALLOWED_CHAT_IDS="123456789"  # chat_id kamu (comma-separated)
export GMAIL_CREDENTIALS="credentials.json"  # optional
export GMAIL_TOKENS="tokens.json"  # optional
```

### 5. Run

```bash
python3 otp_bot.py
```

## 📁 Struktur

```
otp-bot-gmail/
├── otp_bot.py          # Main bot
├── requirements.txt    # Dependencies
├── README.md           # Dokumentasi
├── credentials.json    # Google OAuth2 client config (gitignored)
└── tokens.json         # OAuth2 tokens per akun (gitignored)
```

## ⚙️ Environment Variables

| Variable | Required | Default | Deskripsi |
|----------|----------|---------|-----------|
| `BOT_TOKEN` | ✅ | — | Telegram Bot API token |
| `ALLOWED_CHAT_IDS` | ✅ | — | Comma-separated chat IDs |
| `GMAIL_CREDENTIALS` | ❌ | `credentials.json` | Path ke OAuth2 client config |
| `GMAIL_TOKENS` | ❌ | `tokens.json` | Path ke tokens file |

## 🔒 Keamanan

- `credentials.json` dan `tokens.json` masuk `.gitignore` — jangan push ke repo!
- Access control via `ALLOWED_CHAT_IDS` — cuma chat_id yang di-list yang bisa akses
- Token auto-refresh — ga perlu re-auth manual
