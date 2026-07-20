# 🤖 Telegram OTP Bot — Gmail Multi-Account

Bot Telegram untuk ambil OTP dari multiple Gmail accounts via Google API OAuth2.

## ✨ Fitur

| Fitur | Deskripsi |
|-------|-----------|
| 🔐 **Auto-detect OTP** | 4-8 digit codes dari inbox Gmail dengan subject-based filtering |
| 📋 **Copy button** | Tap untuk copy OTP atau email langsung |
| 📬 **Multi-account** | Kelola banyak akun Gmail sekaligus (pagination 10/halaman) |
| ⏱️ **Age indicator** | Tahu OTP baru atau lama (contoh: "Baru aja", "5m lalu") |
| 🔄 **Refresh** | Refresh OTP tanpa ulang command — tap tombol 🔄 |
| ➕ **Tambah akun** | `/add` — auto-detect ID, generate auth link, exchange code inline |
| 🔢 **Ketik nomor** | `/otp` → muncul keyboard → ketik angka (misal `3`) buat pilih akun |
| 📑 **List paginated** | `/list` — 50 akun per halaman dengan navigasi |
| 🔒 **Access control** | Whitelist via `ALLOWED_CHAT_IDS` |
| 💾 **State persistence** | Auth flow dan OTP mode tetap aman meski bot restart |

## 📋 Commands

| Command | Deskripsi |
|---------|-----------|
| `/otp` | Pilih akun dari inline keyboard (atau ketik nomor) |
| `/otp <nomor>` | Cek langsung (misal: `/otp 3` = account-3) |
| `/list` | Lihat semua akun terdaftar (paginated, 50/halaman) |
| `/add` | Tambah akun baru — auto-detect ID + link auth |
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
- Buat project baru → enable **Gmail API**
- Buat OAuth2 credentials (Desktop app) → download `credentials.json`
- Setup auth script (`gmail_auth.py`) untuk generate token per akun

### 4. Set Environment Variables

```bash
# Required
export BOT_TOKEN="your-telegram-bot-token"
export ALLOWED_CHAT_IDS="123456789"  # chat_id kamu (comma-separated)

# Optional — defaults shown
export GMAIL_CREDENTIALS="credentials.json"   # Google OAuth2 client config
export GMAIL_TOKENS="tokens.json"              # Tokens file per akun
export GMAIL_AUTH_SCRIPT="gmail_auth.py"       # Auth helper script
export AUTH_STATE_FILE=".otp_auth_state.json"  # Auth flow state persistence
export OTP_MODE_FILE=".otp_mode_state.json"    # OTP mode state persistence
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
| `ALLOWED_CHAT_IDS` | ✅ | — | Comma-separated chat IDs yang diizinkan |
| `GMAIL_CREDENTIALS` | ❌ | `credentials.json` | Path ke Google OAuth2 client config |
| `GMAIL_TOKENS` | ❌ | `tokens.json` | Path ke tokens file |
| `GMAIL_AUTH_SCRIPT` | ❌ | `gmail_auth.py` | Path ke script auth helper |
| `AUTH_STATE_FILE` | ❌ | `.otp_auth_state.json` | State file untuk flow auth |
| `OTP_MODE_FILE` | ❌ | `.otp_mode_state.json` | State file untuk OTP mode selection |

## 🔒 Keamanan

- `credentials.json` dan `tokens.json` masuk `.gitignore` — jangan push ke repo!
- Access control via `ALLOWED_CHAT_IDS` — cuma chat_id yang di-list yang bisa akses
- Token auto-refresh — ga perlu re-auth manual
- State files juga di `.gitignore` — aman dari commit tidak sengaja
