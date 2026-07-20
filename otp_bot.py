#!/usr/bin/env python3
"""Telegram OTP Bot — Gmail OAuth2 Multi-Account

Fitur:
  /otp         → pilih akun (inline keyboard) atau /otp <nomor>
  /list        → list semua akun terdaftar (paginated)
  /add         → tambah akun baru (auto-detect ID + auth link)
  /start       → bantuan

Setup:
  1. pip install -r requirements.txt
  2. export BOT_TOKEN="your-telegram-bot-token"
  3. export ALLOWED_CHAT_IDS="123456789"  # comma-separated
  4. Setup Gmail OAuth2 → credentials.json + tokens.json
  5. python3 otp_bot.py
"""

import logging
import os
import sys
import re
import json
import base64
import subprocess
from datetime import datetime
import email.utils
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, CopyTextButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# ─── Config ─────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ALLOWED_CHAT_IDS = set(
    int(x.strip()) for x in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if x.strip()
)

CREDENTIALS_FILE = os.environ.get("GMAIL_CREDENTIALS", "credentials.json")
TOKENS_FILE = os.environ.get("GMAIL_TOKENS", "tokens.json")
GMAIL_SCRIPT = os.environ.get("GMAIL_AUTH_SCRIPT", "gmail_auth.py")
ACCOUNTS_PER_PAGE = 10
LIST_PAGE_SIZE = 50

# ─── State Files ────────────────────────────────────────────────────
AUTH_STATE_FILE = os.environ.get("AUTH_STATE_FILE", ".otp_auth_state.json")
OTP_MODE_FILE = os.environ.get("OTP_MODE_FILE", ".otp_mode_state.json")


# ─── Access Control ─────────────────────────────────────────────────
def is_authorized(update: Update) -> bool:
    """Check apakah user boleh akses bot."""
    return update.effective_chat.id in ALLOWED_CHAT_IDS


async def deny_access(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Kirim pesan akses ditolak."""
    await update.message.reply_text(
        "🚫 <b>Akses Ditolak</b>\n\n"
        "Bot ini hanya untuk authorized users.\n"
        f"Your chat_id: <code>{update.effective_chat.id}</code>",
        parse_mode="HTML",
    )


# ─── State Management ───────────────────────────────────────────────
def load_auth_states():
    """Load auth states from file (chat_id → {account_id, auth_url, ...})."""
    if not os.path.exists(AUTH_STATE_FILE):
        return {}
    try:
        with open(AUTH_STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_auth_states(states):
    """Persist auth states to file."""
    with open(AUTH_STATE_FILE, "w") as f:
        json.dump(states, f, indent=2)


def get_next_account_id():
    """Auto-detect next account ID. Format: account-1, account-2, etc."""
    if not os.path.exists(TOKENS_FILE):
        return "account-1"
    with open(TOKENS_FILE, "r") as f:
        tokens = json.load(f)
    max_num = 0
    for acc_id in tokens.keys():
        match = re.match(r"account-(\d+)", acc_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
    return f"account-{max_num + 1}"


def load_otp_modes():
    """Load OTP mode states (which chats are in 'select account' mode)."""
    if not os.path.exists(OTP_MODE_FILE):
        return {}
    try:
        with open(OTP_MODE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_otp_modes(states):
    """Persist OTP mode states to file."""
    with open(OTP_MODE_FILE, "w") as f:
        json.dump(states, f, indent=2)


def resolve_account_by_number(number_str):
    """Resolve angka ke account ID. '3' → 'account-3', '53' → 'account-53'.

    Also handles 'account-3' direct input.
    Returns (account_id, email) or None.
    """
    accounts = list_accounts()
    # Direct account ID input
    if number_str in accounts:
        return number_str, accounts[number_str]
    # Number-only input: resolve
    acc_id = f"account-{number_str}"
    if acc_id in accounts:
        return acc_id, accounts[acc_id]
    # Try pure number match (no prefix)
    for aid, email in accounts.items():
        num_part = aid.split("-")[-1] if "-" in aid else ""
        if num_part == number_str:
            return aid, email
    return None


# ─── Gmail ──────────────────────────────────────────────────────────
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_credentials(account_id):
    """Load + refresh credentials."""
    if not os.path.exists(TOKENS_FILE):
        return None
    with open(TOKENS_FILE, "r") as f:
        tokens = json.load(f)
    if account_id not in tokens:
        return None
    t = tokens[account_id]
    creds = Credentials(
        token=t.get("token"),
        refresh_token=t.get("refresh_token"),
        token_uri=t.get("token_uri"),
        client_id=t.get("client_id"),
        client_secret=t.get("client_secret"),
        scopes=t.get("scopes"),
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        t["token"] = creds.token
        try:
            service = build("gmail", "v1", credentials=creds)
            profile = service.users().getProfile(userId="me").execute()
            t["email"] = profile.get("emailAddress", "")
        except Exception:
            pass
        with open(TOKENS_FILE, "w") as f:
            json.dump(tokens, f, indent=2)
    return creds


def extract_otp(text, subject=""):
    """Extract OTP code dari text (4-8 digits), with subject-based filtering."""
    skip_patterns = [
        r"persyaratan layanan",
        r"terms of service",
        r"privasi baru",
        r"privacy policy",
        r"google play",
        r"setelan privasi",
        r"your power is locked",
        r"newsletter",
        r"weekly update",
    ]
    for sp in skip_patterns:
        if re.search(sp, subject, re.IGNORECASE):
            return None
    patterns = [
        r">\s*(\d{6})\s*<",
        r"code[:：\s]+(\d{4,8})",
        r"OTP[:：\s]+(\d{4,8})",
        r"verification code[:：\s]+(\d{4,8})",
        r"kode verifikasi[:：\s]+(\d{4,8})",
        r"(\d{4,8})\s+is your",
        r"(?<![#\d])\b(\d{6})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def parse_gmail_date(date_str):
    """Parse Gmail RFC 2822 date string ke datetime."""
    try:
        return email.utils.parsedate_to_datetime(date_str)
    except Exception:
        return None


def get_age_indicator(date_str):
    """Human-readable age dari timestamp email."""
    dt = parse_gmail_date(date_str)
    if not dt:
        return ""
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "⏱️ Baru aja"
    elif seconds < 3600:
        return f"⏱️ {seconds // 60}m lalu"
    elif seconds < 86400:
        return f"⏱️ {seconds // 3600}j lalu"
    else:
        return f"⏱️ {seconds // 86400}h lalu"


def get_latest_otp(account_id):
    """Get latest OTP dari account."""
    creds = get_credentials(account_id)
    if not creds:
        return None
    service = build("gmail", "v1", credentials=creds)
    otp_subject_pattern = re.compile(
        r"(verification|verify|code|otp|kode|verifikasi|authenticator|"
        r"authentication|2fa|mfa|security\s*code|login|signup|sign in|"
        r"register|aktivasi)",
        re.IGNORECASE,
    )
    results = service.users().messages().list(userId="me", maxResults=20).execute()
    messages = results.get("messages", [])
    if not messages:
        return None

    def _get_body(msg):
        """Extract body text from message payload."""
        payload = msg["payload"]
        body = ""
        if payload.get("body", {}).get("data"):
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode(
                "utf-8", errors="ignore"
            )
        if "parts" in payload:
            for part in payload["parts"]:
                if part["mimeType"] == "text/html" and part.get("body", {}).get("data"):
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode(
                        "utf-8", errors="ignore"
                    )
                    break
            if not body:
                for part in payload["parts"]:
                    if part["mimeType"] == "text/plain" and part.get("body", {}).get("data"):
                        body = base64.urlsafe_b64decode(part["body"]["data"]).decode(
                            "utf-8", errors="ignore"
                        )
                        break
        return body

    # Pass 1: OTP-related subjects first
    for msg_summary in messages[:10]:
        msg = service.users().messages().get(
            userId="me", id=msg_summary["id"], format="full"
        ).execute()
        headers = msg["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        from_addr = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
        date = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
        body = _get_body(msg)
        if otp_subject_pattern.search(subject):
            otp = extract_otp(body, subject)
            if otp:
                return {"otp": otp, "from": from_addr, "subject": subject, "date": date}

    # Pass 2: fallback — check all messages without subject filter
    for msg_summary in messages[:10]:
        msg = service.users().messages().get(
            userId="me", id=msg_summary["id"], format="full"
        ).execute()
        headers = msg["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        from_addr = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
        date = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
        body = _get_body(msg)
        if not otp_subject_pattern.search(subject):
            otp = extract_otp(body, subject)
            if otp:
                return {"otp": otp, "from": from_addr, "subject": subject, "date": date}
    return None


def list_accounts():
    """List all registered accounts: {account_id: email}."""
    if not os.path.exists(TOKENS_FILE):
        return {}
    with open(TOKENS_FILE, "r") as f:
        tokens = json.load(f)
    return {acc_id: data.get("email", "") for acc_id, data in tokens.items()}


# ─── Helpers ────────────────────────────────────────────────────────
def escape_html(text):
    """Escape HTML reserved characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def escape_markdown_v2(text):
    """Escape reserved characters for Telegram MarkdownV2."""
    reserved = r"_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in reserved else c for c in text)


# ─── Keyboard Builders ──────────────────────────────────────────────
def build_otp_keyboard(otp_code, account_id, email=""):
    """Build inline keyboard: copy OTP + copy email + refresh button."""
    buttons = []
    try:
        row1 = [InlineKeyboardButton(
            text=f"📋 Copy OTP: {otp_code}",
            copy_text=CopyTextButton(text=otp_code),
        )]
        if email:
            row1.append(InlineKeyboardButton(
                text="📋 Copy Email",
                copy_text=CopyTextButton(text=email),
            ))
        buttons.append(row1)
        buttons.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")])
        return InlineKeyboardMarkup(buttons)
    except Exception:
        # Fallback without CopyTextButton (older PTB versions)
        row1 = [InlineKeyboardButton(text=f"📋 Copy: {otp_code}", callback_data=f"copy:{otp_code}")]
        if email:
            row1.append(InlineKeyboardButton(text="📋 Email", callback_data=f"copy:{email}"))
        buttons.append(row1)
        buttons.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")])
        return InlineKeyboardMarkup(buttons)


def build_account_keyboard(accounts, page=0):
    """Buat keyboard paginated — 2 kolom per baris, 10 per halaman, wrap-around + cancel."""
    sorted_accs = sorted(
        accounts.keys(),
        key=lambda x: int(x.split("-")[-1]) if x.split("-")[-1].isdigit() else x,
    )
    total = len(sorted_accs)
    total_pages = max(1, (total + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    start = page * ACCOUNTS_PER_PAGE
    end = min(start + ACCOUNTS_PER_PAGE, total)
    page_accs = sorted_accs[start:end]

    keyboard = []
    row = []
    for i, acc_id in enumerate(page_accs):
        row.append(InlineKeyboardButton(acc_id, callback_data=f"otp_info:{acc_id}"))
        if len(row) == 2 or i == len(page_accs) - 1:
            keyboard.append(row)
            row = []

    nav_row = [
        InlineKeyboardButton("⬅️", callback_data=f"page:{page - 1 if page > 0 else total_pages - 1}"),
        InlineKeyboardButton(f"📄 {page + 1}/{total_pages}", callback_data="page_info"),
        InlineKeyboardButton("➡️", callback_data=f"page:{page + 1 if end < total else 0}"),
    ]
    keyboard.append(nav_row)
    keyboard.append([InlineKeyboardButton("❌ Tutup", callback_data="otp_cancel")])

    return InlineKeyboardMarkup(keyboard), total_pages, page


def build_auth_keyboard(account_id):
    """Build inline keyboard untuk flow add account."""
    keyboard = [
        [
            InlineKeyboardButton("🔄 Refresh Link", callback_data=f"auth_refresh:{account_id}"),
            InlineKeyboardButton("❌ Cancel", callback_data=f"auth_cancel:{account_id}"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


# ─── Display Helpers ────────────────────────────────────────────────
async def _show_otp(message, account_id):
    """Fetch OTP dan tampilkan dengan refresh button + age indicator + email copy."""
    accounts = list_accounts()
    email = accounts.get(account_id, "")
    try:
        result = get_latest_otp(account_id)
    except Exception as e:
        err_msg = str(e).lower()
        keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}"),
        ]])
        if "invalid_grant" in err_msg or "expired" in err_msg or "revoked" in err_msg:
            await message.reply_text(
                f"⚠️ Token expired untuk `{escape_markdown_v2(account_id)}`\n"
                f"📧 {escape_markdown_v2(email)}\n\n"
                f"Perlu re-auth. Ketik /add {account_id}",
                reply_markup=keyboard,
                parse_mode="MarkdownV2",
            )
        else:
            await message.reply_text(
                f"❌ Error: `{escape_markdown_v2(str(e)[:200])}`",
                reply_markup=keyboard,
                parse_mode="MarkdownV2",
            )
        return
    if result:
        otp = result["otp"]
        age = get_age_indicator(result["date"])
        reply = (
            f"🔐 OTP untuk {escape_markdown_v2(account_id)}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Kode: `{otp}`  {age}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📨 {escape_markdown_v2(email) if email else escape_markdown_v2(result['from'])}\n"
            f"📝 {escape_markdown_v2(result['subject'])}"
        )
        keyboard = build_otp_keyboard(otp, account_id, email)
        await message.reply_text(reply, reply_markup=keyboard, parse_mode="MarkdownV2")
    else:
        keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}"),
        ]])
        await message.reply_text(
            f"❌ OTP tidak ditemukan untuk `{escape_markdown_v2(account_id)}`.",
            reply_markup=keyboard,
            parse_mode="MarkdownV2",
        )


async def _generate_auth_url(account_id):
    """Generate auth URL via gmail_auth.py script. Return (url, error)."""
    try:
        env = os.environ.copy()
        result = subprocess.run(
            ["python3", GMAIL_SCRIPT, "url", account_id],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if result.returncode != 0:
            return None, result.stderr or result.stdout
        output = result.stdout
        for line in output.split("\n"):
            if line.startswith("http"):
                return line.strip(), None
        return None, f"Gagal extract URL. Output:\n{output[:2000]}"
    except Exception as e:
        return None, str(e)


def _build_account_info_text(account_id, email):
    """Build text for account info display."""
    if email:
        return (
            f"📧 {escape_markdown_v2(account_id)}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✉️ {escape_markdown_v2(email)}"
        )
    else:
        return (
            f"📧 {escape_markdown_v2(account_id)}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"*(email belum terdaftar)*"
        )


def _build_account_info_keyboard(account_id, email):
    """Build keyboard for account info: email copy + OTP button."""
    if email:
        try:
            return InlineKeyboardMarkup([
                [InlineKeyboardButton(
                    text="📋 Copy Email",
                    copy_text=CopyTextButton(text=email),
                )],
                [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")],
            ])
        except Exception:
            return InlineKeyboardMarkup([
                [InlineKeyboardButton("📋 Email", callback_data=f"copy:{email}")],
                [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")],
            ])
    else:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")]
        ])


async def _show_account_info(message, account_id, email, edit=False):
    """Tampilkan info akun dengan email copy button + OTP button."""
    text = _build_account_info_text(account_id, email)
    keyboard = _build_account_info_keyboard(account_id, email)
    if edit:
        await message.edit_text(text, reply_markup=keyboard, parse_mode="MarkdownV2")
    else:
        await message.reply_text(text, reply_markup=keyboard, parse_mode="MarkdownV2")


async def _send_auth_message(update_or_query, account_id, auth_url, is_edit=False):
    """Kirim/edit pesan auth dengan link + keyboard. Return message_id."""
    text = (
        f"📩 <b>Menambahkan {account_id}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <b>Buka link ini di browser:</b>\n"
        f"{auth_url}\n\n"
        f"📌 Login Google → klik <b>Allow</b> → <b>Copy kode</b> dari URL browser\n"
        f"⏱️ Link valid ~5 menit\n"
        f"━━━━━━━━━━━━━━━━━━━━━━"
    )
    keyboard = build_auth_keyboard(account_id)
    if is_edit:
        msg = await update_or_query.message.edit_text(text, reply_markup=keyboard, parse_mode="HTML")
    else:
        msg = await update_or_query.message.reply_text(text, reply_markup=keyboard, parse_mode="HTML")
    return msg.message_id


# ─── List Page Helper ────────────────────────────────────────────────
async def _show_list_page(message, accounts, page=0, edit=False):
    """Show paginated list — 50 per page, numbered, copyable columns."""
    sorted_accs = sorted(
        accounts.keys(),
        key=lambda x: int(x.split("-")[-1]) if x.split("-")[-1].isdigit() else x,
    )
    total = len(sorted_accs)
    total_pages = max(1, (total + LIST_PAGE_SIZE - 1) // LIST_PAGE_SIZE)
    start = page * LIST_PAGE_SIZE
    end = min(start + LIST_PAGE_SIZE, total)
    page_accs = sorted_accs[start:end]

    lines = []
    for i, acc_id in enumerate(page_accs, start + 1):
        email = accounts[acc_id]
        safe_acc = escape_html(acc_id)
        if email:
            safe_email = escape_html(email)
            lines.append(f"<code>{i}. {safe_acc}</code> → <code>{safe_email}</code>")
        else:
            lines.append(f"<code>{i}. {safe_acc}</code>")

    reply = f"📬 <b>Akun ({start + 1}-{end} / {total})</b>\n━━━━━━━━━━━━━━━━━━\n" + "\n".join(lines)

    nav_row = [
        InlineKeyboardButton("⬅️", callback_data=f"list_page:{page - 1 if page > 0 else total_pages - 1}"),
        InlineKeyboardButton(f"📄 {page + 1}/{total_pages}", callback_data="page_info"),
        InlineKeyboardButton("➡️", callback_data=f"list_page:{page + 1 if end < total else 0}"),
    ]
    keyboard = [nav_row, [InlineKeyboardButton("❌ Tutup", callback_data="list_cancel")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    if edit:
        await message.edit_text(reply, reply_markup=reply_markup, parse_mode="HTML")
    else:
        await message.reply_text(reply, reply_markup=reply_markup, parse_mode="HTML")


# ─── Callback Handler ───────────────────────────────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id not in ALLOWED_CHAT_IDS:
        await update.callback_query.answer("🚫 Akses ditolak", show_alert=True)
        return
    query = update.callback_query
    await query.answer()

    data = query.data

    # ── COPY (fallback) ──
    if data.startswith("copy:"):
        copy_text = data.split(":", 1)[1]
        await query.message.reply_text(f"`{copy_text}`", parse_mode="MarkdownV2")

    # ── CANCEL ──
    elif data == "otp_cancel":
        try:
            await query.message.delete()
        except Exception:
            await query.message.edit_text("👋 Tutup~")

    elif data == "list_cancel":
        try:
            await query.message.delete()
        except Exception:
            await query.message.edit_text("👋 Tutup~")

    # ── LIST PAGE NAVIGATION ──
    elif data.startswith("list_page:"):
        page = int(data.split(":", 1)[1])
        accounts = list_accounts()
        await _show_list_page(query.message, accounts, page, edit=True)

    # ── PAGE NAVIGATION ──
    elif data.startswith("page:"):
        page = int(data.split(":", 1)[1])
        accounts = list_accounts()
        reply_markup, _, _ = build_account_keyboard(accounts, page)
        await query.message.edit_text("📬 Pilih akun untuk cek OTP:", reply_markup=reply_markup)

    elif data == "page_info":
        pass

    # ── OTP INFO ──
    elif data.startswith("otp_info:"):
        account_id = data.split(":", 1)[1]
        accounts = list_accounts()
        email = accounts.get(account_id, "")
        await _show_account_info(query.message, account_id, email, edit=True)

    # ── OTP SELECT ──
    elif data.startswith("otp_select:"):
        account_id = data.split(":", 1)[1]
        await query.message.edit_text(f"🔍 Cek OTP untuk {account_id}...")
        await _show_otp(query.message, account_id)

    # ── OTP REFRESH ──
    elif data.startswith("otp_refresh:"):
        account_id = data.split(":", 1)[1]
        try:
            await query.message.edit_text(f"🔄 Refresh OTP untuk {account_id}...")
        except Exception:
            pass
        await _show_otp(query.message, account_id)

    # ── AUTH FLOW: REFRESH LINK ──
    elif data.startswith("auth_refresh:"):
        account_id = data.split(":", 1)[1]
        chat_id = str(update.effective_chat.id)

        await query.message.edit_text(f"🔄 Merefresh link auth untuk {account_id}...")

        url, error = await _generate_auth_url(account_id)
        if error:
            await query.message.edit_text(f"❌ Error: {error[:2000]}")
            return

        # Update state
        states = load_auth_states()
        if chat_id in states:
            states[chat_id]["auth_url"] = url
            save_auth_states(states)

        await _send_auth_message(query, account_id, url, is_edit=True)

    # ── AUTH FLOW: CANCEL ──
    elif data.startswith("auth_cancel:"):
        account_id = data.split(":", 1)[1]
        chat_id = str(update.effective_chat.id)

        states = load_auth_states()
        if chat_id in states:
            del states[chat_id]
            save_auth_states(states)

        await query.message.delete()


# ─── Command Handlers ───────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny_access(update, context)
        return
    await update.message.reply_text(
        "🤖 **OTP Bot v4 — Ketik Nomor + Copy Email!** 🚀\n\n"
        "**Commands:**\n"
        "/otp — Pilih akun (tap button atau ketik nomor) 🎯\n"
        "/otp <nomor/id> — Cek langsung (misal: /otp 3 = account-3)\n"
        "/list — Lihat semua akun + email\n"
        "/add — Tambah akun baru (auto-detect ID + link auth) ✨\n"
        "/start — Bantuan ini\n\n"
        "💡 *Tip:* Ketik /otp lalu ketik angka akun (misal: `3`) untuk info + copy email!"
    )


async def otp_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny_access(update, context)
        return
    args = context.args
    accounts = list_accounts()

    if not accounts:
        await update.message.reply_text("Belum ada akun terdaftar. Gunakan /add untuk menambah.")
        return

    if not args:
        # No args — show keyboard + enter OTP mode (ketik angka)
        if len(accounts) == 1:
            account_id = list(accounts.keys())[0]
            await update.message.reply_text(f"🔍 Cek OTP untuk `{account_id}`...", parse_mode="MarkdownV2")
            await _show_otp(update.message, account_id)
        else:
            chat_id = str(update.effective_chat.id)
            modes = load_otp_modes()
            reply_markup, _, _ = build_account_keyboard(accounts, 0)
            prompt_msg = await update.message.reply_text(
                "📬 Pilih akun — tap button atau ketik nomor",
                reply_markup=reply_markup,
            )
            modes[chat_id] = {"mode": "otp_select", "prompt_msg_id": prompt_msg.message_id}
            save_otp_modes(modes)
        return

    # Direct account ID or number
    resolved = resolve_account_by_number(args[0].strip())
    if not resolved:
        await update.message.reply_text(
            f"❌ Akun '{args[0].strip()}' tidak ditemukan.\n"
            "Gunakan /list untuk melihat akun."
        )
        return

    account_id, _ = resolved
    await update.message.reply_text(f"🔍 Cek OTP untuk `{account_id}`...", parse_mode="MarkdownV2")
    await _show_otp(update.message, account_id)


async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Paginated list — 50 per halaman, numbered, copyable, close button."""
    if not is_authorized(update):
        await deny_access(update, context)
        return
    accounts = list_accounts()
    if not accounts:
        await update.message.reply_text("Belum ada akun terdaftar.")
        return
    await _show_list_page(update.message, accounts, 0)


async def add_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Auto-detect next ID, generate auth URL, kirim dengan keyboard."""
    if not is_authorized(update):
        await deny_access(update, context)
        return
    account_id = get_next_account_id()
    chat_id = str(update.effective_chat.id)

    await update.message.reply_text(f"⏳ Generating auth URL untuk `{account_id}`...")

    url, error = await _generate_auth_url(account_id)
    if error:
        await update.message.reply_text(f"❌ Error: {error[:2000]}")
        return

    # Simpan state
    states = load_auth_states()
    states[chat_id] = {
        "account_id": account_id,
        "auth_url": url,
        "waiting_code": True,
        "generated_at": datetime.now().isoformat(),
    }
    save_auth_states(states)

    msg_id = await _send_auth_message(update, account_id, url)
    # Update state dengan message_id
    states = load_auth_states()
    if chat_id in states:
        states[chat_id]["message_id"] = msg_id
        save_auth_states(states)


# ─── Message Handler ────────────────────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Menangkap input teks biasa.

    1) Kalau dalam OTP mode → detect angka → tampil info akun (email copy)
    2) Kalau dalam auth flow → proses sebagai auth code.
    """
    if not is_authorized(update):
        return
    chat_id = str(update.effective_chat.id)
    text = update.message.text.strip()

    # ── OTP MODE: ketik angka → info akun ──
    modes = load_otp_modes()
    if chat_id in modes and modes[chat_id].get("mode") == "otp_select":
        resolved = resolve_account_by_number(text)
        if resolved:
            account_id, email = resolved
            del modes[chat_id]
            save_otp_modes(modes)
            # Delete prompt + user's message for clean chat
            prompt_msg_id = modes[chat_id].get("prompt_msg_id") if chat_id in modes else None
            try:
                if prompt_msg_id:
                    await context.bot.delete_message(chat_id=chat_id, message_id=prompt_msg_id)
            except Exception:
                pass
            try:
                await update.message.delete()
            except Exception:
                pass
            await context.bot.send_message(
                chat_id=chat_id,
                text=_build_account_info_text(account_id, email),
                reply_markup=_build_account_info_keyboard(account_id, email),
                parse_mode="MarkdownV2",
            )
            return

        accounts = list_accounts()
        max_num = max(
            (int(a.split("-")[-1]) for a in accounts.keys() if a.split("-")[-1].isdigit()),
            default=0,
        )
        await update.message.reply_text(
            f"❌ Akun '{text}' tidak ditemukan.\n"
            f"Ketik nomor 1-{max_num} atau ID lengkap (misal: account-3)"
        )
        return

    # ── AUTH FLOW: waiting for auth code ──
    states = load_auth_states()
    if chat_id not in states or not states[chat_id].get("waiting_code"):
        return

    state = states[chat_id]
    account_id = state["account_id"]
    auth_message_id = state.get("message_id")

    # Hapus state biar ga double process
    del states[chat_id]
    save_auth_states(states)

    # Edit pesan auth jadi "processing..."
    try:
        auth_msg = await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=auth_message_id,
            text=f"⏳ Exchanging code untuk <code>{account_id}</code>...",
            parse_mode="HTML",
        )
    except Exception:
        auth_msg = None

    # Process auth code via gmail_auth.py
    try:
        env = os.environ.copy()
        result = subprocess.run(
            ["python3", GMAIL_SCRIPT, "token", account_id, text],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if result.returncode != 0:
            await update.message.reply_text(f"❌ Error: {result.stderr or result.stdout}")
            return

        output = result.stdout

        # Fetch email
        try:
            creds = get_credentials(account_id)
            if creds:
                service = build("gmail", "v1", credentials=creds)
                profile = service.users().getProfile(userId="me").execute()
                email = profile.get("emailAddress", "")
                with open(TOKENS_FILE, "r") as f:
                    tokens = json.load(f)
                if account_id in tokens:
                    tokens[account_id]["email"] = email
                    with open(TOKENS_FILE, "w") as f:
                        json.dump(tokens, f, indent=2)
                    output += f"\n📧 Email: {email}"
        except Exception:
            pass

        success_text = f"✅ <b>Sukses!</b> <code>{account_id}</code> berhasil ditambahkan~ 🎉\n\n{output[:2000]}"

        if auth_msg:
            try:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=auth_message_id,
                    text=success_text,
                    parse_mode="HTML",
                )
            except Exception:
                await update.message.reply_text(success_text, parse_mode="HTML")
        else:
            await update.message.reply_text(success_text, parse_mode="HTML")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")


# ─── Main ───────────────────────────────────────────────────────────
def main():
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("otp", otp_command))
    app.add_handler(CommandHandler("list", list_command))
    app.add_handler(CommandHandler("add", add_command))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
