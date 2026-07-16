#!/usr/bin/env python3
"""Telegram OTP Bot — Gmail OAuth2 Multi-Account

Fitur:
  /otp         → pilih akun (inline keyboard) atau /otp <nomor>
  /list        → list semua akun terdaftar
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
import re
import json
import base64
import email.utils
from datetime import datetime

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

ACCOUNTS_PER_PAGE = 10
LIST_PAGE_SIZE = 50

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# ─── Access Control ─────────────────────────────────────────────────
def is_authorized(update: Update) -> bool:
    return update.effective_chat.id in ALLOWED_CHAT_IDS

async def deny_access(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🚫 <b>Akses Ditolak</b>\n\n"
        "Bot ini hanya untuk authorized users.\n"
        f"Your chat_id: <code>{update.effective_chat.id}</code>",
        parse_mode="HTML",
    )

# ─── Account Management ─────────────────────────────────────────────
def list_accounts() -> dict:
    """Return {account_id: email} dari tokens.json."""
    if not os.path.exists(TOKENS_FILE):
        return {}
    with open(TOKENS_FILE, "r") as f:
        tokens = json.load(f)
    return {acc_id: data.get("email", "") for acc_id, data in tokens.items()}

def resolve_account_by_number(number_str: str):
    """Resolve angka ke account ID. '3' → 'account-3'. Returns (account_id, email) or None."""
    accounts = list_accounts()
    if number_str in accounts:
        return number_str, accounts[number_str]
    acc_id = f"account-{number_str}"
    if acc_id in accounts:
        return acc_id, accounts[acc_id]
    for aid, email in accounts.items():
        num_part = aid.split("-")[-1] if "-" in aid else ""
        if num_part == number_str:
            return aid, email
    return None

# ─── Gmail / OTP Extraction ─────────────────────────────────────────
def get_credentials(account_id: str):
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
        with open(TOKENS_FILE, "w") as f:
            json.dump(tokens, f, indent=2)
    return creds

def extract_otp(text: str, subject: str = ""):
    """Extract OTP code (4-8 digits) dari email body."""
    skip_patterns = [
        r"persyaratan layanan", r"terms of service", r"privasi baru",
        r"privacy policy", r"google play", r"setelan privasi",
        r"your power is locked", r"newsletter", r"weekly update",
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

def parse_gmail_date(date_str: str):
    try:
        return email.utils.parsedate_to_datetime(date_str)
    except Exception:
        return None

def get_age_indicator(date_str: str) -> str:
    dt = parse_gmail_date(date_str)
    if not dt:
        return ""
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    seconds = int((now - dt).total_seconds())
    if seconds < 60:
        return "⏱️ Baru aja"
    elif seconds < 3600:
        return f"⏱️ {seconds // 60}m lalu"
    elif seconds < 86400:
        return f"⏱️ {seconds // 3600}j lalu"
    else:
        return f"⏱️ {seconds // 86400}h lalu"

def get_latest_otp(account_id: str):
    """Fetch latest OTP dari Gmail account."""
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

    for msg_summary in messages[:10]:
        msg = service.users().messages().get(userId="me", id=msg_summary["id"], format="full").execute()
        headers = msg["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        from_addr = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
        date = next((h["value"] for h in headers if h["name"].lower() == "date"), "")

        body = _extract_body(msg["payload"])
        if otp_subject_pattern.search(subject):
            otp = extract_otp(body, subject)
            if otp:
                return {"otp": otp, "from": from_addr, "subject": subject, "date": date}

    # Fallback: scan all without subject filter
    for msg_summary in messages[:10]:
        msg = service.users().messages().get(userId="me", id=msg_summary["id"], format="full").execute()
        headers = msg["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        from_addr = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
        date = next((h["value"] for h in headers if h["name"].lower() == "date"), "")

        body = _extract_body(msg["payload"])
        otp = extract_otp(body, subject)
        if otp:
            return {"otp": otp, "from": from_addr, "subject": subject, "date": date}

    return None

def _extract_body(payload: dict) -> str:
    """Extract text/html atau text/plain dari MIME payload."""
    if payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/html" and part.get("body", {}).get("data"):
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain" and part.get("body", {}).get("data"):
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
    return ""

# ─── Helpers ────────────────────────────────────────────────────────
def escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def escape_markdown_v2(text: str) -> str:
    reserved = r"_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in reserved else c for c in text)

def build_otp_keyboard(otp_code: str, account_id: str, email: str = ""):
    buttons = []
    try:
        row1 = [InlineKeyboardButton(text=f"📋 Copy OTP: {otp_code}", copy_text=CopyTextButton(text=otp_code))]
        if email:
            row1.append(InlineKeyboardButton(text="📋 Copy Email", copy_text=CopyTextButton(text=email)))
        buttons.append(row1)
        buttons.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")])
        return InlineKeyboardMarkup(buttons)
    except Exception:
        row1 = [InlineKeyboardButton(text=f"📋 Copy: {otp_code}", callback_data=f"copy:{otp_code}")]
        if email:
            row1.append(InlineKeyboardButton(text="📋 Email", callback_data=f"copy:{email}"))
        buttons.append(row1)
        buttons.append([InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")])
        return InlineKeyboardMarkup(buttons)

def build_account_keyboard(accounts: dict, page: int = 0):
    """2 kolom per baris, ACCOUNTS_PER_PAGE per halaman, wrap-around."""
    sorted_accs = sorted(accounts.keys(), key=lambda x: int(x.split("-")[-1]) if x.split("-")[-1].isdigit() else x)
    total = len(sorted_accs)
    total_pages = max(1, (total + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    start = page * ACCOUNTS_PER_PAGE
    end = min(start + ACCOUNTS_PER_PAGE, total)
    page_accs = sorted_accs[start:end]

    keyboard, row = [], []
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

def _build_account_info_text(account_id: str, email: str) -> str:
    if email:
        return (
            f"📧 {escape_markdown_v2(account_id)}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✉️ {escape_markdown_v2(email)}"
        )
    return (
        f"📧 {escape_markdown_v2(account_id)}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"*(email belum terdaftar)*"
    )

def _build_account_info_keyboard(account_id: str, email: str):
    if email:
        try:
            return InlineKeyboardMarkup([
                [InlineKeyboardButton(text="📋 Copy Email", copy_text=CopyTextButton(text=email))],
                [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")],
            ])
        except Exception:
            return InlineKeyboardMarkup([
                [InlineKeyboardButton("📋 Email", callback_data=f"copy:{email}")],
                [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")],
            ])
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔐 Ambil OTP", callback_data=f"otp_select:{account_id}")]
    ])

# ─── Command Handlers ───────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny_access(update, context); return
    await update.message.reply_text(
        "🤖 **OTP Bot v4 — Ketik Nomor + Copy Email!** 🚀\n\n"
        "**Commands:**\n"
        "/otp — Pilih akun (tap button atau ketik nomor) 🎯\n"
        "/otp <nomor/id> — Cek langsung (misal: /otp 3 = account-3)\n"
        "/list — Lihat semua akun + email\n"
        "/start — Bantuan ini\n\n"
        "💡 *Tip:* Ketik /otp lalu ketik angka akun (misal: `3`) untuk info + copy email!"
    )

async def otp_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny_access(update, context); return
    args = context.args
    accounts = list_accounts()

    if not accounts:
        await update.message.reply_text("Belum ada akun terdaftar.")
        return

    if not args:
        if len(accounts) == 1:
            account_id = list(accounts.keys())[0]
            await update.message.reply_text(f"🔍 Cek OTP untuk `{account_id}`...", parse_mode="MarkdownV2")
            await _show_otp(update.message, account_id)
        else:
            reply_markup, _, _ = build_account_keyboard(accounts, 0)
            await update.message.reply_text("📬 Pilih akun — tap button atau ketik nomor", reply_markup=reply_markup)
        return

    resolved = resolve_account_by_number(args[0].strip())
    if not resolved:
        await update.message.reply_text(f"❌ Akun '{args[0].strip()}' tidak ditemukan.\nGunakan /list untuk melihat akun.")
        return

    account_id, _ = resolved
    await update.message.reply_text(f"🔍 Cek OTP untuk `{account_id}`...", parse_mode="MarkdownV2")
    await _show_otp(update.message, account_id)

async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny_access(update, context); return
    accounts = list_accounts()
    if not accounts:
        await update.message.reply_text("Belum ada akun terdaftar.")
        return
    await _show_list_page(update.message, accounts, 0)

# ─── Display Helpers ────────────────────────────────────────────────
async def _show_otp(message, account_id: str) -> None:
    accounts = list_accounts()
    email = accounts.get(account_id, "")
    try:
        result = get_latest_otp(account_id)
    except Exception as e:
        err_msg = str(e).lower()
        keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")
        ]])
        if "invalid_grant" in err_msg or "expired" in err_msg or "revoked" in err_msg:
            await message.reply_text(
                f"⚠️ Token expired untuk `{escape_markdown_v2(account_id)}`\\n"
                f"📧 {escape_markdown_v2(email)}\\n\\n"
                f"Perlu re\\-auth\\.",
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
            InlineKeyboardButton("🔄 Refresh", callback_data=f"otp_refresh:{account_id}")
        ]])
        await message.reply_text(
            f"❌ OTP tidak ditemukan untuk `{escape_markdown_v2(account_id)}`.",
            reply_markup=keyboard,
            parse_mode="MarkdownV2",
        )

async def _show_account_info(message, account_id: str, email: str, edit: bool = False) -> None:
    text = _build_account_info_text(account_id, email)
    keyboard = _build_account_info_keyboard(account_id, email)
    if edit:
        await message.edit_text(text, reply_markup=keyboard, parse_mode="MarkdownV2")
    else:
        await message.reply_text(text, reply_markup=keyboard, parse_mode="MarkdownV2")

async def _show_list_page(message, accounts: dict, page: int = 0, edit: bool = False) -> None:
    sorted_accs = sorted(accounts.keys(), key=lambda x: int(x.split("-")[-1]) if x.split("-")[-1].isdigit() else x)
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

    reply = f"📬 <b>Akun ({start+1}-{end} / {total})</b>\n━━━━━━━━━━━━━━━━━━\n" + "\n".join(lines)
    nav_row = [
        InlineKeyboardButton("⬅️", callback_data=f"list_page:{page - 1 if page > 0 else total_pages - 1}"),
        InlineKeyboardButton(f"📄 {page + 1}/{total_pages}", callback_data="page_info"),
        InlineKeyboardButton("➡️", callback_data=f"list_page:{page + 1 if end < total else 0}"),
    ]
    keyboard = [nav_row, [InlineKeyboardButton("❌ Tutup", callback_data="list_cancel")]]
    if edit:
        await message.edit_text(reply, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="HTML")
    else:
        await message.reply_text(reply, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="HTML")

# ─── Callback Handler ───────────────────────────────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.id not in ALLOWED_CHAT_IDS:
        await update.callback_query.answer("🚫 Akses ditolak", show_alert=True); return
    query = update.callback_query
    await query.answer()
    data = query.data

    if data.startswith("copy:"):
        copy_text = data.split(":", 1)[1]
        await query.message.reply_text(f"`{copy_text}`", parse_mode="MarkdownV2")
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
    elif data.startswith("list_page:"):
        page = int(data.split(":", 1)[1])
        await _show_list_page(query.message, list_accounts(), page, edit=True)
    elif data.startswith("page:"):
        page = int(data.split(":", 1)[1])
        reply_markup, _, _ = build_account_keyboard(list_accounts(), page)
        await query.message.edit_text("📬 Pilih akun untuk cek OTP:", reply_markup=reply_markup)
    elif data == "page_info":
        pass
    elif data.startswith("otp_info:"):
        account_id = data.split(":", 1)[1]
        accounts = list_accounts()
        await _show_account_info(query.message, account_id, accounts.get(account_id, ""), edit=True)
    elif data.startswith("otp_select:"):
        account_id = data.split(":", 1)[1]
        await query.message.edit_text(f"🔍 Cek OTP untuk {account_id}...")
        await _show_otp(query.message, account_id)
    elif data.startswith("otp_refresh:"):
        account_id = data.split(":", 1)[1]
        try:
            await query.message.edit_text(f"🔄 Refresh OTP untuk {account_id}...")
        except Exception:
            pass
        await _show_otp(query.message, account_id)

# ─── Message Handler (ketik nomor) ──────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Ketik angka → info akun + copy email."""
    if not is_authorized(update):
        return
    chat_id = str(update.effective_chat.id)
    text = update.message.text.strip()

    resolved = resolve_account_by_number(text)
    if resolved:
        account_id, email = resolved
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
    if accounts:
        max_num = max((int(a.split("-")[-1]) for a in accounts.keys() if a.split("-")[-1].isdigit()), default=0)
        await update.message.reply_text(
            f"❌ Akun '{text}' tidak ditemukan.\nKetik nomor 1-{max_num} atau ID lengkap (misal: account-3)"
        )

# ─── Main ───────────────────────────────────────────────────────────
def main():
    if not BOT_TOKEN:
        logging.error("BOT_TOKEN tidak diset! Export dulu: export BOT_TOKEN='...'")
        return

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("otp", otp_command))
    app.add_handler(CommandHandler("list", list_command))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
