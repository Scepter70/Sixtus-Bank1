from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Iterator

import streamlit as st
import requests
from streamlit.components.v1 import html as st_html


APP_TITLE = "Sixtus Bank"
DB_PATH = Path(__file__).with_name("banking.db")

SUPPORTED_CURRENCIES = {
    "USD": {"name": "US Dollar", "symbol": "$", "usd_per_unit": "1"},
    "EUR": {"name": "Euro", "symbol": "€", "usd_per_unit": "1.09"},
    "GBP": {"name": "British Pound", "symbol": "£", "usd_per_unit": "1.28"},
    "CAD": {"name": "Canadian Dollar", "symbol": "C$", "usd_per_unit": "0.73"},
    "AUD": {"name": "Australian Dollar", "symbol": "A$", "usd_per_unit": "0.66"},
    "CHF": {"name": "Swiss Franc", "symbol": "CHF ", "usd_per_unit": "1.12"},
    "JPY": {"name": "Japanese Yen", "symbol": "¥", "usd_per_unit": "0.0067"},
    "NGN": {"name": "Nigerian Naira", "symbol": "₦", "usd_per_unit": "0.00065"},
}

# ── Color palette ──
GOLD = "#c9a227"
GOLD_LIGHT = "#e8d5a3"
DARK_BG = "#0a0e1a"
TEXT_PRIMARY = "#e8ecf1"
TEXT_SECONDARY = "#8b9bb4"
SUCCESS = "#27ae60"
DANGER = "#e74c3c"


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database() -> None:
    with get_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('customer', 'admin')),
                account_number TEXT NOT NULL UNIQUE,
                balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                transaction_type TEXT NOT NULL CHECK (
                    transaction_type IN ('deposit', 'withdrawal')
                ),
                currency TEXT NOT NULL DEFAULT 'USD',
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                balance_after_cents INTEGER NOT NULL CHECK (balance_after_cents >= 0),
                note TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                currency TEXT NOT NULL,
                balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
                UNIQUE (user_id, currency)
            );

            CREATE TABLE IF NOT EXISTS exchange_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                from_currency TEXT NOT NULL,
                from_amount_cents INTEGER NOT NULL CHECK (from_amount_cents > 0),
                to_currency TEXT NOT NULL,
                to_amount_cents INTEGER NOT NULL CHECK (to_amount_cents > 0),
                exchange_rate TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        # Backwards compatibility
        transaction_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(transactions)")
        }
        if "currency" not in transaction_columns:
            connection.execute(
                "ALTER TABLE transactions ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'"
            )

        # Ensure wallets exist for all users
        for existing_user in connection.execute("SELECT id, balance_cents FROM users"):
            ensure_user_wallets(connection, existing_user["id"], existing_user["balance_cents"])


def has_admin() -> bool:
    with get_db() as connection:
        return connection.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone() is not None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return f"pbkdf2_sha256$120000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, rounds_text, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds_text)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def parse_amount(value: str | float | int) -> int:
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if amount <= 0:
        raise ValueError("Enter an amount greater than zero.")
    return int(amount * 100)


def format_money(cents: int, currency: str = "USD") -> str:
    currency_info = SUPPORTED_CURRENCIES.get(currency, SUPPORTED_CURRENCIES["USD"])
    return f"{currency_info['symbol']}{cents / 100:,.2f}"


def currency_label(currency: str) -> str:
    info = SUPPORTED_CURRENCIES[currency]
    return f"{currency} — {info['name']}"


def currency_codes() -> list[str]:
    return list(SUPPORTED_CURRENCIES)


def get_exchange_rate(from_currency: str, to_currency: str) -> Decimal:
    if from_currency not in SUPPORTED_CURRENCIES or to_currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Choose supported currencies.")
    if from_currency == to_currency:
        raise ValueError("Choose two different currencies.")
    source_usd = Decimal(SUPPORTED_CURRENCIES[from_currency]["usd_per_unit"])
    target_usd = Decimal(SUPPORTED_CURRENCIES[to_currency]["usd_per_unit"])
    return (source_usd / target_usd).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


def convert_amount(amount_cents: int, from_currency: str, to_currency: str) -> tuple[int, Decimal]:
    rate = get_exchange_rate(from_currency, to_currency)
    converted = ((Decimal(amount_cents) / Decimal(100)) * rate).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return int(converted * 100), rate


def generate_account_number(connection: sqlite3.Connection) -> str:
    while True:
        candidate = f"HB-{secrets.randbelow(900000) + 100000}"
        exists = connection.execute(
            "SELECT 1 FROM users WHERE account_number = ?", (candidate,)
        ).fetchone()
        if exists is None:
            return candidate


def ensure_user_wallets(
    connection: sqlite3.Connection, user_id: int, usd_balance_cents: int = 0
) -> None:
    for currency in SUPPORTED_CURRENCIES:
        starting_balance = usd_balance_cents if currency == "USD" else 0
        connection.execute(
            """
            INSERT OR IGNORE INTO wallets (user_id, currency, balance_cents)
            VALUES (?, ?, ?)
            """,
            (user_id, currency, starting_balance),
        )


def get_wallets(user_id: int) -> list[sqlite3.Row]:
    with get_db() as connection:
        return connection.execute(
            """
            SELECT currency, balance_cents
            FROM wallets
            WHERE user_id = ?
            ORDER BY CASE currency
                WHEN 'USD' THEN 0 WHEN 'EUR' THEN 1 WHEN 'GBP' THEN 2
                WHEN 'CAD' THEN 3 WHEN 'AUD' THEN 4 WHEN 'CHF' THEN 5
                WHEN 'JPY' THEN 6 WHEN 'NGN' THEN 7 ELSE 8 END
            """,
            (user_id,),
        ).fetchall()


def get_wallet_balance(user_id: int, currency: str) -> int:
    with get_db() as connection:
        wallet = connection.execute(
            "SELECT balance_cents FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        ).fetchone()
    return wallet["balance_cents"] if wallet else 0


def authenticate(username: str, password: str) -> sqlite3.Row | None:
    with get_db() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)
        ).fetchone()
    if user and verify_password(password, user["password_hash"]):
        return user
    return None


def create_admin(username: str, full_name: str, password: str) -> None:
    if len(username.strip()) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Username may contain letters, numbers, underscores, and hyphens.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(full_name.strip()) < 2:
        raise ValueError("Enter the administrator's full name.")

    with get_db() as connection:
        try:
            connection.execute(
                """
                INSERT INTO users (
                    username, full_name, password_hash, role, account_number,
                    balance_cents, created_at
                ) VALUES (?, ?, ?, 'admin', ?, 0, ?)
                """,
                (
                    username.strip(), full_name.strip(), hash_password(password),
                    "ADMIN-000001", now_iso(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("That username is already taken.") from error


def create_customer(
    username: str, full_name: str, password: str,
    initial_deposit: str | float | int, initial_currency: str = "USD"
) -> tuple[str, int]:
    if len(username.strip()) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Username may contain letters, numbers, underscores, and hyphens.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(full_name.strip()) < 2:
        raise ValueError("Enter the account holder's full name.")
    if initial_currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Choose a supported opening currency.")

    deposit_cents = 0
    if str(initial_deposit).strip():
        deposit_cents = parse_amount(initial_deposit)

    with get_db() as connection:
        account_number = generate_account_number(connection)
        try:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    username, full_name, password_hash, role, account_number,
                    balance_cents, created_at
                ) VALUES (?, ?, ?, 'customer', ?, ?, ?)
                """,
                (
                    username.strip(), full_name.strip(), hash_password(password),
                    account_number,
                    deposit_cents if initial_currency == "USD" else 0,
                    now_iso(),
                ),
            )
        except sqlite3.IntegrityError as error:
            if "username" in str(error).lower():
                raise ValueError("That username is already taken.") from error
            raise ValueError("Could not create the account. Please try again.") from error

        ensure_user_wallets(connection, cursor.lastrowid)
        if deposit_cents:
            connection.execute(
                """
                INSERT INTO transactions (
                    user_id, transaction_type, currency, amount_cents,
                    balance_after_cents, note, created_at
                ) VALUES (?, 'deposit', ?, ?, ?, ?, ?)
                """,
                (
                    cursor.lastrowid, initial_currency, deposit_cents,
                    deposit_cents, "Opening deposit", now_iso(),
                ),
            )
            connection.execute(
                """
                UPDATE wallets
                SET balance_cents = balance_cents + ?
                WHERE user_id = ? AND currency = ?
                """,
                (deposit_cents, cursor.lastrowid, initial_currency),
            )
    return account_number, deposit_cents


def update_balance(
    user_id: int, transaction_type: str, amount: str | float | int,
    note: str, currency: str = "USD"
) -> int:
    amount_cents = parse_amount(amount)
    if transaction_type not in {"deposit", "withdrawal"}:
        raise ValueError("Unsupported transaction.")
    if currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Choose a supported currency.")

    with get_db() as connection:
        user = connection.execute(
            "SELECT id, balance_cents FROM users WHERE id = ? AND role = 'customer'",
            (user_id,),
        ).fetchone()
        if user is None:
            raise ValueError("Customer account not found.")

        ensure_user_wallets(connection, user_id, user["balance_cents"])
        wallet = connection.execute(
            "SELECT balance_cents FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        ).fetchone()
        current_balance = wallet["balance_cents"]
        new_balance = (
            current_balance + amount_cents
            if transaction_type == "deposit"
            else current_balance - amount_cents
        )
        if new_balance < 0:
            raise ValueError(f"This withdrawal is greater than the available {currency} balance.")

        connection.execute(
            "UPDATE wallets SET balance_cents = ? WHERE user_id = ? AND currency = ?",
            (new_balance, user_id, currency),
        )
        if currency == "USD":
            connection.execute(
                "UPDATE users SET balance_cents = ? WHERE id = ?",
                (new_balance, user_id),
            )
        connection.execute(
            """
            INSERT INTO transactions (
                user_id, transaction_type, currency, amount_cents,
                balance_after_cents, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id, transaction_type, currency, amount_cents,
                new_balance, note.strip() or None, now_iso(),
            ),
        )
    return new_balance


def exchange_currency(
    user_id: int, from_currency: str, to_currency: str,
    amount: str | float | int, note: str
) -> tuple[int, Decimal]:
    amount_cents = parse_amount(amount)
    converted_cents, rate = convert_amount(amount_cents, from_currency, to_currency)

    with get_db() as connection:
        user = connection.execute(
            "SELECT id, balance_cents FROM users WHERE id = ? AND role = 'customer'",
            (user_id,),
        ).fetchone()
        if user is None:
            raise ValueError("Customer account not found.")

        ensure_user_wallets(connection, user_id, user["balance_cents"])
        source = connection.execute(
            "SELECT balance_cents FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, from_currency),
        ).fetchone()
        target = connection.execute(
            "SELECT balance_cents FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, to_currency),
        ).fetchone()
        if source is None or target is None:
            raise ValueError("Currency wallet not found.")
        if source["balance_cents"] < amount_cents:
            raise ValueError(f"Not enough {from_currency} to complete this exchange.")

        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents - ? WHERE user_id = ? AND currency = ?",
            (amount_cents, user_id, from_currency),
        )
        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents + ? WHERE user_id = ? AND currency = ?",
            (converted_cents, user_id, to_currency),
        )
        if from_currency == "USD":
            connection.execute(
                "UPDATE users SET balance_cents = balance_cents - ? WHERE id = ?",
                (amount_cents, user_id),
            )
        if to_currency == "USD":
            connection.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                (converted_cents, user_id),
            )
        connection.execute(
            """
            INSERT INTO exchange_transactions (
                user_id, from_currency, from_amount_cents, to_currency,
                to_amount_cents, exchange_rate, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id, from_currency, amount_cents, to_currency,
                converted_cents, str(rate), note.strip() or None, now_iso(),
            ),
        )
    return converted_cents, rate


def get_user(user_id: int) -> sqlite3.Row | None:
    with get_db() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_transactions(user_id: int, limit: int = 10) -> list[sqlite3.Row]:
    with get_db() as connection:
        return connection.execute(
            """
            SELECT transaction_type, currency, amount_cents, balance_after_cents, note, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def get_exchange_transactions(user_id: int, limit: int = 10) -> list[sqlite3.Row]:
    with get_db() as connection:
        return connection.execute(
            """
            SELECT from_currency, from_amount_cents, to_currency,
                   to_amount_cents, exchange_rate, note, created_at
            FROM exchange_transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def get_customers() -> list[sqlite3.Row]:
    with get_db() as connection:
        return connection.execute(
            """
            SELECT id, username, full_name, account_number, balance_cents, created_at
            FROM users
            WHERE role = 'customer'
            ORDER BY created_at DESC
            """
        ).fetchall()


def get_customer_by_account(account_number: str) -> sqlite3.Row | None:
    with get_db() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE account_number = ? AND role = 'customer'",
            (account_number.strip().upper(),),
        ).fetchone()


def get_total_deposits() -> int:
    with get_db() as connection:
        row = connection.execute(
            "SELECT COALESCE(SUM(balance_cents), 0) AS total FROM users WHERE role = 'customer'"
        ).fetchone()
        return row["total"]


def get_transaction_count() -> int:
    with get_db() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM transactions").fetchone()
        return row["total"]


def get_exchange_count() -> int:
    with get_db() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM exchange_transactions"
        ).fetchone()
        return row["total"]


# ═══════════════════════════════════════════════════════════════
#  STREAMLIT UI
# ═══════════════════════════════════════════════════════════════

def inject_background():
    """Inject animated mesh gradient + floating particles background."""
    st_html("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    html, body, .stApp {
        font-family: 'Inter', sans-serif !important;
    }
    
    .stApp {
        background: 
            radial-gradient(ellipse at 20% 20%, rgba(201, 162, 39, 0.08) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 80%, rgba(74, 144, 217, 0.06) 0%, transparent 50%),
            radial-gradient(ellipse at 50% 50%, rgba(201, 162, 39, 0.03) 0%, transparent 70%),
            linear-gradient(135deg, #0a0e1a 0%, #0d1321 25%, #0a0e1a 50%, #0c1220 75%, #0a0e1a 100%) !important;
        background-attachment: fixed !important;
        animation: bgShift 20s ease-in-out infinite alternate;
    }
    
    @keyframes bgShift {
        0% { background-position: 0% 0%, 100% 100%, 50% 50%, 0% 0%; }
        100% { background-position: 100% 100%, 0% 0%, 50% 50%, 0% 0%; }
    }
    
    #particles-canvas {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        pointer-events: none;
        z-index: 0;
    }
    
    .glass-card {
        background: rgba(12, 18, 35, 0.55) !important;
        backdrop-filter: blur(20px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
        border: 1px solid rgba(201, 162, 39, 0.12) !important;
        border-radius: 16px !important;
        box-shadow: 
            0 8px 32px rgba(0, 0, 0, 0.3),
            inset 0 1px 0 rgba(255, 255, 255, 0.05) !important;
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    
    .glass-card:hover {
        border-color: rgba(201, 162, 39, 0.25) !important;
        box-shadow: 
            0 12px 48px rgba(0, 0, 0, 0.4),
            0 0 20px rgba(201, 162, 39, 0.08),
            inset 0 1px 0 rgba(255, 255, 255, 0.08) !important;
        transform: translateY(-2px);
    }
    
    .shimmer-border {
        position: relative;
        overflow: hidden;
    }
    .shimmer-border::before {
        content: '';
        position: absolute;
        top: -2px; left: -2px; right: -2px; bottom: -2px;
        background: linear-gradient(45deg, transparent, rgba(201, 162, 39, 0.3), transparent, rgba(74, 144, 217, 0.2), transparent);
        background-size: 400% 400%;
        animation: shimmerRotate 4s linear infinite;
        border-radius: 18px;
        z-index: -1;
    }
    @keyframes shimmerRotate {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .gold-text { color: #c9a227 !important; }
    .muted-text { color: #8b9bb4 !important; }
    .white-text { color: #e8ecf1 !important; }
    
    .stButton > button {
        background: linear-gradient(135deg, #c9a227 0%, #e8d5a3 100%) !important;
        color: #0a0e1a !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        padding: 10px 24px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(201, 162, 39, 0.25) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(201, 162, 39, 0.4) !important;
    }
    .stButton > button:active {
        transform: translateY(0) !important;
    }
    
    .stButton > button[kind="secondary"] {
        background: rgba(255, 255, 255, 0.05) !important;
        color: #e8ecf1 !important;
        border: 1px solid rgba(201, 162, 39, 0.2) !important;
        box-shadow: none !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background: rgba(201, 162, 39, 0.1) !important;
        border-color: rgba(201, 162, 39, 0.4) !important;
    }
    
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > div {
        background: rgba(12, 18, 35, 0.6) !important;
        border: 1px solid rgba(201, 162, 39, 0.15) !important;
        border-radius: 10px !important;
        color: #e8ecf1 !important;
        font-size: 14px !important;
    }
    .stTextInput > div > div > input:focus,
    .stNumberInput > div > div > input:focus {
        border-color: rgba(201, 162, 39, 0.5) !important;
        box-shadow: 0 0 0 3px rgba(201, 162, 39, 0.1) !important;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        background: rgba(12, 18, 35, 0.4) !important;
        border-radius: 12px !important;
        padding: 4px !important;
        gap: 4px !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b9bb4 !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background: rgba(201, 162, 39, 0.15) !important;
        color: #c9a227 !important;
    }
    
    .css-1d391kg, .css-1lcbmhc, section[data-testid="stSidebar"] {
        background: rgba(8, 12, 24, 0.85) !important;
        backdrop-filter: blur(20px) !important;
        border-right: 1px solid rgba(201, 162, 39, 0.1) !important;
    }
    
    .stDataFrame {
        background: rgba(12, 18, 35, 0.4) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(201, 162, 39, 0.1) !important;
    }
    
    .stAlert {
        background: rgba(12, 18, 35, 0.7) !important;
        backdrop-filter: blur(10px) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(201, 162, 39, 0.15) !important;
    }
    
    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #c9a227;
        text-shadow: 0 0 20px rgba(201, 162, 39, 0.3);
    }
    .metric-label {
        font-size: 12px;
        color: #8b9bb4;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    ::-webkit-scrollbar {
        width: 8px;
    }
    ::-webkit-scrollbar-track {
        background: rgba(12, 18, 35, 0.3);
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(201, 162, 39, 0.3);
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(201, 162, 39, 0.5);
    }
    
    header { visibility: hidden; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    </style>
    
    <canvas id="particles-canvas"></canvas>
    <script>
    (function() {
        const canvas = document.getElementById('particles-canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const particles = [];
        const particleCount = 60;
        const connectionDistance = 120;
        
        class Particle {
            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.vx = (Math.random() - 0.5) * 0.4;
                this.vy = (Math.random() - 0.5) * 0.4;
                this.radius = Math.random() * 2 + 0.5;
                this.opacity = Math.random() * 0.5 + 0.1;
            }
            update() {
                this.x += this.vx;
                this.y += this.vy;
                if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
                if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
            }
            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(201, 162, 39, ${this.opacity})`;
                ctx.fill();
            }
        }
        
        for (let i = 0; i < particleCount; i++) {
            particles.push(new Particle());
        }
        
        function drawConnections() {
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < connectionDistance) {
                        const opacity = (1 - dist / connectionDistance) * 0.15;
                        ctx.beginPath();
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.strokeStyle = `rgba(201, 162, 39, ${opacity})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }
        }
        
        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            particles.forEach(p => { p.update(); p.draw(); });
            drawConnections();
            requestAnimationFrame(animate);
        }
        
        animate();
        
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    })();
    </script>
    """, height=0)


def show_logo_header():
    st_html("""
    <div style="display:flex;align-items:center;gap:14px;padding:16px 0 24px 0;">
        <div style="position:relative;width:48px;height:48px;">
            <svg viewBox="0 0 48 48" width="48" height="48" style="animation: logoSpin 8s linear infinite;">
                <defs>
                    <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#c9a227"/>
                        <stop offset="100%" style="stop-color:#e8d5a3"/>
                    </linearGradient>
                </defs>
                <circle cx="24" cy="24" r="22" fill="none" stroke="url(#goldGrad)" stroke-width="1.5" opacity="0.6"/>
                <circle cx="24" cy="24" r="16" fill="none" stroke="url(#goldGrad)" stroke-width="1" opacity="0.4"/>
                <text x="24" y="29" text-anchor="middle" fill="url(#goldGrad)" font-size="20" font-weight="700" font-family="Inter">S</text>
            </svg>
            <div style="position:absolute;top:0;left:0;width:48px;height:48px;border-radius:50%;box-shadow:0 0 20px rgba(201,162,39,0.3);animation:pulse 3s ease-in-out infinite;"></div>
        </div>
        <div>
            <div style="font-size:22px;font-weight:700;color:#e8ecf1;letter-spacing:-0.5px;">Sixtus Bank</div>
            <div style="font-size:11px;color:#8b9bb4;text-transform:uppercase;letter-spacing:2px;">Premium Banking</div>
        </div>
    </div>
    <style>
    @keyframes logoSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    @keyframes pulse { 0%,100% { opacity: 0.3; transform: scale(1); } 50% { opacity: 0.6; transform: scale(1.05); } }
    </style>
    """, height=90)


def show_first_run_setup():
    """First-run admin setup — no hardcoded credentials."""
    st_html("""
    <div style="max-width:480px;margin:0 auto;padding:30px 0;">
        <div style="text-align:center;margin-bottom:32px;">
            <div style="width:64px;height:64px;background:linear-gradient(135deg,#c9a227,#e8d5a3);border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;font-size:28px;">🔐</div>
            <h2 style="color:#e8ecf1;margin:0 0 8px;font-size:26px;">Initial Setup</h2>
            <p style="color:#8b9bb4;margin:0;font-size:14px;line-height:1.5;">Create the first administrator account to secure your banking platform. This step is required once.</p>
        </div>
    </div>
    """, height=200)
    
    with st.form("setup_form", clear_on_submit=True):
        full_name = st.text_input("Full Name", placeholder="Administrator Name")
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="Minimum 8 characters")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
        submitted = st.form_submit_button("Create Administrator", use_container_width=True)
        if submitted:
            if password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    create_admin(username, full_name, password)
                    st.success("✅ Administrator created successfully. Please sign in.")
                    st.session_state.page = "login"
                    st.rerun()
                except (ValueError, sqlite3.Error) as e:
                    st.error(f"❌ {e}")


def show_landing_page():
    st_html("""
    <div style="text-align:center;padding:40px 20px 30px;position:relative;overflow:hidden;">
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:300px;height:300px;background:radial-gradient(circle, rgba(201,162,39,0.08) 0%, transparent 70%);border-radius:50%;animation:heroGlow 4s ease-in-out infinite;"></div>
        <h1 style="font-size:48px;font-weight:800;color:#e8ecf1;margin-bottom:12px;position:relative;letter-spacing:-1px;">
            Banking that feels <span style="background:linear-gradient(135deg,#c9a227,#e8d5a3);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">priceless</span>
        </h1>
        <p style="font-size:17px;color:#8b9bb4;max-width:500px;margin:0 auto 28px;line-height:1.6;">
            Move money across currencies with confidence — instant exchange, elegant security, and modern UX built for people.
        </p>
        <style>
        @keyframes heroGlow { 0%,100%{transform:translate(-50%,-50%) scale(1);opacity:0.5;} 50%{transform:translate(-50%,-50%) scale(1.2);opacity:0.8;} }
        </style>
    </div>
    """, height=220)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st_html("""
        <div class="glass-card" style="padding:24px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">⚡</div>
            <h4 style="color:#c9a227;margin:0 0 8px;font-size:16px;">Instant Exchange</h4>
            <p style="color:#8b9bb4;font-size:13px;margin:0;line-height:1.5;">Convert between 8 major currencies with transparent, real-time rates.</p>
        </div>
        """, height=140)
    with col2:
        st_html("""
        <div class="glass-card" style="padding:24px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">🔒</div>
            <h4 style="color:#c9a227;margin:0 0 8px;font-size:16px;">Secure Vault</h4>
            <p style="color:#8b9bb4;font-size:13px;margin:0;line-height:1.5;">PBKDF2-SHA256 encryption with 120,000 rounds. Your assets, protected.</p>
        </div>
        """, height=140)
    with col3:
        st_html("""
        <div class="glass-card" style="padding:24px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">✨</div>
            <h4 style="color:#c9a227;margin:0 0 8px;font-size:16px;">Elegant UX</h4>
            <p style="color:#8b9bb4;font-size:13px;margin:0;line-height:1.5;">Designed for visibility and trust across every device you own.</p>
        </div>
        """, height=140)
    
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    
    st_html("""
    <div style="text-align:center;padding:20px 0;">
        <p style="color:#8b9bb4;font-size:12px;text-transform:uppercase;letter-spacing:3px;margin-bottom:16px;">Supported Currencies</p>
        <div style="display:flex;justify-content:center;gap:16px;flex-wrap:wrap;">
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">USD</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">EUR</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">GBP</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">CAD</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">AUD</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">CHF</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">JPY</span>
            <span style="background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.2);border-radius:20px;padding:6px 16px;color:#c9a227;font-size:13px;font-weight:500;">NGN</span>
        </div>
    </div>
    """, height=100)


def show_login_page():
    st_html("""
    <div style="max-width:420px;margin:0 auto;padding:20px 0;">
        <div style="text-align:center;margin-bottom:24px;">
            <h2 style="color:#e8ecf1;margin:0 0 6px;font-size:24px;">Welcome Back</h2>
            <p style="color:#8b9bb4;margin:0;font-size:13px;">Sign in to manage your account or create a new one</p>
        </div>
    </div>
    """, height=90)
    
    login_tab, create_tab = st.tabs(["🔐 Sign In", "📝 Create Account"])
    
    with login_tab:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign In", use_container_width=True)
            if submitted:
                user = authenticate(username, password)
                if user is None:
                    st.error("❌ We couldn't sign you in with those details.")
                else:
                    st.session_state.user_id = user["id"]
                    st.session_state.login_error = None
                    st.rerun()
    
    with create_tab:
        with st.form("customer_registration_form", clear_on_submit=True):
            full_name = st.text_input("Full Name", placeholder="John Doe")
            username = st.text_input("Choose Username", placeholder="johndoe")
            password = st.text_input("Create Password", type="password", placeholder="Minimum 8 characters")
            opening_deposit = st.text_input("Opening Deposit (optional)", value="0.00")
            opening_currency = st.selectbox("Opening Currency", currency_codes(), format_func=currency_label)
            submitted = st.form_submit_button("Create Account", use_container_width=True)
            if submitted:
                try:
                    account_number, deposit_cents = create_customer(
                        username, full_name, password, opening_deposit, opening_currency
                    )
                    st.success(f"✅ Account created! Number: **{account_number}** · Balance: {format_money(deposit_cents, opening_currency)}")
                    st.info("Use your new credentials to sign in above.")
                except (ValueError, InvalidOperation) as e:
                    st.error(f"❌ {e}")


def show_customer_dashboard(user):
    with st.sidebar:
        st_html(f"""
        <div style="text-align:center;padding:10px 0 20px;">
            <div style="width:60px;height:60px;background:linear-gradient(135deg,#c9a227,#e8d5a3);border-radius:50%;margin:0 auto 10px;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#0a0e1a;">
                {user['full_name'][0].upper()}
            </div>
            <div style="color:#e8ecf1;font-weight:600;font-size:15px;">{user['full_name']}</div>
            <div style="color:#8b9bb4;font-size:11px;margin-top:2px;">{user['account_number']}</div>
            <div style="display:inline-block;background:rgba(39,174,96,0.15);color:#27ae60;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:600;margin-top:8px;text-transform:uppercase;letter-spacing:1px;">Customer</div>
        </div>
        """, height=160)
        
        if st.button("🚪 Sign Out", use_container_width=True):
            st.session_state.user_id = None
            st.rerun()
    
    st_html(f"""
    <div style="padding:10px 0 20px;">
        <h2 style="color:#e8ecf1;margin:0;font-size:24px;">Dashboard</h2>
        <p style="color:#8b9bb4;margin:4px 0 0;font-size:13px;">Manage your wallets, transactions, and currency exchanges</p>
    </div>
    """, height=70)
    
    wallets = get_wallets(user["id"])
    cols = st.columns(min(len(wallets), 4))
    for i, wallet in enumerate(wallets[:4]):
        with cols[i % 4]:
            curr = wallet["currency"]
            bal = wallet["balance_cents"]
            info = SUPPORTED_CURRENCIES[curr]
            st_html(f"""
            <div class="glass-card shimmer-border" style="padding:18px;text-align:center;position:relative;">
                <div style="font-size:11px;color:#8b9bb4;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px;">{curr}</div>
                <div style="font-size:22px;font-weight:700;color:#c9a227;text-shadow:0 0 15px rgba(201,162,39,0.2);">{info['symbol']}{bal/100:,.2f}</div>
                <div style="font-size:11px;color:#8b9bb4;margin-top:4px;">{info['name']}</div>
            </div>
            """, height=100)
    
    if len(wallets) > 4:
        cols2 = st.columns(min(len(wallets) - 4, 4))
        for i, wallet in enumerate(wallets[4:]):
            with cols2[i % 4]:
                curr = wallet["currency"]
                bal = wallet["balance_cents"]
                info = SUPPORTED_CURRENCIES[curr]
                st_html(f"""
                <div class="glass-card shimmer-border" style="padding:18px;text-align:center;position:relative;">
                    <div style="font-size:11px;color:#8b9bb4;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px;">{curr}</div>
                    <div style="font-size:22px;font-weight:700;color:#c9a227;text-shadow:0 0 15px rgba(201,162,39,0.2);">{info['symbol']}{bal/100:,.2f}</div>
                    <div style="font-size:11px;color:#8b9bb4;margin-top:4px;">{info['name']}</div>
                </div>
                """, height=100)
    
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    
    trans_tab, exchange_tab, history_tab = st.tabs(["💰 Deposit / Withdraw", "🔄 Exchange", "📜 History"])
    
    with trans_tab:
        c1, c2 = st.columns(2)
        with c1:
            st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:8px;font-size:14px;">Deposit Funds</div>""", height=30)
            with st.form("deposit_form"):
                dep_currency = st.selectbox("Currency", currency_codes(), format_func=currency_label, key="dep_curr")
                dep_amount = st.text_input("Amount", placeholder="100.00", key="dep_amt")
                dep_note = st.text_input("Note (optional)", placeholder="Salary deposit", key="dep_note")
                if st.form_submit_button("Deposit", use_container_width=True):
                    try:
                        new_bal = update_balance(user["id"], "deposit", dep_amount, dep_note or "Deposit", dep_currency)
                        st.success(f"✅ Deposited {format_money(int(float(dep_amount)*100), dep_currency)}. New balance: {format_money(new_bal, dep_currency)}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {e}")
        with c2:
            st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:8px;font-size:14px;">Withdraw Funds</div>""", height=30)
            with st.form("withdraw_form"):
                wd_currency = st.selectbox("Currency", currency_codes(), format_func=currency_label, key="wd_curr")
                wd_amount = st.text_input("Amount", placeholder="50.00", key="wd_amt")
                wd_note = st.text_input("Note (optional)", placeholder="ATM withdrawal", key="wd_note")
                if st.form_submit_button("Withdraw", use_container_width=True):
                    try:
                        new_bal = update_balance(user["id"], "withdrawal", wd_amount, wd_note or "Withdrawal", wd_currency)
                        st.success(f"✅ Withdrew {format_money(int(float(wd_amount)*100), wd_currency)}. New balance: {format_money(new_bal, wd_currency)}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {e}")
    
    with exchange_tab:
        st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:8px;font-size:14px;">Currency Exchange</div>""", height=30)
        with st.form("exchange_form"):
            ex_from = st.selectbox("From", currency_codes(), format_func=currency_label, key="ex_from")
            ex_to = st.selectbox("To", currency_codes(), format_func=currency_label, key="ex_to")
            ex_amount = st.text_input("Amount to exchange", placeholder="100.00", key="ex_amt")
            ex_note = st.text_input("Note (optional)", placeholder="Travel funds", key="ex_note")
            if st.form_submit_button("Exchange Now", use_container_width=True):
                try:
                    converted, rate = exchange_currency(user["id"], ex_from, ex_to, ex_amount, ex_note or "Exchange")
                    st.success(f"✅ Exchanged {format_money(int(float(ex_amount)*100), ex_from)} → {format_money(converted, ex_to)} at rate {rate}")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {e}")
    
    with history_tab:
        trans = get_transactions(user["id"], 20)
        if trans:
            data = []
            for t in trans:
                icon = "🟢" if t["transaction_type"] == "deposit" else "🔴"
                data.append({
                    "Type": f"{icon} {t['transaction_type'].title()}",
                    "Currency": t["currency"],
                    "Amount": format_money(t["amount_cents"], t["currency"]),
                    "Balance After": format_money(t["balance_after_cents"], t["currency"]),
                    "Note": t["note"] or "—",
                    "Date": t["created_at"][:19].replace("T", " ")
                })
            st.dataframe(data, use_container_width=True, hide_index=True)
        else:
            st.info("No transactions yet.")
        
        ex_trans = get_exchange_transactions(user["id"], 20)
        if ex_trans:
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:8px;font-size:14px;">Exchange History</div>""", height=30)
            ex_data = []
            for t in ex_trans:
                ex_data.append({
                    "From": f"{t['from_currency']} {format_money(t['from_amount_cents'], t['from_currency'])}",
                    "To": f"{t['to_currency']} {format_money(t['to_amount_cents'], t['to_currency'])}",
                    "Rate": t["exchange_rate"],
                    "Note": t["note"] or "—",
                    "Date": t["created_at"][:19].replace("T", " ")
                })
            st.dataframe(ex_data, use_container_width=True, hide_index=True)


def show_admin_dashboard(user):
    with st.sidebar:
        st_html(f"""
        <div style="text-align:center;padding:10px 0 20px;">
            <div style="width:60px;height:60px;background:linear-gradient(135deg,#e74c3c,#c0392b);border-radius:50%;margin:0 auto 10px;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#fff;">
                {user['full_name'][0].upper()}
            </div>
            <div style="color:#e8ecf1;font-weight:600;font-size:15px;">{user['full_name']}</div>
            <div style="color:#8b9bb4;font-size:11px;margin-top:2px;">{user['account_number']}</div>
            <div style="display:inline-block;background:rgba(231,76,60,0.15);color:#e74c3c;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:600;margin-top:8px;text-transform:uppercase;letter-spacing:1px;">Administrator</div>
        </div>
        """, height=160)
        
        if st.button("🚪 Sign Out", use_container_width=True):
            st.session_state.user_id = None
            st.rerun()
    
    st_html("""
    <div style="padding:10px 0 20px;">
        <h2 style="color:#e8ecf1;margin:0;font-size:24px;">Admin Console</h2>
        <p style="color:#8b9bb4;margin:4px 0 0;font-size:13px;">System overview, customer management, and analytics</p>
    </div>
    """, height=70)
    
    total_deposits = get_total_deposits()
    trans_count = get_transaction_count()
    ex_count = get_exchange_count()
    customers = get_customers()
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st_html(f"""
        <div class="glass-card" style="padding:20px;text-align:center;">
            <div class="metric-label">Total Deposits</div>
            <div class="metric-value">{format_money(total_deposits)}</div>
        </div>
        """, height=90)
    with m2:
        st_html(f"""
        <div class="glass-card" style="padding:20px;text-align:center;">
            <div class="metric-label">Customers</div>
            <div class="metric-value">{len(customers)}</div>
        </div>
        """, height=90)
    with m3:
        st_html(f"""
        <div class="glass-card" style="padding:20px;text-align:center;">
            <div class="metric-label">Transactions</div>
            <div class="metric-value">{trans_count}</div>
        </div>
        """, height=90)
    with m4:
        st_html(f"""
        <div class="glass-card" style="padding:20px;text-align:center;">
            <div class="metric-label">Exchanges</div>
            <div class="metric-value">{ex_count}</div>
        </div>
        """, height=90)
    
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    
    st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:12px;font-size:16px;">👥 Customer Directory</div>""", height=30)
    
    if customers:
        cust_data = []
        for c in customers:
            cust_data.append({
                "ID": c["id"],
                "Name": c["full_name"],
                "Username": c["username"],
                "Account": c["account_number"],
                "Balance": format_money(c["balance_cents"]),
                "Created": c["created_at"][:19].replace("T", " ")
            })
        st.dataframe(cust_data, use_container_width=True, hide_index=True)
    else:
        st.info("No customers registered yet.")
    
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st_html("""<div style="color:#c9a227;font-weight:600;margin-bottom:8px;font-size:14px;">🔍 Account Lookup</div>""", height=30)
    lookup = st.text_input("Enter account number", placeholder="HB-123456")
    if lookup:
        customer = get_customer_by_account(lookup)
        if customer:
            wallets = get_wallets(customer["id"])
            wallet_str = " · ".join([f"{w['currency']}: {format_money(w['balance_cents'], w['currency'])}" for w in wallets if w["balance_cents"] > 0]) or "No balance"
            st_html(f"""
            <div class="glass-card" style="padding:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <div style="color:#e8ecf1;font-weight:600;font-size:15px;">{customer['full_name']}</div>
                        <div style="color:#8b9bb4;font-size:12px;">{customer['account_number']} · {customer['username']}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="color:#c9a227;font-weight:700;font-size:18px;">{format_money(customer['balance_cents'])}</div>
                        <div style="color:#8b9bb4;font-size:11px;">USD Equivalent</div>
                    </div>
                </div>
                <div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(201,162,39,0.1);">
                    <div style="color:#8b9bb4;font-size:12px;">Wallets: {wallet_str}</div>
                </div>
            </div>
            """, height=120)
        else:
            st.error("Account not found.")


def main() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="💎",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    initialize_database()
    
    # Session state
    st.session_state.setdefault("user_id", None)
    st.session_state.setdefault("page", "landing")
    
    # Inject background + styles
    inject_background()
    
    # Logo header
    show_logo_header()
    
    # Check if first-run setup is needed
    admin_exists = has_admin()
    
    if not admin_exists:
        show_first_run_setup()
        return
    
    # Navigation
    if st.session_state.user_id is None:
        col1, col2, col3, col4 = st.columns([1,1,1,4])
        with col1:
            if st.button("🏠 Home", use_container_width=True):
                st.session_state.page = "landing"
        with col2:
            if st.button("🔐 Sign In", use_container_width=True):
                st.session_state.page = "login"
        with col3:
            if st.button("👤 Admin", use_container_width=True):
                st.session_state.page = "login"
    
    st.markdown("<hr style='border:none;height:1px;background:linear-gradient(90deg,transparent,rgba(201,162,39,0.3),transparent);margin:0 0 20px 0;'>", unsafe_allow_html=True)
    
    # Route
    if st.session_state.user_id is not None:
        user = get_user(st.session_state.user_id)
        if user is None:
            st.session_state.user_id = None
            st.rerun()
        if user["role"] == "admin":
            show_admin_dashboard(user)
        else:
            show_customer_dashboard(user)
    else:
        if st.session_state.get("page") == "login":
            show_login_page()
        else:
            show_landing_page()


if __name__ == "__main__":
    main()
