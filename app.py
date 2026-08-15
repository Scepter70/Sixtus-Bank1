
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

# ── Crystalline Obsidian Vault Palette ──
OBSIDIAN = "#030305"
OBSIDIAN_DEEP = "#010102"
GOLD_CRYSTAL = "#d4af37"
GOLD_PALE = "#f0e6c8"
COPPER = "#b87333"
AMBER_GLOW = "#ffbf00"
ICE_BLUE = "#a8d8ea"
TEXT_PRIMARY = "#f0f0f5"
TEXT_SECONDARY = "#7a7a8a"
SUCCESS = "#00d4aa"
DANGER = "#ff4757"
ONYX_GLASS = "rgba(8, 8, 12, 0.72)"


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
        transaction_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(transactions)")
        }
        if "currency" not in transaction_columns:
            connection.execute(
                "ALTER TABLE transactions ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'"
            )

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
#  CRYSTALLINE OBSIDIAN VAULT — UI
# ═══════════════════════════════════════════════════════════════

def inject_vault_background():
    """Inject the Living Obsidian Background with Tumbling Gold Hexagons."""
    st_html("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, .stApp {
        font-family: 'Inter', sans-serif !important;
    }

    .stApp {
        background: #030305 !important;
        background-attachment: fixed !important;
        overflow-x: hidden;
    }

    /* ── Living Obsidian Marble Background ── */
    #obsidian-bg {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0;
        pointer-events: none;
        background: 
            radial-gradient(ellipse at 15% 20%, rgba(212, 175, 55, 0.04) 0%, transparent 50%),
            radial-gradient(ellipse at 85% 75%, rgba(184, 115, 51, 0.03) 0%, transparent 50%),
            radial-gradient(ellipse at 50% 50%, rgba(212, 175, 55, 0.015) 0%, transparent 60%),
            linear-gradient(180deg, #030305 0%, #050508 30%, #030305 60%, #020204 100%);
    }

    /* Gold fault lines */
    .fault-line {
        position: absolute;
        background: linear-gradient(90deg, transparent, rgba(212, 175, 55, 0.15), rgba(255, 191, 0, 0.25), rgba(212, 175, 55, 0.15), transparent);
        height: 1px;
        width: 100%;
        animation: faultPulse 8s ease-in-out infinite;
    }
    .fault-line:nth-child(1) { top: 15%; animation-delay: 0s; }
    .fault-line:nth-child(2) { top: 35%; animation-delay: 2.5s; }
    .fault-line:nth-child(3) { top: 55%; animation-delay: 5s; }
    .fault-line:nth-child(4) { top: 75%; animation-delay: 1.2s; }
    .fault-line:nth-child(5) { top: 90%; animation-delay: 4s; }

    @keyframes faultPulse {
        0%, 100% { opacity: 0.3; transform: scaleX(0.8); }
        50% { opacity: 0.8; transform: scaleX(1); }
    }

    /* ── Onyx Glass Cards ── */
    .onyx-card {
        background: rgba(8, 8, 14, 0.78) !important;
        backdrop-filter: blur(24px) saturate(200%) !important;
        -webkit-backdrop-filter: blur(24px) saturate(200%) !important;
        border: 1px solid rgba(212, 175, 55, 0.08) !important;
        border-radius: 20px !important;
        box-shadow: 
            0 0 0 1px rgba(212, 175, 55, 0.04),
            0 8px 40px rgba(0, 0, 0, 0.5),
            inset 0 1px 0 rgba(255, 255, 255, 0.03),
            inset 0 -1px 0 rgba(0, 0, 0, 0.3) !important;
        transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) !important;
        position: relative;
        overflow: hidden;
    }

    .onyx-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        background: radial-gradient(ellipse at 30% 20%, rgba(212, 175, 55, 0.04) 0%, transparent 50%),
                    radial-gradient(ellipse at 70% 80%, rgba(184, 115, 51, 0.03) 0%, transparent 50%);
        pointer-events: none;
        z-index: 0;
    }

    .onyx-card:hover {
        border-color: rgba(212, 175, 55, 0.2) !important;
        box-shadow: 
            0 0 0 1px rgba(212, 175, 55, 0.08),
            0 16px 60px rgba(0, 0, 0, 0.6),
            0 0 30px rgba(212, 175, 55, 0.06),
            inset 0 1px 0 rgba(255, 255, 255, 0.05),
            inset 0 -1px 0 rgba(0, 0, 0, 0.3) !important;
        transform: translateY(-3px);
    }

    /* ── Gold Leaf Border ── */
    .gold-leaf-border {
        position: relative;
    }
    .gold-leaf-border::after {
        content: '';
        position: absolute;
        top: -1px; left: -1px; right: -1px; bottom: -1px;
        border-radius: 21px;
        background: conic-gradient(from 0deg, transparent, rgba(212, 175, 55, 0.4), rgba(255, 191, 0, 0.6), rgba(212, 175, 55, 0.4), transparent, transparent, rgba(184, 115, 51, 0.3), rgba(212, 175, 55, 0.4), transparent);
        background-size: 200% 200%;
        animation: goldLeafFlow 6s linear infinite;
        z-index: -1;
        opacity: 0;
        transition: opacity 0.5s ease;
    }
    .gold-leaf-border:hover::after {
        opacity: 1;
    }
    @keyframes goldLeafFlow {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* ── Vault Sweep Animation ── */
    .vault-sweep {
        position: relative;
        overflow: hidden;
    }
    .vault-sweep::after {
        content: '';
        position: absolute;
        top: 0; left: -100%;
        width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(212, 175, 55, 0.08), rgba(255, 255, 255, 0.04), rgba(212, 175, 55, 0.08), transparent);
        animation: vaultSweep 5s ease-in-out infinite;
        pointer-events: none;
    }
    @keyframes vaultSweep {
        0% { left: -100%; }
        50% { left: 150%; }
        100% { left: 150%; }
    }

    /* ── Typography ── */
    .cinzel { font-family: 'Cinzel', serif !important; }
    .gold-text { color: #d4af37 !important; }
    .gold-pale { color: #f0e6c8 !important; }
    .copper-text { color: #b87333 !important; }
    .amber-text { color: #ffbf00 !important; }
    .ice-text { color: #a8d8ea !important; }
    .white-text { color: #f0f0f5 !important; }
    .muted-text { color: #7a7a8a !important; }

    /* ── Buttons ── */
    .stButton > button {
        background: linear-gradient(135deg, rgba(212, 175, 55, 0.15) 0%, rgba(184, 115, 51, 0.1) 100%) !important;
        color: #d4af37 !important;
        border: 1px solid rgba(212, 175, 55, 0.25) !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        padding: 10px 28px !important;
        transition: all 0.4s ease !important;
        box-shadow: 0 2px 12px rgba(212, 175, 55, 0.08) !important;
        font-family: 'Cinzel', serif !important;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, rgba(212, 175, 55, 0.25) 0%, rgba(184, 115, 51, 0.15) 100%) !important;
        border-color: rgba(212, 175, 55, 0.5) !important;
        box-shadow: 0 4px 24px rgba(212, 175, 55, 0.15), 0 0 20px rgba(212, 175, 55, 0.05) !important;
        transform: translateY(-1px);
    }
    .stButton > button:active {
        transform: translateY(0);
    }

    .stButton > button[kind="secondary"] {
        background: rgba(255, 255, 255, 0.03) !important;
        color: #7a7a8a !important;
        border: 1px solid rgba(122, 122, 138, 0.15) !important;
        box-shadow: none !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background: rgba(255, 255, 255, 0.06) !important;
        border-color: rgba(212, 175, 55, 0.2) !important;
        color: #d4af37 !important;
    }

    /* ── Inputs ── */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > div {
        background: rgba(8, 8, 14, 0.6) !important;
        border: 1px solid rgba(212, 175, 55, 0.1) !important;
        border-radius: 12px !important;
        color: #f0f0f5 !important;
        font-size: 14px !important;
        font-family: 'Inter', sans-serif !important;
    }
    .stTextInput > div > div > input:focus,
    .stNumberInput > div > div > input:focus {
        border-color: rgba(212, 175, 55, 0.4) !important;
        box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.06) !important;
    }

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab-list"] {
        background: rgba(8, 8, 14, 0.5) !important;
        border-radius: 14px !important;
        padding: 5px !important;
        gap: 4px !important;
        border: 1px solid rgba(212, 175, 55, 0.06) !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #7a7a8a !important;
        border-radius: 10px !important;
        font-weight: 500 !important;
        font-size: 12px !important;
        transition: all 0.4s ease !important;
        font-family: 'Cinzel', serif !important;
        letter-spacing: 0.5px;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background: rgba(212, 175, 55, 0.1) !important;
        color: #d4af37 !important;
        box-shadow: 0 2px 12px rgba(212, 175, 55, 0.08) !important;
    }

    /* ── Sidebar ── */
    .css-1d391kg, .css-1lcbmhc, section[data-testid="stSidebar"] {
        background: rgba(3, 3, 5, 0.92) !important;
        backdrop-filter: blur(30px) !important;
        border-right: 1px solid rgba(212, 175, 55, 0.06) !important;
    }

    /* ── DataFrame ── */
    .stDataFrame {
        background: rgba(8, 8, 14, 0.5) !important;
        border-radius: 14px !important;
        border: 1px solid rgba(212, 175, 55, 0.06) !important;
    }

    /* ── Alert ── */
    .stAlert {
        background: rgba(8, 8, 14, 0.8) !important;
        backdrop-filter: blur(12px) !important;
        border-radius: 14px !important;
        border: 1px solid rgba(212, 175, 55, 0.1) !important;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: rgba(3, 3, 5, 0.5); }
    ::-webkit-scrollbar-thumb { background: rgba(212, 175, 55, 0.2); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(212, 175, 55, 0.35); }

    header { visibility: hidden; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    </style>

    <div id="obsidian-bg">
        <div class="fault-line"></div>
        <div class="fault-line"></div>
        <div class="fault-line"></div>
        <div class="fault-line"></div>
        <div class="fault-line"></div>
    </div>

    <canvas id="hex-canvas" style="position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:1;"></canvas>
    <script>
    (function() {
        const canvas = document.getElementById('hex-canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const hexagons = [];
        const hexCount = 25;

        class Hexagon {
            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.size = Math.random() * 25 + 10;
                this.vx = (Math.random() - 0.5) * 0.3;
                this.vy = (Math.random() - 0.5) * 0.3;
                this.rotation = Math.random() * Math.PI * 2;
                this.rotSpeed = (Math.random() - 0.5) * 0.01;
                this.opacity = Math.random() * 0.15 + 0.03;
                this.goldIntensity = Math.random();
            }
            update() {
                this.x += this.vx;
                this.y += this.vy;
                this.rotation += this.rotSpeed;
                if (this.x < -50) this.x = canvas.width + 50;
                if (this.x > canvas.width + 50) this.x = -50;
                if (this.y < -50) this.y = canvas.height + 50;
                if (this.y > canvas.height + 50) this.y = -50;
            }
            draw() {
                ctx.save();
                ctx.translate(this.x, this.y);
                ctx.rotate(this.rotation);
                ctx.beginPath();
                for (let i = 0; i < 6; i++) {
                    const angle = (Math.PI / 3) * i;
                    const px = this.size * Math.cos(angle);
                    const py = this.size * Math.sin(angle);
                    if (i === 0) ctx.moveTo(px, py);
                    else ctx.lineTo(px, py);
                }
                ctx.closePath();
                ctx.strokeStyle = `rgba(212, 175, 55, ${this.opacity})`;
                ctx.lineWidth = 0.8;
                ctx.stroke();

                // Crystal refraction effect
                ctx.beginPath();
                for (let i = 0; i < 6; i++) {
                    const angle = (Math.PI / 3) * i;
                    const px = this.size * 0.6 * Math.cos(angle);
                    const py = this.size * 0.6 * Math.sin(angle);
                    if (i === 0) ctx.moveTo(px, py);
                    else ctx.lineTo(px, py);
                }
                ctx.closePath();
                ctx.fillStyle = `rgba(212, 175, 55, ${this.opacity * 0.3})`;
                ctx.fill();
                ctx.restore();
            }
        }

        for (let i = 0; i < hexCount; i++) {
            hexagons.push(new Hexagon());
        }

        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            hexagons.forEach(h => { h.update(); h.draw(); });
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


def show_vault_logo():
    st_html("""
    <div style="display:flex;align-items:center;gap:16px;padding:20px 0 28px 0;position:relative;z-index:2;">
        <div style="position:relative;width:52px;height:52px;">
            <svg viewBox="0 0 52 52" width="52" height="52">
                <defs>
                    <linearGradient id="vaultGold" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#d4af37"/>
                        <stop offset="50%" style="stop-color:#ffbf00"/>
                        <stop offset="100%" style="stop-color:#b87333"/>
                    </linearGradient>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                        <feMerge>
                            <feMergeNode in="coloredBlur"/>
                            <feMergeNode in="SourceGraphic"/>
                        </feMerge>
                    </filter>
                </defs>
                <!-- Hexagon frame -->
                <polygon points="26,2 47,14 47,38 26,50 5,38 5,14" fill="none" stroke="url(#vaultGold)" stroke-width="1.2" opacity="0.7"/>
                <polygon points="26,8 41,17 41,35 26,44 11,35 11,17" fill="none" stroke="url(#vaultGold)" stroke-width="0.6" opacity="0.4"/>
                <!-- Center S -->
                <text x="26" y="33" text-anchor="middle" fill="url(#vaultGold)" font-size="22" font-weight="800" font-family="Cinzel, serif" filter="url(#glow)">S</text>
            </svg>
            <div style="position:absolute;top:0;left:0;width:52px;height:52px;border-radius:50%;box-shadow:0 0 25px rgba(212,175,55,0.2);animation:vaultPulse 4s ease-in-out infinite;"></div>
        </div>
        <div>
            <div class="cinzel" style="font-size:24px;font-weight:700;color:#f0f0f5;letter-spacing:2px;">SIXTUS BANK</div>
            <div style="font-size:10px;color:#7a7a8a;text-transform:uppercase;letter-spacing:4px;font-family:'Cinzel',serif;">The Art of Wealth</div>
        </div>
    </div>
    <style>
    @keyframes vaultPulse { 0%,100%{opacity:0.2;transform:scale(1);} 50%{opacity:0.5;transform:scale(1.08);} }
    </style>
    """, height=90)


def show_first_run_setup():
    st_html("""
    <div style="max-width:460px;margin:0 auto;padding:40px 0;position:relative;z-index:2;">
        <div style="text-align:center;margin-bottom:40px;">
            <div style="width:72px;height:72px;background:linear-gradient(135deg,rgba(212,175,55,0.2),rgba(184,115,51,0.1));border:1px solid rgba(212,175,55,0.2);border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:28px;box-shadow:0 0 30px rgba(212,175,55,0.1);">
                ⚜️
            </div>
            <h2 class="cinzel" style="color:#f0f0f5;margin:0 0 10px;font-size:26px;letter-spacing:1px;">Vault Initialization</h2>
            <p style="color:#7a7a8a;margin:0;font-size:13px;line-height:1.6;">Create the first vault keeper to secure the treasury. This sacred step is required once.</p>
        </div>
    </div>
    """, height=220)

    with st.form("setup_form", clear_on_submit=True):
        full_name = st.text_input("Full Name", placeholder="Vault Keeper Name")
        username = st.text_input("Username", placeholder="keeper")
        password = st.text_input("Password", type="password", placeholder="Minimum 8 characters")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
        submitted = st.form_submit_button("Initialize Vault", use_container_width=True)
        if submitted:
            if password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    create_admin(username, full_name, password)
                    st.success("✅ Vault initialized. Please authenticate.")
                    st.session_state.page = "login"
                    st.rerun()
                except (ValueError, sqlite3.Error) as e:
                    st.error(f"❌ {e}")


def show_landing_page():
    st_html("""
    <div style="text-align:center;padding:50px 20px 40px;position:relative;z-index:2;">
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:350px;height:350px;background:radial-gradient(circle, rgba(212,175,55,0.06) 0%, transparent 70%);border-radius:50%;animation:heroGlowVault 5s ease-in-out infinite;"></div>
        <h1 class="cinzel" style="font-size:42px;font-weight:800;color:#f0f0f5;margin-bottom:16px;position:relative;letter-spacing:2px;line-height:1.2;">
            Where Wealth<br><span style="background:linear-gradient(135deg,#d4af37,#ffbf00,#b87333);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">Becomes Art</span>
        </h1>
        <p style="font-size:15px;color:#7a7a8a;max-width:480px;margin:0 auto 32px;line-height:1.7;font-family:'Inter',sans-serif;">
            Move capital across currencies with sovereign confidence — crystalline exchange, vault-grade security, and an interface forged for the discerning few.
        </p>
        <div style="display:flex;justify-content:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
            <span style="font-size:11px;color:#b87333;font-family:'Cinzel',serif;letter-spacing:3px;">EST. MMXXVI</span>
            <span style="font-size:11px;color:#3a3a4a;">|</span>
            <span style="font-size:11px;color:#7a7a8a;font-family:'Cinzel',serif;letter-spacing:2px;">PRIVATE BANKING</span>
        </div>
        <style>
        @keyframes heroGlowVault { 0%,100%{transform:translate(-50%,-50%) scale(1);opacity:0.4;} 50%{transform:translate(-50%,-50%) scale(1.15);opacity:0.7;} }
        </style>
    </div>
    """, height=260)

    col1, col2, col3 = st.columns(3)
    with col1:
        st_html("""
        <div class="onyx-card gold-leaf-border vault-sweep" style="padding:28px;text-align:center;">
            <div style="font-size:28px;margin-bottom:10px;">💎</div>
            <h4 class="cinzel" style="color:#d4af37;margin:0 0 10px;font-size:14px;letter-spacing:1px;">Crystalline Exchange</h4>
            <p style="color:#7a7a8a;font-size:12px;margin:0;line-height:1.6;">Convert between 8 sovereign currencies with transparent, real-time vault rates.</p>
        </div>
        """, height=160)
    with col2:
        st_html("""
        <div class="onyx-card gold-leaf-border vault-sweep" style="padding:28px;text-align:center;">
            <div style="font-size:28px;margin-bottom:10px;">🔐</div>
            <h4 class="cinzel" style="color:#d4af37;margin:0 0 10px;font-size:14px;letter-spacing:1px;">Obsidian Vault</h4>
            <p style="color:#7a7a8a;font-size:12px;margin:0;line-height:1.6;">PBKDF2-SHA256 encryption with 120,000 rounds. Your treasury, impregnable.</p>
        </div>
        """, height=160)
    with col3:
        st_html("""
        <div class="onyx-card gold-leaf-border vault-sweep" style="padding:28px;text-align:center;">
            <div style="font-size:28px;margin-bottom:10px;">✨</div>
            <h4 class="cinzel" style="color:#d4af37;margin:0 0 10px;font-size:14px;letter-spacing:1px;">Mastercrafted UX</h4>
            <p style="color:#7a7a8a;font-size:12px;margin:0;line-height:1.6;">Designed for visibility and trust across every device in your collection.</p>
        </div>
        """, height=160)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    st_html("""
    <div style="text-align:center;padding:20px 0;position:relative;z-index:2;">
        <p class="cinzel" style="color:#7a7a8a;font-size:10px;text-transform:uppercase;letter-spacing:4px;margin-bottom:20px;">Sovereign Currencies</p>
        <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;">
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">USD</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">EUR</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">GBP</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">CAD</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">AUD</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">CHF</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">JPY</span>
            <span style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.1);border-radius:20px;padding:5px 14px;color:#d4af37;font-size:11px;font-weight:500;font-family:'Cinzel',serif;">NGN</span>
        </div>
    </div>
    """, height=100)


def show_login_page():
    st_html("""
    <div style="max-width:420px;margin:0 auto;padding:20px 0;position:relative;z-index:2;">
        <div style="text-align:center;margin-bottom:28px;">
            <h2 class="cinzel" style="color:#f0f0f5;margin:0 0 8px;font-size:24px;letter-spacing:1px;">Vault Access</h2>
            <p style="color:#7a7a8a;margin:0;font-size:12px;font-family:'Inter',sans-serif;">Authenticate to enter the treasury</p>
        </div>
    </div>
    """, height=90)

    login_tab, create_tab = st.tabs(["🔐 Sign In", "📝 Open Account"])

    with login_tab:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your credentials")
            password = st.text_input("Password", type="password", placeholder="Enter your passphrase")
            submitted = st.form_submit_button("Enter Vault", use_container_width=True)
            if submitted:
                user = authenticate(username, password)
                if user is None:
                    st.error("❌ Authentication failed. Invalid credentials.")
                else:
                    st.session_state.user_id = user["id"]
                    st.session_state.login_error = None
                    st.rerun()

    with create_tab:
        with st.form("customer_registration_form", clear_on_submit=True):
            full_name = st.text_input("Full Name", placeholder="Full Legal Name")
            username = st.text_input("Choose Username", placeholder="vaultmember")
            password = st.text_input("Create Password", type="password", placeholder="Minimum 8 characters")
            opening_deposit = st.text_input("Opening Deposit (optional)", value="0.00")
            opening_currency = st.selectbox("Opening Currency", currency_codes(), format_func=currency_label)
            submitted = st.form_submit_button("Create Vault Account", use_container_width=True)
            if submitted:
                try:
                    account_number, deposit_cents = create_customer(
                        username, full_name, password, opening_deposit, opening_currency
                    )
                    st.success(f"✅ Vault opened! Account: **{account_number}** · Balance: {format_money(deposit_cents, opening_currency)}")
                    st.info("Use your credentials to access the vault above.")
                except (ValueError, InvalidOperation) as e:
                    st.error(f"❌ {e}")


def show_customer_dashboard(user):
    with st.sidebar:
        st_html(f"""
        <div style="text-align:center;padding:10px 0 24px;position:relative;z-index:2;">
            <div style="width:64px;height:64px;background:linear-gradient(135deg,rgba(212,175,55,0.2),rgba(184,115,51,0.1));border:1px solid rgba(212,175,55,0.2);border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#d4af37;font-family:'Cinzel',serif;box-shadow:0 0 20px rgba(212,175,55,0.1);">
                {user['full_name'][0].upper()}
            </div>
            <div style="color:#f0f0f5;font-weight:600;font-size:14px;font-family:'Inter',sans-serif;">{user['full_name']}</div>
            <div style="color:#7a7a8a;font-size:10px;margin-top:3px;font-family:'Inter',sans-serif;letter-spacing:1px;">{user['account_number']}</div>
            <div style="display:inline-block;background:rgba(0,212,170,0.08);color:#00d4aa;padding:3px 12px;border-radius:10px;font-size:9px;font-weight:600;margin-top:10px;text-transform:uppercase;letter-spacing:2px;font-family:'Cinzel',serif;border:1px solid rgba(0,212,170,0.15);">Member</div>
        </div>
        """, height=170)

        if st.button("🚪 Seal Vault", use_container_width=True):
            st.session_state.user_id = None
            st.rerun()

    st_html(f"""
    <div style="padding:10px 0 20px;position:relative;z-index:2;">
        <h2 class="cinzel" style="color:#f0f0f5;margin:0;font-size:22px;letter-spacing:1px;">Treasury</h2>
        <p style="color:#7a7a8a;margin:4px 0 0;font-size:12px;font-family:'Inter',sans-serif;">Manage your vaults, transactions, and currency exchanges</p>
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
            <div class="onyx-card gold-leaf-border vault-sweep" style="padding:20px;text-align:center;position:relative;">
                <div style="font-size:10px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;font-family:'Cinzel',serif;">{curr}</div>
                <div style="font-size:20px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.15);font-family:'Inter',sans-serif;">{info['symbol']}{bal/100:,.2f}</div>
                <div style="font-size:10px;color:#7a7a8a;margin-top:5px;font-family:'Inter',sans-serif;">{info['name']}</div>
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
                <div class="onyx-card gold-leaf-border vault-sweep" style="padding:20px;text-align:center;position:relative;">
                    <div style="font-size:10px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;font-family:'Cinzel',serif;">{curr}</div>
                    <div style="font-size:20px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.15);font-family:'Inter',sans-serif;">{info['symbol']}{bal/100:,.2f}</div>
                    <div style="font-size:10px;color:#7a7a8a;margin-top:5px;font-family:'Inter',sans-serif;">{info['name']}</div>
                </div>
                """, height=100)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    trans_tab, exchange_tab, history_tab = st.tabs(["💰 Deposit / Withdraw", "🔄 Exchange", "📜 Ledger"])

    with trans_tab:
        c1, c2 = st.columns(2)
        with c1:
            st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:10px;font-size:13px;letter-spacing:1px;">Deposit to Vault</div>""", height=30)
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
            st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:10px;font-size:13px;letter-spacing:1px;">Withdraw from Vault</div>""", height=30)
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
        st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:10px;font-size:13px;letter-spacing:1px;">Crystalline Exchange</div>""", height=30)
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
            st.info("No transactions recorded yet.")

        ex_trans = get_exchange_transactions(user["id"], 20)
        if ex_trans:
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:10px;font-size:13px;letter-spacing:1px;">Exchange Ledger</div>""", height=30)
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


def admin_add_money_to_customer(account_number: str, amount: str | float | int, currency: str, note: str) -> None:
    """Admin-only: Add money directly to a customer's wallet."""
    amount_cents = parse_amount(amount)
    if currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Choose a supported currency.")

    with get_db() as connection:
        customer = connection.execute(
            "SELECT * FROM users WHERE account_number = ? AND role = 'customer'",
            (account_number.strip().upper(),),
        ).fetchone()
        if customer is None:
            raise ValueError("Customer account not found.")

        ensure_user_wallets(connection, customer["id"], customer["balance_cents"])

        # Update wallet
        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents + ? WHERE user_id = ? AND currency = ?",
            (amount_cents, customer["id"], currency),
        )
        # Update USD balance if applicable
        if currency == "USD":
            connection.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                (amount_cents, customer["id"]),
            )
        # Record transaction
        new_balance = get_wallet_balance(customer["id"], currency) + amount_cents
        connection.execute(
            """
            INSERT INTO transactions (
                user_id, transaction_type, currency, amount_cents,
                balance_after_cents, note, created_at
            ) VALUES (?, 'deposit', ?, ?, ?, ?, ?)
            """,
            (
                customer["id"], currency, amount_cents,
                new_balance, note.strip() or "Admin deposit", now_iso(),
            ),
        )


def admin_edit_customer(account_number: str, new_full_name: str = None, new_username: str = None) -> None:
    """Admin-only: Edit customer details."""
    with get_db() as connection:
        customer = connection.execute(
            "SELECT * FROM users WHERE account_number = ? AND role = 'customer'",
            (account_number.strip().upper(),),
        ).fetchone()
        if customer is None:
            raise ValueError("Customer account not found.")

        updates = []
        params = []
        if new_full_name and len(new_full_name.strip()) >= 2:
            updates.append("full_name = ?")
            params.append(new_full_name.strip())
        if new_username and len(new_username.strip()) >= 3:
            if not new_username.replace("_", "").replace("-", "").isalnum():
                raise ValueError("Username may contain letters, numbers, underscores, and hyphens.")
            updates.append("username = ?")
            params.append(new_username.strip())

        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            params.append(customer["id"])
            try:
                connection.execute(query, tuple(params))
            except sqlite3.IntegrityError as e:
                raise ValueError("That username is already taken.") from e


def show_admin_dashboard(user):
    with st.sidebar:
        st_html(f"""
        <div style="text-align:center;padding:10px 0 24px;position:relative;z-index:2;">
            <div style="width:64px;height:64px;background:linear-gradient(135deg,rgba(255,71,87,0.15),rgba(231,76,60,0.08));border:1px solid rgba(255,71,87,0.2);border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#ff4757;font-family:'Cinzel',serif;box-shadow:0 0 20px rgba(255,71,87,0.1);">
                {user['full_name'][0].upper()}
            </div>
            <div style="color:#f0f0f5;font-weight:600;font-size:14px;font-family:'Inter',sans-serif;">{user['full_name']}</div>
            <div style="color:#7a7a8a;font-size:10px;margin-top:3px;font-family:'Inter',sans-serif;letter-spacing:1px;">{user['account_number']}</div>
            <div style="display:inline-block;background:rgba(255,71,87,0.08);color:#ff4757;padding:3px 12px;border-radius:10px;font-size:9px;font-weight:600;margin-top:10px;text-transform:uppercase;letter-spacing:2px;font-family:'Cinzel',serif;border:1px solid rgba(255,71,87,0.15);">Vault Keeper</div>
        </div>
        """, height=170)

        if st.button("🚪 Seal Vault", use_container_width=True):
            st.session_state.user_id = None
            st.rerun()

    st_html("""
    <div style="padding:10px 0 20px;position:relative;z-index:2;">
        <h2 class="cinzel" style="color:#f0f0f5;margin:0;font-size:22px;letter-spacing:1px;">Keeper's Console</h2>
        <p style="color:#7a7a8a;margin:4px 0 0;font-size:12px;font-family:'Inter',sans-serif;">System overview, treasury management, and vault controls</p>
    </div>
    """, height=70)

    total_deposits = get_total_deposits()
    trans_count = get_transaction_count()
    ex_count = get_exchange_count()
    customers = get_customers()

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st_html(f"""
        <div class="onyx-card vault-sweep" style="padding:22px;text-align:center;">
            <div class="cinzel" style="font-size:9px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;">Total Treasury</div>
            <div style="font-size:26px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.2);font-family:'Inter',sans-serif;">{format_money(total_deposits)}</div>
        </div>
        """, height=90)
    with m2:
        st_html(f"""
        <div class="onyx-card vault-sweep" style="padding:22px;text-align:center;">
            <div class="cinzel" style="font-size:9px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;">Members</div>
            <div style="font-size:26px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.2);font-family:'Inter',sans-serif;">{len(customers)}</div>
        </div>
        """, height=90)
    with m3:
        st_html(f"""
        <div class="onyx-card vault-sweep" style="padding:22px;text-align:center;">
            <div class="cinzel" style="font-size:9px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;">Transactions</div>
            <div style="font-size:26px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.2);font-family:'Inter',sans-serif;">{trans_count}</div>
        </div>
        """, height=90)
    with m4:
        st_html(f"""
        <div class="onyx-card vault-sweep" style="padding:22px;text-align:center;">
            <div class="cinzel" style="font-size:9px;color:#7a7a8a;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;">Exchanges</div>
            <div style="font-size:26px;font-weight:700;color:#d4af37;text-shadow:0 0 20px rgba(212,175,55,0.2);font-family:'Inter',sans-serif;">{ex_count}</div>
        </div>
        """, height=90)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Admin Control Panel ──
    st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:14px;font-size:15px;letter-spacing:1px;">⚜️ Treasury Controls</div>""", height=30)

    ctrl_tab1, ctrl_tab2 = st.tabs(["💰 Add Funds", "✏️ Edit Member"])

    with ctrl_tab1:
        with st.form("admin_add_funds_form"):
            add_acc = st.text_input("Member Account Number", placeholder="HB-123456")
            add_currency = st.selectbox("Currency", currency_codes(), format_func=currency_label, key="add_curr")
            add_amount = st.text_input("Amount to Add", placeholder="500.00")
            add_note = st.text_input("Note", placeholder="Bonus deposit")
            if st.form_submit_button("Add to Vault", use_container_width=True):
                try:
                    admin_add_money_to_customer(add_acc, add_amount, add_currency, add_note or "Admin deposit")
                    st.success(f"✅ Added {format_money(int(float(add_amount)*100), add_currency)} to account {add_acc}")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {e}")

    with ctrl_tab2:
        with st.form("admin_edit_form"):
            edit_acc = st.text_input("Member Account Number", placeholder="HB-123456", key="edit_acc")
            edit_name = st.text_input("New Full Name (leave blank to keep)", placeholder="New legal name")
            edit_user = st.text_input("New Username (leave blank to keep)", placeholder="newusername")
            if st.form_submit_button("Update Member", use_container_width=True):
                try:
                    admin_edit_customer(edit_acc, edit_name or None, edit_user or None)
                    st.success(f"✅ Member {edit_acc} updated successfully.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {e}")

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Customer Directory ──
    st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:14px;font-size:15px;letter-spacing:1px;">👥 Member Registry</div>""", height=30)

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
        st.info("No members registered yet.")

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    st_html("""<div class="cinzel" style="color:#d4af37;font-weight:600;margin-bottom:10px;font-size:13px;letter-spacing:1px;">🔍 Vault Lookup</div>""", height=30)
    lookup = st.text_input("Enter account number", placeholder="HB-123456")
    if lookup:
        customer = get_customer_by_account(lookup)
        if customer:
            wallets = get_wallets(customer["id"])
            wallet_str = " · ".join([f"{w['currency']}: {format_money(w['balance_cents'], w['currency'])}" for w in wallets if w["balance_cents"] > 0]) or "Empty vault"
            st_html(f"""
            <div class="onyx-card" style="padding:20px;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <div style="color:#f0f0f5;font-weight:600;font-size:15px;font-family:'Inter',sans-serif;">{customer['full_name']}</div>
                        <div style="color:#7a7a8a;font-size:11px;font-family:'Inter',sans-serif;">{customer['account_number']} · {customer['username']}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="color:#d4af37;font-weight:700;font-size:18px;font-family:'Inter',sans-serif;">{format_money(customer['balance_cents'])}</div>
                        <div style="color:#7a7a8a;font-size:10px;font-family:'Inter',sans-serif;">USD Equivalent</div>
                    </div>
                </div>
                <div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(212,175,55,0.08);">
                    <div style="color:#7a7a8a;font-size:11px;font-family:'Inter',sans-serif;">Vaults: {wallet_str}</div>
                </div>
            </div>
            """, height=130)
        else:
            st.error("Account not found in the registry.")


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

    # Inject Crystalline Obsidian Vault background
    inject_vault_background()

    # Vault logo header
    show_vault_logo()

    # Check if first-run setup is needed
    admin_exists = has_admin()

    if not admin_exists:
        show_first_run_setup()
        return

    # Navigation (only when not logged in)
    if st.session_state.user_id is None:
        col1, col2, col3, col4 = st.columns([1,1,1,4])
        with col1:
            if st.button("🏠 Treasury", use_container_width=True):
                st.session_state.page = "landing"
        with col2:
            if st.button("🔐 Access", use_container_width=True):
                st.session_state.page = "login"
        with col3:
            if st.button("⚜️ Keeper", use_container_width=True):
                st.session_state.page = "login"

    st.markdown("<hr style='border:none;height:1px;background:linear-gradient(90deg,transparent,rgba(212,175,55,0.2),transparent);margin:0 0 20px 0;'>", unsafe_allow_html=True)

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
