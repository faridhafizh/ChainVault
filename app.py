#!/usr/bin/env python3
import os
import sys
import json
import hashlib
from getpass import getpass
import time
import base64
import hmac
import subprocess
import sqlite3

# ANSI Colors & Styles
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C = {
        'RESET': Style.RESET_ALL,
        'BLUE': Fore.BLUE + Style.BRIGHT,
        'GREEN': Fore.GREEN + Style.BRIGHT,
        'YELLOW': Fore.YELLOW + Style.BRIGHT,
        'RED': Fore.RED + Style.BRIGHT,
        'CYAN': Fore.CYAN + Style.BRIGHT,
        'MAGENTA': Fore.MAGENTA + Style.BRIGHT,
        'WHITE': Fore.WHITE + Style.BRIGHT,
        'BOLD': Style.BRIGHT,
        'DIM': Style.DIM,
    }
except ImportError:
    C = {key: '' for key in ['RESET', 'BLUE', 'GREEN', 'YELLOW', 'RED', 'CYAN', 'MAGENTA', 'WHITE', 'BOLD', 'DIM']}

# UI Color Aliases (New Design)
COLOR_TITLE = C['CYAN'] + C['BOLD']
COLOR_HEADER_TEXT = C['WHITE'] + C['BOLD']
COLOR_MENU_BORDER = C['BLUE']
COLOR_MENU_TEXT = C['WHITE']
COLOR_MENU_HIGHLIGHT = C['YELLOW'] + C['BOLD']
COLOR_PROMPT = C['YELLOW'] + C['BOLD']
COLOR_INPUT_TEXT = C['WHITE']
COLOR_SUCCESS = C['GREEN']
COLOR_ERROR = C['RED'] + C['BOLD']
COLOR_WARNING = C['YELLOW']
COLOR_INFO = C['BLUE'] + C['BOLD']
COLOR_TABLE_HEADER = C['CYAN'] + C['BOLD']
COLOR_TABLE_BORDER = C['BLUE']
COLOR_TABLE_TEXT = C['WHITE']
COLOR_HEALTH_STRONG = C['GREEN']
COLOR_HEALTH_FAIR = C['YELLOW']
COLOR_HEALTH_WEAK = C['RED']
COLOR_EMPHASIS = C['MAGENTA'] + C['BOLD']


# OS Compatibility
if os.name not in ('posix', 'nt'):
    print(f"{COLOR_ERROR}❌ This script only runs on Windows or Linux.{C['RESET']}")
    sys.exit(1)

# Try to import dependencies
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False

# File Paths
STORAGE_FILE = "secure_passwords.db"
COLLECTED_PASSWORDS_FILE = "collected_passwords.json"
MASTER_PASSWORD_FILE = ".master_hash.json" # Stores master hash and encryption salt

# ──────────────────────────────────────
# 🔐 Security Utilities
# ──────────────────────────────────────
def generate_key_from_password(password: str, salt: bytes) -> (bytes, bytes):
    """Derives a key from a password using PBKDF2HMAC and the provided salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode()), salt

def encrypt_data(key: bytes, data: str) -> str:
    """Encrypts data using AESGCM with the provided key."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # AESGCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_data(key: bytes, encrypted_data: str) -> str:
    """Decrypts data using AESGCM with the provided key."""
    try:
        data_bytes = base64.b64decode(encrypted_data)
        aesgcm = AESGCM(key)
        nonce, ciphertext = data_bytes[:12], data_bytes[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed. Data may be corrupt or key incorrect. Original error: {e}")


def hash_block(data: str, previous_hash: str) -> str:
    """Hashes data for a block in the blockchain."""
    return hashlib.sha256(f"{previous_hash}{data}".encode()).hexdigest()

def calculate_password_health(password: str, timestamp: float) -> str:
    """Calculates the health of a password based on complexity and age."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    age_days = (time.time() - timestamp) / 86400

    strength_score = 0
    if length >= 12: strength_score += 1
    if has_upper and has_lower: strength_score += 1
    if has_digit: strength_score += 1
    if has_special: strength_score += 1

    if strength_score >= 3 and age_days < 90:
        return "Strong"
    elif strength_score >= 2 and age_days < 180:
        return "Fair"
    return "Weak"

# ──────────────────────────────────────
# 🧱 Blockchain Classes
# ──────────────────────────────────────
class Block:
    def __init__(self, index: int, timestamp: float, data: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = hash_block(data, previous_hash)

    def to_dict(self) -> dict:
        return {
            "index": self.index, "timestamp": self.timestamp, "data": self.data,
            "previous_hash": self.previous_hash, "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, data: str):
        last_block = self.chain[-1] if self.chain else None
        index = 0 if not last_block else last_block.index + 1
        prev_hash = "0" if not last_block else last_block.hash
        new_block = Block(index, time.time(), data, prev_hash)
        self.chain.append(new_block)

    def is_valid(self) -> bool:
        for i, block in enumerate(self.chain):
            if i > 0 and block.previous_hash != self.chain[i - 1].hash:
                return False
            if block.hash != hash_block(block.data, block.previous_hash):
                return False
        return True

# ──────────────────────────────────────
# 🛠️ Database Setup
# ──────────────────────────────────────
def setup_database():
    with sqlite3.connect(STORAGE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS blockchain (
                            id INTEGER PRIMARY KEY, encrypted_data TEXT, signature TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT UNIQUE, username TEXT,
                            encrypted_password TEXT, url TEXT, timestamp REAL,
                            hash TEXT, health_status TEXT)''')
        conn.commit()

# ──────────────────────────────────────
# 🧰 File IO & Blockchain Persistence
# ──────────────────────────────────────
def sign_data(key: bytes, data: str) -> str:
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def save_blockchain(encryption_key: bytes, blockchain_to_save: Blockchain):
    try:
        chain_data_json = json.dumps([block.to_dict() for block in blockchain_to_save.chain])
        encrypted_chain_data = encrypt_data(encryption_key, chain_data_json)
        data_signature = sign_data(encryption_key, encrypted_chain_data)
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO blockchain (id, encrypted_data, signature) VALUES (1, ?, ?)",
                           (encrypted_chain_data, data_signature))
            conn.commit()
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Blockchain save failed: {e}{C['RESET']}")

def load_blockchain(decryption_key: bytes) -> Blockchain:
    loaded_chain = Blockchain()
    try:
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_data, signature FROM blockchain WHERE id = 1")
            row = cursor.fetchone()
        if not row: return loaded_chain

        encrypted_chain_data, stored_signature = row
        if not hmac.compare_digest(stored_signature, sign_data(decryption_key, encrypted_chain_data)):
            raise ValueError("Invalid signature. Data may be tampered with.")

        decrypted_chain_json = decrypt_data(decryption_key, encrypted_chain_data)
        chain_data_list = json.loads(decrypted_chain_json)
        for item in chain_data_list:
            block = Block(item["index"], item["timestamp"], item["data"], item["previous_hash"])
            if block.hash != item["hash"]:
                raise ValueError(f"Block hash mismatch for index {block.index}. Chain corrupted.")
            loaded_chain.chain.append(block)
        
        if not loaded_chain.is_valid():
            raise ValueError("Loaded blockchain failed integrity check.")
        return loaded_chain
    except json.JSONDecodeError as e:
        print(f"{COLOR_ERROR}❌ Error decoding blockchain data: {e}. File might be corrupt.{C['RESET']}")
        return Blockchain()
    except ValueError as e:
        print(f"{COLOR_ERROR}❌ Error loading blockchain: {e}{C['RESET']}")
        return Blockchain()
    except Exception as e:
        print(f"{COLOR_ERROR}❌ An unexpected error occurred loading blockchain: {e}{C['RESET']}")
        return Blockchain()

# ──────────────────────────────────────
# 🔐 Master Password Functions
# ──────────────────────────────────────
def hash_master_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_master_info() -> (str | None, bytes | None):
    if not os.path.exists(MASTER_PASSWORD_FILE): return None, None
    try:
        with open(MASTER_PASSWORD_FILE, "r") as f: data = json.load(f)
        stored_hash = data.get("master_hash")
        stored_salt_b64 = data.get("encryption_salt")
        if stored_hash and stored_salt_b64:
            return stored_hash, base64.b64decode(stored_salt_b64.encode())
        return None, None
    except Exception as e:
        print(f"{COLOR_WARNING}⚠️ Could not load master info: {e}. Assuming first setup or corruption.{C['RESET']}")
        return None, None

def save_master_info(master_hash_to_save: str, encryption_salt_to_save: bytes):
    try:
        with open(MASTER_PASSWORD_FILE, "w") as f:
            json.dump({
                "master_hash": master_hash_to_save,
                "encryption_salt": base64.b64encode(encryption_salt_to_save).decode()
            }, f, indent=4)
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Error saving master info: {e}{C['RESET']}")

def authenticate_master_password(stored_master_hash: str) -> str | None:
    """Authenticates the user against the stored master password hash."""
    for attempt in range(3):
        prompt_message = f"{COLOR_PROMPT}🔑 Enter Master Password: {COLOR_INPUT_TEXT}"
        entered_password = getpass(prompt_message)
        print(C['RESET'], end='') # Reset color after getpass
        if hash_master_password(entered_password) == stored_master_hash:
            return entered_password
        print(f"{COLOR_ERROR}❌ Incorrect password. {2 - attempt} attempts left.{C['RESET']}")
    return None

# ──────────────────────────────────────
# 🧱 Export/Import Functions
# ──────────────────────────────────────
def export_collected_passwords(passwords: dict, filename: str = COLLECTED_PASSWORDS_FILE):
    try:
        with open(filename, "w") as f: json.dump(passwords, f, indent=4)
        print(f"{COLOR_SUCCESS}✅ Collected passwords saved to {filename}{C['RESET']}")
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Failed to export collected passwords: {e}{C['RESET']}")

def collect_system_passwords() -> (dict, list[str]):
    """Collects Wi-Fi passwords. Returns collected data and status messages."""
    collected = {}
    status_messages = []
    if os.name == 'nt': # Windows
        status_messages.append(f"{COLOR_INFO}🔍 Collecting Wi-Fi passwords (Windows)...{C['RESET']}")
        try:
            profiles_output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], text=True, stderr=subprocess.DEVNULL)
            profile_names = [line.split(':')[1].strip() for line in profiles_output.split('\n') if "All User Profile" in line or "Profil Tous les utilisateurs" in line]
            collected['wifi'] = []
            for name in profile_names:
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', name, 'key=clear'], text=True, stderr=subprocess.DEVNULL)
                    password_lines = [line.split(':')[1].strip() for line in results.split('\n') if "Key Content" in line or "Contenu de la cl" in line]
                    if password_lines:
                        collected['wifi'].append({'name': name, 'password': password_lines[0]})
                    else:
                        collected['wifi'].append({'name': name, 'password': 'No key found or protected'})
                except subprocess.CalledProcessError:
                    collected['wifi'].append({'name': name, 'password': 'Failed to retrieve (permissions?)'})
                except Exception as e:
                     status_messages.append(f"{COLOR_WARNING}⚠️ Failed to process Wi-Fi profile '{name}': {e}{C['RESET']}")
        except subprocess.CalledProcessError:
            status_messages.append(f"{COLOR_WARNING}⚠️ No Wi-Fi profiles found or 'netsh' command failed (run as admin?).{C['RESET']}")
        except Exception as e:
            status_messages.append(f"{COLOR_ERROR}⚠️ Error collecting Windows Wi-Fi passwords: {e}{C['RESET']}")

    elif os.name == 'posix': # Linux
        status_messages.append(f"{COLOR_INFO}🔍 Collecting Wi-Fi passwords (Linux - NetworkManager)...{C['RESET']}")
        wifi_dir = "/etc/NetworkManager/system-connections/"
        if os.path.exists(wifi_dir) and os.access(wifi_dir, os.R_OK):
            collected['wifi'] = []
            try:
                for filename in os.listdir(wifi_dir):
                    filepath = os.path.join(wifi_dir, filename)
                    if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                        try:
                            with open(filepath, 'r') as f: content = f.read()
                            if "psk=" in content:
                                psk = content.split("psk=")[1].split("\n")[0]
                                ssid_lines = [line for line in content.split("\n") if line.startswith("ssid=")]
                                ssid = ssid_lines[0].split("=")[1] if ssid_lines else filename
                                collected['wifi'].append({'name': ssid, 'password': psk})
                        except Exception as e:
                            status_messages.append(f"{COLOR_WARNING}⚠️ Could not read or parse {filename}: {e}{C['RESET']}")
            except PermissionError:
                 status_messages.append(f"{COLOR_WARNING}⚠️ Permission denied reading {wifi_dir}. Try with sudo.{C['RESET']}")
            except Exception as e:
                 status_messages.append(f"{COLOR_ERROR}⚠️ Failed to collect Linux Wi-Fi passwords: {e}{C['RESET']}")
        else:
            status_messages.append(f"{COLOR_WARNING}⚠️ NetworkManager directory not found or not accessible: {wifi_dir}{C['RESET']}")
    return collected, status_messages

# ──────────────────────────────────────
# 🧑‍💻 UI & Action Functions (Redesigned)
# ──────────────────────────────────────
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def app_header():
    """Prints the application header (New Design)."""
    print(f"{COLOR_MENU_BORDER}┌───────────────────────────────────────────────────┐{C['RESET']}")
    print(f"{COLOR_MENU_BORDER}│ {COLOR_TITLE}{'🔑 SecurePass - Password Manager v1.1':^49}{COLOR_MENU_BORDER} │{C['RESET']}")
    print(f"{COLOR_MENU_BORDER}└───────────────────────────────────────────────────┘{C['RESET']}")
    print() # Extra line for spacing

def display_menu():
    """Displays the main menu options (New Design)."""
    print(f"{COLOR_MENU_BORDER}╭───────────────────────────────────────────────────╮{C['RESET']}")
    print(f"{COLOR_MENU_BORDER}│ {COLOR_HEADER_TEXT}{'Main Menu':^49}{COLOR_MENU_BORDER} │{C['RESET']}")
    print(f"{COLOR_MENU_BORDER}├───────────────────────────────────────────────────┤{C['RESET']}")
    menu_items = [
        "View All Passwords", "Add New Password", "Verify Chain Integrity",
        "Export Password Entry", "Import Password Entry", "Delete Password Entry",
        "Collect & Export System Passwords", "Exit"
    ]
    for i, item in enumerate(menu_items):
        print(f"{COLOR_MENU_BORDER}│ {COLOR_MENU_HIGHLIGHT}[{i+1}]{C['RESET']} {COLOR_MENU_TEXT}{item:<44}{COLOR_MENU_BORDER} │{C['RESET']}")
    print(f"{COLOR_MENU_BORDER}╰───────────────────────────────────────────────────╯{C['RESET']}")

def display_passwords_action(decryption_key: bytes):
    """Displays all stored passwords with their health status (New Table Design)."""
    try:
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT service, username, encrypted_password, url, health_status, hash, timestamp FROM passwords ORDER BY service")
            rows = cursor.fetchall()

        # Define column widths
        col_num = 3
        col_service = 20
        col_username = 20
        col_password = 15 # For masked password
        col_url = 25
        col_health = 8
        total_width = col_num + col_service + col_username + col_password + col_url + col_health + 7 # 7 for separators |

        print(f"{COLOR_TABLE_BORDER}╭─{'─' * (total_width-2)}─╮{C['RESET']}")
        print(f"{COLOR_TABLE_BORDER}│ {COLOR_HEADER_TEXT}{'Stored Passwords':^{total_width-2}} {COLOR_TABLE_BORDER}│{C['RESET']}")
        print(f"{COLOR_TABLE_BORDER}├─{'─'*col_num}─┬─{'─'*col_service}─┬─{'─'*col_username}─┬─{'─'*col_password}─┬─{'─'*col_url}─┬─{'─'*col_health}─┤{C['RESET']}")
        print(f"{COLOR_TABLE_BORDER}│ {COLOR_TABLE_HEADER}{'#':^{col_num}}{COLOR_TABLE_BORDER} │ "
              f"{COLOR_TABLE_HEADER}{'Service':<{col_service}}{COLOR_TABLE_BORDER} │ "
              f"{COLOR_TABLE_HEADER}{'Username':<{col_username}}{COLOR_TABLE_BORDER} │ "
              f"{COLOR_TABLE_HEADER}{'Password':<{col_password}}{COLOR_TABLE_BORDER} │ "
              f"{COLOR_TABLE_HEADER}{'URL':<{col_url}}{COLOR_TABLE_BORDER} │ "
              f"{COLOR_TABLE_HEADER}{'Health':<{col_health}}{COLOR_TABLE_BORDER} │{C['RESET']}")
        print(f"{COLOR_TABLE_BORDER}├─{'─'*col_num}─┼─{'─'*col_service}─┼─{'─'*col_username}─┼─{'─'*col_password}─┼─{'─'*col_url}─┼─{'─'*col_health}─┤{C['RESET']}")

        if not rows:
            print(f"{COLOR_TABLE_BORDER}│ {COLOR_WARNING}{'No passwords found.':^{total_width-2}} {COLOR_TABLE_BORDER}│{C['RESET']}")
        else:
            for i, row_data in enumerate(rows, start=1):
                service, username, encrypted_pass_db, url, health_db, _, timestamp = row_data
                try:
                    decrypted_pass = decrypt_data(decryption_key, encrypted_pass_db)
                    masked_pass = '*' * len(decrypted_pass)
                    current_health = calculate_password_health(decrypted_pass, timestamp)
                    # TODO: Update health in DB if current_health != health_db
                except ValueError:
                    masked_pass = f"{COLOR_ERROR}DECRYPT FAIL{C['RESET']}"
                    current_health = "Unknown"
                except Exception:
                    masked_pass = f"{COLOR_ERROR}ERROR{C['RESET']}"
                    current_health = "Unknown"

                health_color_map = {"Strong": COLOR_HEALTH_STRONG, "Fair": COLOR_HEALTH_FAIR, "Weak": COLOR_HEALTH_WEAK}
                health_display_color = health_color_map.get(current_health, COLOR_TABLE_TEXT)

                # Truncate fields if they exceed column width
                s_service = (service[:col_service-1] + '…') if len(service) > col_service else service
                s_username = (username[:col_username-1] + '…') if len(username) > col_username else username
                s_url = (url[:col_url-1] + '…') if url and len(url) > col_url else (url if url else "N/A")
                s_masked_pass = (masked_pass[:col_password-1] + '…') if len(masked_pass) > col_password else masked_pass


                print(f"{COLOR_TABLE_BORDER}│ {COLOR_TABLE_TEXT}{str(i):>{col_num}}{COLOR_TABLE_BORDER} │ "
                      f"{COLOR_TABLE_TEXT}{s_service:<{col_service}}{COLOR_TABLE_BORDER} │ "
                      f"{COLOR_TABLE_TEXT}{s_username:<{col_username}}{COLOR_TABLE_BORDER} │ "
                      f"{COLOR_TABLE_TEXT}{s_masked_pass:<{col_password}}{COLOR_TABLE_BORDER} │ "
                      f"{COLOR_TABLE_TEXT}{s_url:<{col_url}}{COLOR_TABLE_BORDER} │ "
                      f"{health_display_color}{current_health:<{col_health}}{COLOR_TABLE_BORDER} │{C['RESET']}")
        print(f"{COLOR_TABLE_BORDER}╰─{'─'*col_num}─┴─{'─'*col_service}─┴─{'─'*col_username}─┴─{'─'*col_password}─┴─{'─'*col_url}─┴─{'─'*col_health}─╯{C['RESET']}")

    except sqlite3.Error as e:
        print(f"{COLOR_ERROR}❌ Database error displaying passwords: {e}{C['RESET']}")
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Failed to display passwords: {e}{C['RESET']}")


def add_password_action(encryption_key: bytes, current_blockchain: Blockchain):
    clear_screen(); app_header()
    print(f"{COLOR_INFO}➕ Add New Password Entry{C['RESET']}")
    service = input(f"{COLOR_PROMPT}   Service Name: {COLOR_INPUT_TEXT}").strip()
    username = input(f"{COLOR_PROMPT}   Username:     {COLOR_INPUT_TEXT}").strip()
    password = getpass(f"{COLOR_PROMPT}   Password:     {COLOR_INPUT_TEXT}")
    print(C['RESET'], end='') # Reset after getpass
    password = password.strip()
    url = input(f"{COLOR_PROMPT}   URL (optional): {COLOR_INPUT_TEXT}").strip()

    if not service or not username or not password:
        print(f"{COLOR_ERROR}❌ Service, username, and password cannot be empty.{C['RESET']}")
        return

    entry_data = {"service": service, "username": username, "password": password, "url": url}
    entry_json = json.dumps(entry_data)
    current_blockchain.add_block(entry_json)
    latest_block = current_blockchain.chain[-1]

    try:
        encrypted_pass = encrypt_data(encryption_key, password)
        health_status = calculate_password_health(password, latest_block.timestamp)
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT INTO passwords 
                                  (service, username, encrypted_password, url, timestamp, hash, health_status)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)''',
                               (service, username, encrypted_pass, url,
                                latest_block.timestamp, latest_block.hash, health_status))
                conn.commit()
                save_blockchain(encryption_key, current_blockchain)
                print(f"{COLOR_SUCCESS}✅ Password for '{service}' added securely.{C['RESET']}")
            except sqlite3.IntegrityError:
                print(f"{COLOR_ERROR}❌ Error: A password for service '{service}' already exists.{C['RESET']}")
                current_blockchain.chain.pop()
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Failed to add password: {e}{C['RESET']}")
        if current_blockchain.chain and current_blockchain.chain[-1].data == entry_json:
            current_blockchain.chain.pop()


def delete_password_action(encryption_key: bytes, current_blockchain: Blockchain):
    clear_screen(); app_header()
    print(f"{COLOR_INFO}🗑️ Delete Password Entry{C['RESET']}")
    try:
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, service, username FROM passwords ORDER BY service")
            rows = cursor.fetchall()

        if not rows:
            print(f"{COLOR_WARNING}ℹ️ No passwords to delete.{C['RESET']}")
            return

        print(f"{COLOR_HEADER_TEXT}Select Password to Delete:{C['RESET']}")
        for i, row_data in enumerate(rows):
            db_id, service, username = row_data
            print(f"  {COLOR_MENU_HIGHLIGHT}[{i + 1}]{C['RESET']} {COLOR_MENU_TEXT}{service} - {username} (ID: {db_id}){C['RESET']}")
        
        choice = input(f"{COLOR_PROMPT}🔢 Enter entry number to delete (or 0 to cancel): {COLOR_INPUT_TEXT}").strip()
        if not choice.isdigit() or int(choice) == 0:
            print(f"{COLOR_INFO}ℹ️ Deletion cancelled.{C['RESET']}")
            return
        
        index_to_delete = int(choice) - 1
        if 0 <= index_to_delete < len(rows):
            db_id_to_delete, service_to_delete, _ = rows[index_to_delete]
            confirm = input(f"{COLOR_WARNING}⚠️ Confirm deletion of '{service_to_delete}'? (yes/no): {COLOR_INPUT_TEXT}").lower().strip()
            if confirm == "yes":
                with sqlite3.connect(STORAGE_FILE) as conn_del: # New connection for delete
                    cursor_del = conn_del.cursor()
                    cursor_del.execute("DELETE FROM passwords WHERE id=?", (db_id_to_delete,))
                    conn_del.commit()

                new_blockchain = Blockchain()
                # Re-fetch remaining entries from the DB to rebuild blockchain
                with sqlite3.connect(STORAGE_FILE) as conn_rebuild:
                    cursor_rebuild = conn_rebuild.cursor()
                    cursor_rebuild.execute("SELECT service, username, encrypted_password, url, timestamp FROM passwords") # Removed hash
                    remaining_entries = cursor_rebuild.fetchall()

                for entry_row in remaining_entries:
                    r_service, r_username, r_encrypted_pass, r_url, r_timestamp = entry_row
                    try:
                        r_plain_pass = decrypt_data(encryption_key, r_encrypted_pass)
                        block_data = {"service": r_service, "username": r_username, "password": r_plain_pass, "url": r_url}
                        # Create a new block. Its timestamp will be current time.
                        # If original timestamp is critical, Block class needs adjustment or manual setting here.
                        new_blockchain.add_block(json.dumps(block_data))
                        # To preserve original timestamp (approximate, as hash changes):
                        # new_blockchain.chain[-1].timestamp = r_timestamp 
                        # new_blockchain.chain[-1].hash = hash_block(new_blockchain.chain[-1].data, new_blockchain.chain[-1].previous_hash) # Re-hash if timestamp changed
                    except ValueError:
                        print(f"{COLOR_WARNING}⚠️ Could not decrypt password for '{r_service}' during chain rebuild. Skipping.{C['RESET']}")
                        continue
                
                current_blockchain.chain = new_blockchain.chain
                save_blockchain(encryption_key, current_blockchain)
                print(f"{COLOR_SUCCESS}✅ Password for '{service_to_delete}' deleted and chain rebuilt.{C['RESET']}")
            else:
                print(f"{COLOR_INFO}ℹ️ Deletion cancelled.{C['RESET']}")
        else:
            print(f"{COLOR_ERROR}❌ Invalid selection.{C['RESET']}")
    except sqlite3.Error as e:
        print(f"{COLOR_ERROR}❌ Database error during deletion: {e}{C['RESET']}")
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Deletion failed: {e}{C['RESET']}")


def export_password_file_action(decryption_key: bytes):
    clear_screen(); app_header()
    print(f"{COLOR_INFO}📤 Export Password Entry to File{C['RESET']}")
    try:
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, service, username, encrypted_password, url FROM passwords ORDER BY service")
            rows = cursor.fetchall()

        if not rows:
            print(f"{COLOR_WARNING}ℹ️ No passwords to export.{C['RESET']}")
            return

        print(f"{COLOR_HEADER_TEXT}Select Password to Export:{C['RESET']}")
        for i, row_data in enumerate(rows):
            db_id, service, username, _, _ = row_data
            print(f"  {COLOR_MENU_HIGHLIGHT}[{i + 1}]{C['RESET']} {COLOR_MENU_TEXT}{service} - {username} (ID: {db_id}){C['RESET']}")

        choice = input(f"{COLOR_PROMPT}🔢 Enter entry number to export (or 0 to cancel): {COLOR_INPUT_TEXT}").strip()
        if not choice.isdigit() or int(choice) == 0:
            print(f"{COLOR_INFO}ℹ️ Export cancelled.{C['RESET']}")
            return
        
        index_to_export = int(choice) - 1
        if 0 <= index_to_export < len(rows):
            _, service, username, encrypted_pass, url = rows[index_to_export]
            try:
                decrypted_pass = decrypt_data(decryption_key, encrypted_pass)
                export_data = {"service": service, "username": username, "password": decrypted_pass, "url": url}
                filename = f"exported_{service.replace(' ', '_').lower()}.json"
                with open(filename, "w") as f: json.dump(export_data, f, indent=4)
                print(f"{COLOR_SUCCESS}✅ Password for '{service}' exported to {filename}{C['RESET']}")
            except ValueError:
                print(f"{COLOR_ERROR}❌ Decryption failed for '{service}'. Cannot export.{C['RESET']}")
        else:
            print(f"{COLOR_ERROR}❌ Invalid selection.{C['RESET']}")
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Export failed: {e}{C['RESET']}")


def import_password_file_action(encryption_key: bytes, current_blockchain: Blockchain):
    clear_screen(); app_header()
    print(f"{COLOR_INFO}📥 Import Password Entry from File{C['RESET']}")
    filename = input(f"{COLOR_PROMPT}📄 Enter file name to import (e.g., exported_service.json): {COLOR_INPUT_TEXT}").strip()
    if not os.path.exists(filename):
        print(f"{COLOR_ERROR}❌ File '{filename}' not found.{C['RESET']}")
        return

    try:
        with open(filename, "r") as f: entry_data_import = json.load(f)
        
        required_keys = {"service", "username", "password"}
        if not required_keys.issubset(entry_data_import.keys()):
            print(f"{COLOR_ERROR}❌ Invalid file format. Missing keys: {required_keys - entry_data_import.keys()}{C['RESET']}")
            return

        service = entry_data_import["service"]
        username = entry_data_import["username"]
        password = entry_data_import["password"]
        url = entry_data_import.get("url", "")

        entry_json = json.dumps({"service": service, "username": username, "password": password, "url": url})
        current_blockchain.add_block(entry_json)
        latest_block = current_blockchain.chain[-1]
        encrypted_pass = encrypt_data(encryption_key, password)
        health_status = calculate_password_health(password, latest_block.timestamp)

        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT INTO passwords 
                                  (service, username, encrypted_password, url, timestamp, hash, health_status)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)''',
                               (service, username, encrypted_pass, url,
                                latest_block.timestamp, latest_block.hash, health_status))
                conn.commit()
                save_blockchain(encryption_key, current_blockchain)
                print(f"{COLOR_SUCCESS}✅ Password for '{service}' imported successfully from {filename}.{C['RESET']}")
            except sqlite3.IntegrityError:
                print(f"{COLOR_ERROR}❌ Error: A password for service '{service}' already exists. Import aborted.{C['RESET']}")
                current_blockchain.chain.pop()
    except json.JSONDecodeError:
        print(f"{COLOR_ERROR}❌ Invalid JSON format in '{filename}'.{C['RESET']}")
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Import failed: {e}{C['RESET']}")
        # Basic rollback
        # A more robust check would be to see if the last block's data matches the imported data
        # For simplicity, we assume if an error occurs after add_block, it might be the one to remove.
        if current_blockchain.chain and current_blockchain.chain[-1].data == json.dumps({"service": service, "username": username, "password": password, "url": url}):
             current_blockchain.chain.pop()


# ──────────────────────────────────────
# 🔑 Main Application Logic
# ──────────────────────────────────────
def main():
    if not DEPENDENCIES_AVAILABLE:
        print(f"{COLOR_ERROR}❌ Required cryptographic libraries missing.{C['RESET']}")
        print(f"{COLOR_WARNING}Please install them by running: pip install cryptography colorama{C['RESET']}")
        sys.exit(1)

    setup_database()
    stored_master_hash, stored_encryption_salt = load_master_info()
    session_master_password = None

    if not stored_master_hash or not stored_encryption_salt:
        clear_screen(); app_header()
        print(f"{COLOR_INFO}ℹ️ First time setup or master credentials missing.{C['RESET']}")
        print(f"{COLOR_HEADER_TEXT}Please set up your master password.{C['RESET']}")
        while True:
            new_pass = getpass(f"{COLOR_PROMPT}   Enter new master password (min 8 chars): {COLOR_INPUT_TEXT}")
            print(C['RESET'], end='')
            if len(new_pass) < 8:
                print(f"{COLOR_ERROR}   Password must be at least 8 characters.{C['RESET']}")
                continue
            confirm_pass = getpass(f"{COLOR_PROMPT}   Confirm new master password: {COLOR_INPUT_TEXT}")
            print(C['RESET'], end='')
            if new_pass == confirm_pass:
                session_master_password = new_pass
                stored_master_hash = hash_master_password(session_master_password)
                stored_encryption_salt = os.urandom(16)
                save_master_info(stored_master_hash, stored_encryption_salt)
                print(f"{COLOR_SUCCESS}✅ Master password set up successfully.{C['RESET']}")
                break
            else:
                print(f"{COLOR_ERROR}❌ Passwords do not match. Please try again.{C['RESET']}")
    else:
        clear_screen(); app_header() # Show header before auth prompt
        session_master_password = authenticate_master_password(stored_master_hash)
        if not session_master_password:
            print(f"{COLOR_ERROR}❌ Authentication failed. Too many attempts. Exiting.{C['RESET']}")
            sys.exit(1)
        print(f"{COLOR_SUCCESS}✅ Authentication successful.{C['RESET']}")

    encryption_key, _ = generate_key_from_password(session_master_password, stored_encryption_salt)
    blockchain = load_blockchain(encryption_key)
    if not blockchain.is_valid():
        print(f"{COLOR_ERROR}CRITICAL: Loaded blockchain is invalid. Data might be corrupt. Proceed with caution.{C['RESET']}")

    # Sync passwords table from blockchain
    try:
        with sqlite3.connect(STORAGE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords"); conn.commit() # Clear before sync
            for block in blockchain.chain:
                try:
                    entry = json.loads(block.data)
                    service, username, plain_password = entry.get('service'), entry.get('username'), entry.get('password')
                    url = entry.get('url', '')
                    if not all([service, username, plain_password is not None]):
                        print(f"{COLOR_WARNING}⚠️ Skipping block index {block.index} due to missing essential data.{C['RESET']}")
                        continue
                    encrypted_pass = encrypt_data(encryption_key, plain_password)
                    health_status = calculate_password_health(plain_password, block.timestamp)
                    cursor.execute('''INSERT INTO passwords 
                                      (service, username, encrypted_password, url, timestamp, hash, health_status)
                                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                   (service, username, encrypted_pass, url,
                                    block.timestamp, block.hash, health_status))
                except json.JSONDecodeError:
                    print(f"{COLOR_WARNING}⚠️ Skipping block index {block.index}: Invalid JSON data.{C['RESET']}")
                except Exception as sync_err:
                    print(f"{COLOR_WARNING}⚠️ Error processing block index {block.index} for sync: {sync_err}{C['RESET']}")
            conn.commit()
    except Exception as e:
        print(f"{COLOR_ERROR}❌ Failed to sync passwords table from blockchain: {e}{C['RESET']}")
        # sys.exit(1) # Potentially exit if sync fails critically

    # Main Menu Loop
    while True:
        if not session_master_password: # Should not happen if auth is successful
            print(f"{COLOR_ERROR}Critical error: No session master password. Exiting.{C['RESET']}")
            sys.exit(1)

        app_header()
        display_menu()
        choice = input(f"{COLOR_PROMPT}CHOICE (1-8) ▶ {COLOR_INPUT_TEXT}").strip()
        print(C['RESET'], end='')


        action_taken = True # Flag to control "Press Enter" prompt
        if choice == "1": clear_screen(); app_header(); display_passwords_action(encryption_key)
        elif choice == "2": add_password_action(encryption_key, blockchain) # Clears screen itself
        elif choice == "3":
            clear_screen(); app_header()
            if blockchain.is_valid(): print(f"{COLOR_SUCCESS}✅ Chain integrity verified. No tampering detected.{C['RESET']}")
            else: print(f"{COLOR_ERROR}❌ Chain corruption detected!{C['RESET']}")
        elif choice == "4": export_password_file_action(encryption_key) # Clears screen itself
        elif choice == "5": import_password_file_action(encryption_key, blockchain) # Clears screen itself
        elif choice == "6": delete_password_action(encryption_key, blockchain) # Clears screen itself
        elif choice == "7":
            clear_screen(); app_header()
            print(f"{COLOR_INFO}🧰 Collecting System Passwords...{C['RESET']}")
            collected_sys_passwords, status_msgs = collect_system_passwords()
            for msg in status_msgs: print(msg) # Print status messages from collection
            if collected_sys_passwords.get('wifi'):
                export_collected_passwords(collected_sys_passwords)
            else:
                print(f"{COLOR_WARNING}ℹ️ No system Wi-Fi passwords collected or collection failed.{C['RESET']}")
        elif choice == "8":
            print(f"\n{COLOR_SUCCESS}👋 Exiting SecurePass. Stay secure!{C['RESET']}")
            break
        else:
            action_taken = False # No specific action, just invalid choice
            print(f"{COLOR_WARNING}❌ Invalid choice. Please try again.{C['RESET']}")

        if action_taken or choice not in [str(i) for i in range(1,9)]: # Prompt if action taken or invalid choice that didn't exit
             input(f"\n{COLOR_PROMPT}Press Enter to return to menu... {C['RESET']}")
        clear_screen()

if __name__ == "__main__":
    main()
