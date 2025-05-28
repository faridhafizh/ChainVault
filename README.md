# ChainVault
🔑 A secure, local CLI password manager that uses a blockchain-inspired ledger for tamper-evident credential storage.

## ✨ About The Project

**ChainVault** is a command-line password manager designed for developers and power users who prefer the terminal. It secures your passwords locally in an encrypted SQLite database.

What makes it unique is its **blockchain-inspired architecture**. Every password addition or modification is logged as a "block" in a cryptographic chain. This creates an immutable, verifiable history, making it easy to detect any unauthorized tampering with the password database.

### Key Features

* 🔐 **Strong Encryption:** Uses **AES-256-GCM** to encrypt all sensitive data, with a key derived from your master password using **PBKDF2-HMAC-SHA256**.
* ⛓️ **Blockchain Ledger:** Passwords are not just stored; they are added to a verifiable chain. The integrity of the entire chain can be checked at any time.
* 💻 **Modern CLI Interface:** A clean, colorful, and user-friendly command-line interface built with `colorama`.
* ❤️ **Password Health Check:** Automatically assesses the strength and age of your passwords ("Strong", "Fair", "Weak").
* 📦 **Local First:** All data is stored locally in an encrypted `secure_passwords.db` file. No cloud, no external servers.
* 🔁 **Import/Export:** Securely export individual password entries to a JSON file or import them back in.
* 🌐 **Cross-Platform:** Runs on both Windows and Linux.
* 🔍 **Wi-Fi Password Collector:** Includes a utility to find and export saved Wi-Fi passwords from your system.

---

## 🚀 Getting Started

Follow these steps to get a local copy up and running.

### Prerequisites

* Python 3.8+
* `pip` (Python package installer)

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/faridhafizh/ChainVault.git
    ```
2.  **Navigate to the project directory:**
    ```sh
    cd ChainVault
    ```
3.  **Create a `requirements.txt` file** with the following content:
    ```txt
    cryptography
    colorama
    ```
4.  **Install the required packages:**
    ```sh
    pip install -r requirements.txt
    ```

---

## USAGE

To run the application, execute the main Python script from your terminal:

```sh
python main.py
```

The first time you run it, you will be prompted to create a strong master password. Do not forget this password! It is the only way to decrypt your vault.

📜 License
This project is distributed under the MIT License. See the LICENSE file for more information.
