 # Password-manager-
# Vault

A robust, lightweight, self-hosted password manager web application engineered with Python, Flask, Argon2id, and authenticated AES-256-GCM encryption.

Vault is designed for individuals who want complete ownership of their credential storage without sacrificing modern cryptographic standards. It operates on a **zero-knowledge persistence model** where the host server never stores the master key or plaintexts on persistent media.

---

## 🚀 Quick Start

### 1. System Requirements
* Python 3.10 or higher
* `pip` (Python package manager)

### 2. Installation & Setup

```bash
# Clone the repository and navigate into the workspace
git clone [https://github.com/yourusername/vault.git](https://github.com/yourusername/vault.git)
cd vault

# Initialize and activate an isolated virtual environment
python3 -m venv venv
source venv/bin/activate        # On Windows Git Bash: source venv/Scripts/activate

# Install required production dependencies
pip install -r requirements.txt

# Run the local application server
python app.py
