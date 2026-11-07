#!/usr/bin/env bash
set -eu

cd -- "$(dirname -- "$0")"

if [ -e .venv ]; then
    if [ ! -x .venv/bin/python ]; then
        echo "Error: .venv already exists but is not a usable Unix virtual environment." >&2
        echo "Move or remove it and run this script again; do not share a venv across operating systems." >&2
        exit 1
    fi
else
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: Python 3.10 or newer is required. Install Python and its venv support first." >&2
        exit 1
    fi
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        echo "Error: python3 must be Python 3.10 or newer." >&2
        exit 1
    fi
    if ! python3 -m venv .venv; then
        echo "Error: Could not create .venv. Check that Python's venv/ensurepip support is installed." >&2
        exit 1
    fi
fi

if ! .venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    echo "Error: .venv requires Python 3.10 or newer. Recreate it with a supported Python." >&2
    exit 1
fi

echo "Installing client and server dependencies..."
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -c 'from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal; from PySide6.QtGui import QGuiApplication, QIcon, QKeySequence; from PySide6.QtWidgets import QApplication, QFileDialog, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QStatusBar, QVBoxLayout, QWidget; from cryptography.exceptions import InvalidSignature, InvalidTag; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.hazmat.primitives.asymmetric import ed25519, x25519; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; from cryptography.hazmat.primitives.kdf.hkdf import HKDF; from warpgate import Gate, TCP, peer; from aionetiface import SUB_ALL; import stun'

echo "Setup complete. Run .venv/bin/python p2pfs_client.py or .venv/bin/python p2pfs_server.py"
