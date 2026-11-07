@echo off
setlocal
pushd "%~dp0" || (echo Error: Could not enter the project directory. 1>&2 & exit /b 1)

if exist ".venv" goto check_venv

where py >nul 2>&1
if errorlevel 1 goto try_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 goto try_python
py -3 -m venv ".venv"
if errorlevel 1 goto venv_error
goto check_venv

:try_python
where python >nul 2>&1
if errorlevel 1 goto python_error
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 goto python_error
python -m venv ".venv"
if errorlevel 1 goto venv_error

:check_venv
if not exist ".venv\Scripts\python.exe" goto invalid_venv
".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 10))"
if errorlevel 1 goto invalid_venv

echo Installing client and server dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto install_error
".venv\Scripts\python.exe" -m pip check
if errorlevel 1 goto install_error
".venv\Scripts\python.exe" -c "from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal; from PySide6.QtGui import QGuiApplication, QIcon, QKeySequence; from PySide6.QtWidgets import QApplication, QFileDialog, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QStatusBar, QVBoxLayout, QWidget; from cryptography.exceptions import InvalidSignature, InvalidTag; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.hazmat.primitives.asymmetric import ed25519, x25519; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; from cryptography.hazmat.primitives.kdf.hkdf import HKDF; from warpgate import Gate, TCP, peer; from aionetiface import SUB_ALL; import stun"
if errorlevel 1 goto install_error

echo Setup complete. Run .venv\Scripts\python p2pfs_client.py or .venv\Scripts\python p2pfs_server.py
popd
exit /b 0

:python_error
echo Error: Python 3.10 or newer was not found. Install Python and its venv support first. 1>&2
goto fail
:venv_error
echo Error: Could not create .venv. Check that Python's venv and ensurepip support are installed. 1>&2
goto fail
:invalid_venv
echo Error: .venv is not a usable Windows virtual environment with Python 3.10 or newer. 1>&2
echo Move or remove it and run this script again; do not share a venv across operating systems. 1>&2
goto fail
:install_error
echo Error: Dependency installation or verification failed. See the output above. 1>&2
:fail
popd
exit /b 1
