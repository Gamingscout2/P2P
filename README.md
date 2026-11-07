# P2PFS

P2PFS is a desktop file-sharing tool with direct peer connections and a relay
server fallback. Both peers must use the current client version; older clients
and relay servers are not compatible with this version.

## Run from source

Install Python 3.10 or newer (including `venv` and `pip` support), then run the
setup script from the project directory. The script creates or reuses `.venv`
and installs the dependencies for both the client and the relay server.

On Windows, in PowerShell:

```powershell
.\depends.bat
.\.venv\Scripts\python p2pfs_client.py
```

On Linux or macOS:

```sh
bash depends.sh
.venv/bin/python p2pfs_client.py
```

Internet access is needed to download packages. On some Linux distributions,
Python's `venv` support, C build tools and Python development headers may need
to be installed separately, as may Qt's platform libraries for the desktop
environment. Use a graphical session for the client. If setup fails, resolve
the reported error and run the script again. Virtual environments are
platform-specific; move or remove `.venv` before switching operating systems
or Python installations. To use a particular Python version, create `.venv`
with that interpreter before running the setup script.

Choose a username on first launch. To send a file:

1. Connect both clients to the same relay server using its `host:port` address,
   or enter the other peer's ID directly.
2. Select a peer from the online list or paste their ID into the Peer field.
3. Choose a file to send. The recipient must accept the offer and choose where
   to save it.
4. On first contact, verify each peer's fingerprint through a separate trusted
   channel before accepting the trust prompt. Treat a changed-key warning with
   care and verify the new fingerprint before replacing a pinned key.

The client stores its identity, trusted peers, configuration and log in
`%USERPROFILE%\.p2pfs`. Keep the identity file private.

## Run a relay server

After running the setup script, start the relay server from the project directory:

```powershell
.\.venv\Scripts\python p2pfs_server.py
```

On Linux or macOS, use `.venv/bin/python p2pfs_server.py` instead.

By default, the server listens on all interfaces on TCP port `47777`. Clients
need a reachable server address; for remote peers, configure your firewall and
port forwarding or use a TCP tunnel. To change the bind address or port:

```powershell
$env:P2PFS_SERVER_HOST = "127.0.0.1"
$env:P2PFS_SERVER_PORT = "47777"
.\.venv\Scripts\python p2pfs_server.py
```

The loopback address above only accepts connections from the same machine.

## Build the Windows application

With the source dependencies installed in the virtual environment:

```powershell
.\.venv\Scripts\python -m pip install pyinstaller
.\.venv\Scripts\python -m PyInstaller p2pfs_client.spec --noconfirm
```

Launch `dist\P2PFS\P2PFS.exe`. This is a folder-based build: keep the entire
`dist\P2PFS` folder together when moving or sharing the application. The relay
server is run separately from source.
