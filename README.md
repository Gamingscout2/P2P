# P2PFS

P2PFS is a desktop file-sharing tool with direct peer connections and a relay
server fallback. Both peers must use the current client version; older clients
and relay servers are not compatible with this version.

## Run from source

Install Python and run these commands in PowerShell from the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install PySide6 cryptography warpgate aionetiface pystun3
.\.venv\Scripts\python p2pfs_client.py
```

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

The relay server requires Python and `cryptography`. From the project directory:

```powershell
.\.venv\Scripts\python p2pfs_server.py
```

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
.\.venv\Scripts\python -m PyInstaller p2p5.spec --noconfirm
```

Launch `dist\P2PFS\P2PFS.exe`. This is a folder-based build: keep the entire
`dist\P2PFS` folder together when moving or sharing the application. The relay
server is run separately from source.
