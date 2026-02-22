# proton-drive-client

A Python async client to access your Proton Drive programmatically, browse the tree, download files, and decrypt them on the fly.

## Install

```bash
git clone https://github.com/wenceslas-sanchez/proton-drive.git
cd proton-drive
uv sync
```

## Quick start

```python
import asyncio
from proton_drive import ProtonDriveClient

async def main():
    async with ProtonDriveClient() as client:
        await client.authenticate("user@proton.me", "password")

        if client.requires_2fa:
            await client.provide_2fa(input("2FA code: "))

        # Browse
        root = await client.build_tree()
        print(root)

        # List a directory
        nodes = await client.list_directory("/Documents")

        # Download a file
        async for chunk in client.download_file("/Documents/report.pdf"):
            ...

        # Download to disk
        await client.download_to_file("/Documents/report.pdf", "./report.pdf")

asyncio.run(main())
```

## API

### `ProtonDriveClient`

| Method | Description |
|---|---|
| `authenticate(username, password)` | Log in |
| `provide_2fa(code)` | Submit TOTP/2FA code |
| `logout()` | Log out |
| `build_tree(max_depth=50)` | Build the full folder tree |
| `list_directory(path="/")` | List direct children of a folder |
| `get_node(path)` | Get a node by path, or `None` |
| `download_file(path)` | Async generator yielding decrypted bytes |
| `download_to_file(path, destination)` | Download and write to disk |

## How it works

All file content is end-to-end encrypted by Proton. This client:
1. Authenticates against the Proton API (SRP + optional 2FA)
2. Fetches and decrypts your private keys
3. Walks the node key chain to recover each file's session key
4. Streams and decrypts each block using AES (OpenPGP SEIPD v1)

Crypto is handled by `pgpy` + `cryptography`.

## TODO

- [ ] Upload / POST files
- [ ] Filter the tree with a regex (hide matching paths)
- [ ] Remove `pgpy` dependency — implement ECDH session key extraction natively with `cryptography`

## License

GPL-3.0
