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

## How encryption works

Proton Drive is end-to-end encrypted. Everything revolves around a **key hierarchy** and **per-file session keys**.

### Key hierarchy

```
User Key                                (unlocked from your password via SRP)
 └── Address Key                        (passphrase encrypted with User Key)
      └── Share Key                     (passphrase encrypted with Address Key)
           └── Node Key per folder/file (passphrase encrypted with parent Node Key)
                └── Session Key         (stored in ContentKeyPacket, encrypted with Node Key)
```

To decrypt any file, the client walks this chain top-down, unlocking each level with the one above.

### File blocks

Each file is split into blocks (≤ 4 MB). Every block is an **OpenPGP SEIPD v1** (tag 18) packet:

```
[ version: 1 byte ]
[ CFB-encrypted payload ]
  ├── prefix: block_size + 2 random bytes  (CFB IV check)
  ├── Literal Data packet (tag 11)         (actual file content)
  └── MDC packet (0xd3 0x14 + SHA-1)       (integrity check)
```

Decryption steps per block:
1. Verify the block SHA-256 hash against the API-provided value
2. Decrypt the full ciphertext with AES-CFB (zero IV, session key)
3. Verify the MDC SHA-1 (covers prefix + literal data + `0xd3 0x14`)
4. Strip the prefix and parse the Literal Data packet to get raw bytes

### Session key extraction

The `ContentKeyPacket` is a **PKESK** (tag 1) packet. The session key is ECDH-encrypted with the file's Node Key:

```
ECDH decrypt(Node Key, PKESK)  →  [ algo (1 byte) | key (16/24/32 bytes) | checksum (2 bytes) ]
```

The checksum is `sum(key_bytes) mod 65536`. Currently handled by `pgpy` + `cryptography` (see TODO).

## TODO

- [ ] Upload / POST files
- [ ] Filter the tree with a regex (hide matching paths)
- [ ] Remove `pgpy` dependency — implement ECDH session key extraction natively with `cryptography`

## License

GPL-3.0
