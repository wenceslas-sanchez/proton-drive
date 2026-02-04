"""
Proton Drive client configuration.
"""

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ProtonDriveConfig:
    """
    Attributes:
        api_url: Base URL for Proton API.
        redirect_uri: Redirect URI for OAuth token refresh.
        timeout: Request timeout in seconds.
        app_version: Application version string sent to API.
        user_agent: User-Agent header value.
        max_retries: Maximum number of retries for failed requests.
        retry_delay: Base delay between retries in seconds.
        block_download_timeout: Timeout for downloading a single block in seconds.
        max_concurrent_blocks: Maximum number of blocks to download concurrently.
        key_cache_max_size: Maximum number of keys to cache.
        metadata_cache_ttl: Time-to-live for cached metadata in seconds.
    """

    api_url: str = "https://mail-api.proton.me"
    redirect_uri: str = "https://protonmail.ch"
    timeout: float = 30.0
    app_version: str = "macos-drive@1.0.0-alpha.1+rclone"
    user_agent: str = "ProtonDrive-Python/1.0"
    max_retries: int = 3
    retry_delay: float = 1.0
    block_download_timeout: float = 120.0
    max_concurrent_blocks: int = 4
    key_cache_max_size: int = 1000
    metadata_cache_ttl: float = 300.0

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            msg = "timeout must be positive"
            raise ValueError(msg)
        if self.block_download_timeout <= 0:
            msg = "block_download_timeout must be positive"
            raise ValueError(msg)
        if self.max_retries < 0:
            msg = "max_retries must be non-negative"
            raise ValueError(msg)
        if self.retry_delay < 0:
            msg = "retry_delay must be non-negative"
            raise ValueError(msg)
        if self.max_concurrent_blocks <= 0:
            msg = "max_concurrent_blocks must be positive"
            raise ValueError(msg)
        if self.key_cache_max_size <= 0:
            msg = "key_cache_max_size must be positive"
            raise ValueError(msg)
        if self.metadata_cache_ttl <= 0:
            msg = "metadata_cache_ttl must be positive"
            raise ValueError(msg)
