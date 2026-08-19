from importlib.metadata import version, PackageNotFoundError

try:
    # The distribution is published as tokenwatch-cli (pyproject `name`).
    # Querying "tokenwatch" would never match and __version__ would always
    # fall back to "unknown" for pip installs.
    __version__ = version("tokenwatch-cli")
except PackageNotFoundError:
    __version__ = "unknown"