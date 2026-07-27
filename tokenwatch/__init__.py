from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("tokenwatch")
except PackageNotFoundError:
    __version__ = "unknown"