"""SIMPATI License Manager Application Package."""

__version__ = "1.1.0"


def __getattr__(name: str):
    if name == "app":
        from .main import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
