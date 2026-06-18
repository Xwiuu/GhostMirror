"""Console entrypoint for GhostMirror.

Exposes the Typer ``app`` and a ``main`` callable used by the ``ghostmirror``
console script (see ``pyproject.toml``) and ``python -m ghostmirror.app.main``.
"""

from __future__ import annotations

from ghostmirror.app.cli import app


def main() -> None:
    """Run the GhostMirror CLI."""

    app()


if __name__ == "__main__":
    main()
