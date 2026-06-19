"""Console entrypoint for GhostMirror.

Exposes the Typer ``app`` and a ``main`` callable used by the ``ghostmirror``
console script (see ``pyproject.toml``) and ``python -m ghostmirror.app.main``.
"""

from __future__ import annotations

import sys

from ghostmirror.app.cli import app
from ghostmirror.app.error_handler import present_error
from ghostmirror.core.exceptions import (
    ExitCode,
    InvalidConfigurationError,
    ProjectError,
    ToolNotFoundError,
)


def main() -> None:
    """Run the GhostMirror CLI with global error handling.

    NUNCA exibe traceback para o usuario.
    Sempre converte excecoes em paineis Rich amigaveis.
    """
    try:
        app()
    except SystemExit as e:
        sys.exit(e.code)
    except KeyboardInterrupt:
        present_error(KeyboardInterrupt("Operacao cancelada pelo usuario."))
        sys.exit(ExitCode.USER_ERROR.value)
    except InvalidConfigurationError as exc:
        present_error(exc)
        sys.exit(ExitCode.CONFIG_ERROR.value)
    except ToolNotFoundError as exc:
        present_error(exc)
        sys.exit(ExitCode.DEPENDENCY_MISSING.value)
    except ProjectError as exc:
        present_error(exc)
        sys.exit(ExitCode.USER_ERROR.value)
    except Exception as exc:
        present_error(exc)
        sys.exit(ExitCode.INTERNAL_ERROR.value)


if __name__ == "__main__":
    main()
