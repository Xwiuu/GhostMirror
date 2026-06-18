from __future__ import annotations

from ghostmirror.core.exceptions import (
    GhostMirrorError,
    InvalidConfigurationError,
    OutOfScopeError,
    ProjectAlreadyExistsError,
    ProjectError,
    ProjectNotFoundError,
    ReportGenerationError,
    ScannerError,
    ScopeError,
    ScopeViolationError,
    TemplateNotFoundError,
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)


class TestExceptionHierarchy:
    def test_ghostmirror_error_base(self):
        assert issubclass(GhostMirrorError, Exception)
        err = GhostMirrorError("base error")
        assert str(err) == "base error"

    def test_tool_error_hierarchy(self):
        assert issubclass(ToolError, GhostMirrorError)
        assert issubclass(ToolNotFoundError, ToolError)
        assert issubclass(ToolTimeoutError, ToolError)
        assert issubclass(ToolExecutionError, ToolError)

    def test_scope_error_hierarchy(self):
        assert issubclass(ScopeError, GhostMirrorError)
        assert issubclass(ScopeViolationError, ScopeError)
        assert issubclass(OutOfScopeError, ScopeViolationError)

    def test_project_error_hierarchy(self):
        assert issubclass(ProjectError, GhostMirrorError)
        assert issubclass(ProjectAlreadyExistsError, ProjectError)
        assert issubclass(ProjectNotFoundError, ProjectError)

    def test_other_exceptions(self):
        assert issubclass(ScannerError, GhostMirrorError)
        assert issubclass(InvalidConfigurationError, GhostMirrorError)
        assert issubclass(TemplateNotFoundError, GhostMirrorError)
        assert issubclass(ReportGenerationError, GhostMirrorError)

    def test_exception_messages(self):
        errors = {
            ToolNotFoundError: "nmap not found",
            ToolTimeoutError: "nmap timed out",
            ToolExecutionError: "nmap failed",
            ScopeViolationError: "out of scope",
            OutOfScopeError: "target not authorized",
            ProjectAlreadyExistsError: "project exists",
            ProjectNotFoundError: "project not found",
            InvalidConfigurationError: "invalid config",
            TemplateNotFoundError: "template missing",
            ReportGenerationError: "report failed",
            ScannerError: "scan error",
        }
        for exc_cls, msg in errors.items():
            exc = exc_cls(msg)
            assert str(exc) == msg
