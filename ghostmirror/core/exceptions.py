"""Centralized exception definitions for GhostMirror."""

from __future__ import annotations


class GhostMirrorError(Exception):
    """Base exception for all GhostMirror errors."""

    pass


# Tool execution errors
class ToolError(GhostMirrorError):
    """Base exception for all external tool errors."""

    pass


class ScannerError(GhostMirrorError):
    """Base exception for all scanner-related errors."""

    pass


class ToolNotFoundError(ToolError):
    """Raised when the target tool binary is not installed or available in PATH."""

    pass


class ToolTimeoutError(ToolError):
    """Raised when the tool execution exceeds the configured timeout."""

    pass


class ToolExecutionError(ToolError):
    """Raised when the process fails and exit code validation is enforced."""

    pass


# Scope validation errors
class ScopeError(GhostMirrorError):
    """Base class for scope validation errors."""

    pass


class ScopeViolationError(ScopeError):
    """Raised when an operation violates target or scope rules."""

    pass


class OutOfScopeError(ScopeViolationError):
    """Raised when a target is not authorized in the project scope."""

    pass


# Project errors
class ProjectError(GhostMirrorError):
    """Base class for project-related failures."""

    pass


class ProjectAlreadyExistsError(ProjectError):
    """Raised when creating a project whose directory already exists."""

    pass


class ProjectNotFoundError(ProjectError):
    """Raised when opening a project that does not exist."""

    pass


# Configuration and other platform errors
class InvalidConfigurationError(GhostMirrorError):
    """Raised when a configuration parameter is missing, invalid, or malformed."""

    pass


class TemplateNotFoundError(GhostMirrorError):
    """Raised when a required Nuclei or other configuration template is missing."""

    pass


class ReportGenerationError(GhostMirrorError):
    """Raised when the report generation engine fails."""

    pass
