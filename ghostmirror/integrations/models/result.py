"""Model for capturing raw command execution results from external tools."""

from pydantic import BaseModel, Field


class ToolExecutionResult(BaseModel):
    """Execution result of an external security tool CLI command."""

    tool_name: str = Field(..., description="Name of the external tool binary executed")
    command: str = Field(..., description="Full command-line string that was run")
    exit_code: int = Field(..., description="Process exit status code")
    stdout: str = Field(..., description="Raw standard output from the process")
    stderr: str = Field(..., description="Raw standard error from the process")
    duration: float = Field(..., description="Time taken to execute the process in seconds")
    success: bool = Field(..., description="Whether the command exited successfully (usually exit code 0)")
