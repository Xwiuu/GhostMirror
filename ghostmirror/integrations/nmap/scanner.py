"""Nmap tool integration wrapper and XML parser implementation."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import ToolRunner
from ghostmirror.integrations.models.port_finding import PortFinding
from ghostmirror.integrations.models.result import ToolExecutionResult

logger = get_logger()


class NmapParser:
    """Parser for Nmap XML output (-oX option)."""

    @staticmethod
    def parse_xml_content(xml_content: str) -> List[PortFinding]:
        """Parses raw Nmap XML string into a list of PortFinding objects.

        Parameters
        ----------
        xml_content : str
            The raw XML string from Nmap.

        Returns
        -------
        List[PortFinding]
            List of parsed PortFinding models.
        """
        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            logger.error("NMAP_XML_PARSE_FAILED error={}", exc)
            raise ValueError(f"Invalid Nmap XML output: {exc}") from exc

        findings: List[PortFinding] = []

        # Iterate over all <host> nodes
        for host in root.findall("host"):
            # Extract state of the host
            status_node = host.find("status")
            if status_node is not None and status_node.get("state") == "down":
                continue

            # Ports list for this host
            ports_node = host.find("ports")
            if ports_node is None:
                continue

            for port in ports_node.findall("port"):
                portid_str = port.get("portid")
                if not portid_str or not portid_str.isdigit():
                    continue

                port_num = int(portid_str)
                protocol = port.get("protocol", "tcp")

                state_node = port.find("state")
                state = state_node.get("state", "unknown") if state_node is not None else "unknown"

                service_node = port.find("service")
                service_name = "unknown"
                product = "Unknown"
                version = "Unknown"

                if service_node is not None:
                    service_name = service_node.get("name", "unknown")
                    product = service_node.get("product", "Unknown")
                    version = service_node.get("version", "Unknown")

                findings.append(
                    PortFinding(
                        port=port_num,
                        protocol=protocol,
                        service=service_name,
                        product=product,
                        version=version,
                        state=state,
                    )
                )

        return findings

    @classmethod
    def parse_xml_file(cls, filepath: Path | str) -> List[PortFinding]:
        """Reads and parses an Nmap XML output file.

        Parameters
        ----------
        filepath : Path | str
            Path to the XML file.

        Returns
        -------
        List[PortFinding]
            List of parsed PortFinding models.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found at {path}")

        content = path.read_text(encoding="utf-8")
        return cls.parse_xml_content(content)


class NmapRunner:
    """Helper to run the Nmap binary using ToolRunner."""

    def __init__(self, tool_runner: ToolRunner | None = None) -> None:
        self.runner = tool_runner or ToolRunner()

    def scan(
        self,
        target: str,
        xml_output_path: Path | str,
        ports_limit: int = 100,
        timing_template: int = 3,
        timeout: float | None = 600.0,
    ) -> ToolExecutionResult:
        """Executes nmap scan on the target, writing the XML output to xml_output_path.

        Parameters
        ----------
        target : str
            Target IP or domain.
        xml_output_path : Path | str
            Filepath to save the XML output (-oX option).
        ports_limit : int, default 100
            Number of top ports to scan (--top-ports option).
        timing_template : int, default 3
            Timing template value (-T option, range 0-5).
        timeout : float | None, default 600.0
            Maximum time allowed for scan execution in seconds.

        Returns
        -------
        ToolExecutionResult
            Execution results from ToolRunner.
        """
        xml_path = Path(xml_output_path)
        xml_path.parent.mkdir(parents=True, exist_ok=True)

        args = [
            "-sV",
            "--top-ports",
            str(ports_limit),
            f"-T{timing_template}",
            "-oX",
            str(xml_path),
            target,
        ]

        logger.info("NMAP_SCAN_RUNNING target={} ports_limit={} T={}", target, ports_limit, timing_template)
        
        # ToolRunner handles binary validation, process execution, timeout and metrics
        return self.runner.run(
            tool_name="nmap",
            args=args,
            timeout=timeout,
        )
