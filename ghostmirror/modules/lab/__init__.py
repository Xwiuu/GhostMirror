"""Lab Mode — controlled vulnerable environments for training and testing."""

from ghostmirror.modules.lab.manager import LabManager, LabSafetyGuard
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.docker_runner import DockerRunner
from ghostmirror.modules.lab.health import LabHealth
from ghostmirror.modules.lab.project_factory import LabProjectFactory
from ghostmirror.modules.lab.benchmark import LabBenchmark

__all__ = [
    "LabManager",
    "LabSafetyGuard",
    "LabCatalog",
    "DockerRunner",
    "LabHealth",
    "LabProjectFactory",
    "LabBenchmark",
]
