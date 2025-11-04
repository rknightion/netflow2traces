"""NetFlow to OpenTelemetry Traces Converter.

A Python application that listens for NetFlow/IPFIX data and converts it
to OpenTelemetry traces for observability.
"""

__version__ = "0.1.0"

__all__ = [
    "Config",
    "TracerManager",
    "NetflowCollector",
]

from .collector import NetflowCollector
from .config import Config
from .tracer import TracerManager
