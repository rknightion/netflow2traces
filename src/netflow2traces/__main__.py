"""Main entry point for NetFlow to OpenTelemetry Traces application.

Run with: python -m netflow2traces
"""

import logging
import signal
import sys

from .collector import NetflowCollector
from .config import Config
from .tracer import TracerManager

logger = logging.getLogger(__name__)

# Global references for signal handling
collector: NetflowCollector | None = None
tracer_manager: TracerManager | None = None


def signal_handler(signum: int, frame: any) -> None:
    """Handle shutdown signals gracefully.

    Args:
        signum: Signal number.
        frame: Current stack frame.
    """
    signal_name = signal.Signals(signum).name
    logger.info(f"Received signal {signal_name}, initiating graceful shutdown...")

    # Stop collector
    if collector:
        collector.stop()

    # Shutdown tracer (flush pending spans)
    if tracer_manager:
        tracer_manager.shutdown()

    logger.info("Shutdown complete")
    sys.exit(0)


def main() -> int:
    """Main application entry point.

    Returns:
        Exit code (0 for success, non-zero for error).
    """
    global collector, tracer_manager

    try:
        # Load configuration from environment
        config = Config.from_env()
        config.setup_logging()

        logger.info("=" * 60)
        logger.info("NetFlow to OpenTelemetry Traces Converter")
        logger.info("=" * 60)
        logger.info(f"\n{config}\n")

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Initialize OpenTelemetry tracer
        tracer_manager = TracerManager(config)
        tracer = tracer_manager.setup()

        # Initialize and start NetFlow collector
        collector = NetflowCollector(config, tracer)
        collector.start()

        return 0

    except ValueError as e:
        # Configuration errors
        logger.error(f"Configuration error: {e}")
        logger.error(
            "\nPlease ensure all required environment variables are set. "
            "See .env.example for reference."
        )
        return 1

    except OSError as e:
        # Network/socket errors
        logger.error(f"Network error: {e}")
        logger.error(
            f"\nFailed to bind to {config.netflow_listen_host}:{config.netflow_listen_port}. "
            "Check if the port is already in use or if you have sufficient privileges."
        )
        return 1

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
        if collector:
            collector.stop()
        if tracer_manager:
            tracer_manager.shutdown()
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1

    finally:
        # Ensure cleanup
        if collector:
            stats = collector.get_stats()
            logger.info(f"Final statistics: {stats}")


if __name__ == "__main__":
    sys.exit(main())
