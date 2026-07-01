"""Console entrypoint: ``cerberus-envoy-ai-gateway``."""

import sys

import uvicorn

from .app import create_app
from .config import Config, ConfigError


def main() -> None:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"cerberus-envoy-ai-gateway: configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    uvicorn.run(
        create_app(config),
        host="0.0.0.0",  # noqa: S104 — container/cluster service
        port=config.listen_port,
        log_level=config.log_level,
    )


if __name__ == "__main__":
    main()
