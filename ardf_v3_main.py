#!/usr/bin/env python3
"""ARDF v3 Main Entry Point - Complete framework initialization and execution."""

import sys
import argparse
import logging
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

from ardf_v3_framework import ARDFv3Framework, get_framework
from ardf_v3_endpoints import ARDFv3EndpointRegistry, HTTPMethod, EndpointCategory
from ardf_v3_dashboard_api import ARDFv3DashboardAPI


class ARDFv3Application:
    """Main ARDF v3 application."""

    def __init__(self, base_path: str = ".", config_file: Optional[str] = None):
        self.base_path = Path(base_path)
        self.config_file = config_file
        self.config = self._load_config()
        self.framework = get_framework(str(self.base_path))
        self.logger = self._setup_logging()
        self.dashboard: Optional[ARDFv3DashboardAPI] = None

    def _load_config(self) -> dict:
        """Load configuration."""
        default_config = {
            "framework": {
                "debug": False,
                "log_level": "INFO",
                "max_workers": 8,
                "timeout": 300
            },
            "dashboard": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "auth_key": "change_me_in_production"
            },
            "modules": {
                "auto_load": True,
                "load_timeout": 30,
                "skip_on_error": True
            },
            "api": {
                "rate_limit": 100,
                "timeout": 30,
                "enable_cors": True
            }
        }

        if self.config_file and Path(self.config_file).exists():
            try:
                with open(self.config_file) as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Failed to load config file: {e}")

        return default_config

    def _setup_logging(self) -> logging.Logger:
        """Setup logging."""
        log_level = self.config.get("framework", {}).get("log_level", "INFO")
        logger = logging.getLogger("ARDF-v3")

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, log_level))

        return logger

    def print_banner(self) -> None:
        """Print application banner."""
        banner = """
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    ARDF v3 - Autonomous Red Team Deployment                ║
║                           Framework v3.0.0                                 ║
║                                                                            ║
║  Complete unified framework with:                                         ║
║    • 131 Python modules across all attack vectors                         ║
║    • Dynamic endpoint registry with OpenAPI support                       ║
║    • Real-time web dashboard with authentication                          ║
║    • Module auto-discovery and dependency resolution                      ║
║    • RESTful API with comprehensive logging                               ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def initialize(self) -> bool:
        """Initialize the framework."""
        self.print_banner()
        self.logger.info("Initializing ARDF v3 Framework...")

        try:
            if not self.framework.initialize():
                self.logger.error("Framework initialization failed")
                return False

            self.logger.info("Framework initialization complete")
            return True
        except Exception as e:
            self.logger.error(f"Initialization error: {e}", exc_info=True)
            return False

    def start_dashboard(self) -> bool:
        """Start the dashboard server."""
        if not self.config.get("dashboard", {}).get("enabled"):
            self.logger.info("Dashboard disabled in configuration")
            return True

        try:
            dashboard_config = self.config.get("dashboard", {})
            # Fall back to config/ardf.yaml dashboard section (A7 localhost default)
            try:
                import yaml as _yaml
                _yp = Path("config/ardf.yaml")
                if _yp.exists():
                    _yd = (_yaml.safe_load(_yp.read_text()) or {}).get("dashboard", {}) or {}
                    dashboard_config = {**{"host": _yd.get("host", "127.0.0.1"),
                                           "port": _yd.get("port", 5000)},
                                        **{k: v for k, v in dashboard_config.items()
                                           if k in ("host", "port") and v not in
                                           ("0.0.0.0", 5000, None)}}
                    self.config["dashboard"].update(dashboard_config)
            except Exception:
                pass
            import os
            # Must be set before the API object reads it in __init__.
            os.environ["ARDF_AUTH_KEY"] = str(
                dashboard_config.get("auth_key") or
                os.getenv("ARDF_AUTH_KEY", "change_me"))

            self.dashboard = ARDFv3DashboardAPI(
                self.framework,
                host=dashboard_config.get("host", "0.0.0.0"),
                port=dashboard_config.get("port", 5000),
                debug=dashboard_config.get("debug", False)
            )

            self.dashboard.run()
            return True
        except ImportError:
            self.logger.warning("Flask not installed. Dashboard unavailable.")
            self.logger.info("Install with: pip install flask (flask-cors is optional)")
            return False
        except Exception as e:
            self.logger.error(f"Dashboard startup error: {e}")
            return False

    def print_status(self) -> None:
        """Print current framework status."""
        state = self.framework.get_framework_state()

        status_output = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                       FRAMEWORK STATUS REPORT                              ║
╠════════════════════════════════════════════════════════════════════════════╣
║ Status: {'INITIALIZED' if state.get('initialized') else 'NOT INITIALIZED':40} ║
║ Modules Loaded: {state.get('modules_loaded', 0):31} ║
║ Modules Failed: {state.get('modules_failed', 0):31} ║
║ Endpoints Registered: {state.get('endpoints_registered', 0):27} ║
║ Uptime: {state.get('start_time', 'unknown'):45} ║
╠════════════════════════════════════════════════════════════════════════════╣
║ Module Categories:                                                         ║
"""
        for category, count in state.get("modules_info", {}).items():
            status_output += f"║   • {category:50} ║\n"

        status_output += """╠════════════════════════════════════════════════════════════════════════════╣
║ Endpoint Categories:                                                       ║
"""
        for category in self.framework.endpoints.get_categories():
            status_output += f"║   • {category:50} ║\n"

        status_output += f"""╠════════════════════════════════════════════════════════════════════════════╣
║ Dashboard: {'ENABLED' if self.config.get('dashboard', {}).get('enabled') else 'DISABLED':42} ║
║ API Endpoints: {len(self.framework.endpoints.endpoints):40} ║
╚════════════════════════════════════════════════════════════════════════════╝
        """
        print(status_output)

    def export_configuration(self, output_file: str) -> bool:
        """Export framework configuration."""
        try:
            config = {
                "version": "3.0.0",
                "timestamp": datetime.now().isoformat(),
                "framework": self.framework.get_framework_state(),
                "endpoints": self.framework.list_endpoints(),
                "configuration": self.config
            }

            with open(output_file, "w") as f:
                json.dump(config, f, indent=2)

            self.logger.info(f"Configuration exported to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            return False

    def run_interactive_mode(self) -> None:
        """Run in interactive mode."""
        self.print_status()

        while True:
            try:
                command = input("\nardf-v3> ").strip().lower()

                if command in ["exit", "quit", "q"]:
                    break
                elif command == "status":
                    self.print_status()
                elif command == "modules":
                    modules = self.framework.get_modules()
                    print(f"\n{len(modules)} modules loaded:")
                    for mod_id, info in modules.items():
                        print(f"  • {mod_id}: {info.get('status')}")
                elif command == "endpoints":
                    endpoints = self.framework.list_endpoints()
                    print(f"\n{len(endpoints)} endpoints registered:")
                    for key, info in endpoints.items():
                        print(f"  • {key}: {info.get('doc', 'N/A')}")
                elif command == "health":
                    health = self.framework.health_check()
                    print(f"\nHealth Status: {json.dumps(health, indent=2)}")
                elif command == "stats":
                    stats = self.framework.get_framework_state()
                    print(f"\nFramework Statistics: {json.dumps(stats, indent=2)}")
                elif command.startswith("export"):
                    parts = command.split()
                    if len(parts) > 1:
                        self.export_configuration(parts[1])
                    else:
                        print("Usage: export <filename>")
                elif command == "help":
                    print("""
Available commands:
  status              - Show framework status
  modules             - List loaded modules
  endpoints           - List registered endpoints
  health              - Show health check
  stats               - Show detailed statistics
  export <file>       - Export configuration to file
  help                - Show this help
  exit/quit           - Exit application
                    """)
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in interactive mode: {e}")

    def shutdown(self) -> None:
        """Shutdown the application."""
        self.logger.info("Shutting down ARDF v3...")
        self.framework.shutdown()
        self.logger.info("ARDF v3 shutdown complete")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ARDF v3 - Autonomous Red Team Deployment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ardf_v3_main.py --status               # Show framework status
  ardf_v3_main.py --dashboard            # Start web dashboard
  ardf_v3_main.py --interactive          # Interactive mode
  ardf_v3_main.py --export config.json   # Export configuration
  ardf_v3_main.py --config my_config.json # Load custom configuration
        """
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Show framework status and exit"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start web dashboard (default if Flask installed)"
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Dashboard bind host (overrides config; default from config/ardf.yaml)"
    )
    parser.add_argument(
        "--port",
        default=None, type=int,
        help="Dashboard port (overrides config; default from config/ardf.yaml)"
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Start in interactive mode"
    )
    parser.add_argument(
        "--config",
        help="Custom configuration file path"
    )
    parser.add_argument(
        "--export",
        help="Export framework configuration to file"
    )
    parser.add_argument(
        "--base-path",
        default=".",
        help="Base path for ARDF modules (default: current directory)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    app = ARDFv3Application(args.base_path, args.config)

    if args.debug:
        app.config["framework"]["log_level"] = "DEBUG"
        app.config["dashboard"]["debug"] = True

    try:
        if not app.initialize():
            sys.exit(1)

        if args.status:
            app.print_status()
        elif args.export:
            app.export_configuration(args.export)
        elif args.dashboard:
            if args.host:
                app.config["dashboard"]["host"] = args.host
            if args.port:
                app.config["dashboard"]["port"] = args.port
            app.start_dashboard()
        elif args.interactive:
            app.run_interactive_mode()
        else:
            app.print_status()
            print("\nNo action specified. Use --help for options.")
            print("Default: Starting interactive mode...")
            app.run_interactive_mode()

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        app.logger.error(f"Fatal error: {e}", exc_info=args.debug)
        sys.exit(1)
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
