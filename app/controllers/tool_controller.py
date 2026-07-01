from flask import Blueprint, jsonify

from app.engine.registry import SCANNER_REGISTRY, TOOL_REGISTRY
from app.extensions import auth


class ToolController:
    """Read-only management surface for the Tool Management UI.

    The Flask process never invokes apt-get / nuclei -update-templates itself —
    the UI copies the suggested command for the user to run in their own
    terminal. See ARCHITECTURE.md / chapter 6.4 control TOOL-1.
    """

    def __init__(self):
        self.bp = Blueprint("tools", __name__, url_prefix="/api/tools")
        # Auth required even on read-only endpoint to avoid leaking the
        # host's installed-scanner inventory to unauthenticated probes.
        self.bp.add_url_rule(
            "", "list",
            auth.login_required(self.list_tools),
            methods=["GET"],
        )

    def register(self, app):
        app.register_blueprint(self.bp)

    def list_tools(self):
        return jsonify({
            "tools": [
                {
                    "name": cls.name,
                    "cli_name": cls.cli_name,
                    "apt_package": cls.apt_package,
                    "installed": cls.is_installed(),
                    "version": cls.installed_version(),
                    "is_scanner": name in SCANNER_REGISTRY,
                    "install_command": cls.install_command(),
                    "update_command": cls.update_command(),
                }
                for name, cls in TOOL_REGISTRY.items()
            ]
        })
