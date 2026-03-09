from __future__ import annotations

import sys
import types

from flask import Flask, jsonify
import pytest

from app.routes import api as api_routes
from app.routes import helpdesk as helpdesk_routes
from app.routes import ipam as ipam_routes
from app.routes import monitoring as monitoring_routes


def _install_fake_service_module(module_name: str, **functions: object) -> None:
    fake_mod = types.ModuleType(module_name)
    for key, value in functions.items():
        setattr(fake_mod, key, value)
    sys.modules[module_name] = fake_mod


def test_ipam_routes_delegate_to_services(monkeypatch: pytest.MonkeyPatch) -> None:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test"
    ipam_routes.register_routes(app)

    _install_fake_service_module(
        "app.services.legacy_ipam_handlers",
        ip_addressing_dashboard=lambda: ("ipam-dashboard", 200),
        ip_addressing_live_data_api=lambda: jsonify({"ok": True}),
    )
    _install_fake_service_module(
        "app.services.legacy_ip_branch_handlers",
        manage_ip_branches=lambda: ("managed", 200),
        request_ip_branch_add=lambda: ("requested-add", 200),
        request_ip_branch_delete=lambda: ("requested-delete", 200),
        ip_branch_state_api=lambda: jsonify({"rows": []}),
        network_isp_branches_state_api=lambda: jsonify({"rows": []}),
        network_isp_atms_state_api=lambda: jsonify({"rows": []}),
    )

    with app.test_client() as client:
        assert client.get("/ip-addressing").status_code == 200
        assert client.get("/ip-addressing/live-data").get_json()["ok"] is True
        assert client.post("/ip-branches").status_code == 200
        assert client.post("/ip-branches/request-add").status_code == 200
        assert client.post("/ip-branches/request-delete").status_code == 200
        assert client.get("/ip-branches/state").status_code == 200


def test_monitoring_helpdesk_and_api_routes_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test"
    monitoring_routes.register_routes(app)
    helpdesk_routes.register_routes(app)
    api_routes.register_routes(app)

    _install_fake_service_module(
        "app.services.legacy_monitoring_handlers",
        monitoring_node_add_page=lambda: ("ok", 200),
        monitoring_node_delete_page=lambda: ("ok", 200),
        monitoring_category_add_page=lambda: ("ok", 200),
        monitoring_category_delete_page=lambda: ("ok", 200),
        monitoring_category_rename_page=lambda: ("ok", 200),
        monitoring_node_test_snmp_api=lambda: jsonify({"ok": True}),
        monitoring_node_resources_pull_api=lambda: jsonify({"ok": True}),
        monitoring_node_resources_save_api=lambda: jsonify({"ok": True}),
        monitoring_alert_ack_api=lambda: jsonify({"ok": True}),
        monitoring_node_dashboard_data_api=lambda: jsonify({"ok": True}),
        monitoring_node_live_gauges_api=lambda: jsonify({"ok": True}),
    )
    _install_fake_service_module(
        "app.services.legacy_command_handlers",
        helpdesk_interfaces_api=lambda: jsonify({"ok": True}),
        run_commands=lambda: ("run", 200),
        run_commands_api=lambda: jsonify({"ok": True}),
        open_ssh_sessions_api=lambda: jsonify({"ok": True}),
        run_session_command_api=lambda: jsonify({"ok": True}),
        ping_selected_devices=lambda: jsonify({"ok": True}),
    )

    with app.test_client() as client:
        assert client.post("/monitoring/node/dashboard-data").get_json()["ok"] is True
        assert client.post("/monitoring/node/live-gauges").get_json()["ok"] is True
        assert client.post("/helpdesk/interfaces").get_json()["ok"] is True
        assert client.post("/run").status_code == 200
        assert client.post("/run-api").get_json()["ok"] is True
        assert client.post("/ssh-session-open").get_json()["ok"] is True
        assert client.post("/run-session-api").get_json()["ok"] is True
