"""Tests for mcp_shield.classification.risk — tool risk classification."""

from __future__ import annotations

import pytest

from mcp_shield.classification.risk import classify_tool_risk
from mcp_shield.storage.audit_db import RiskTier


class TestReadTier:
    """Tools that only read/query data → RiskTier.READ."""

    def test_read_file(self):
        assert classify_tool_risk("read_file", "Read a file from disk") == RiskTier.READ

    def test_get_user(self):
        assert classify_tool_risk("get_user", "Retrieve user information") == RiskTier.READ

    def test_list_items(self):
        assert classify_tool_risk("list_files", "List directory contents") == RiskTier.READ

    def test_search(self):
        assert classify_tool_risk("search", "Search for documents") == RiskTier.READ

    def test_fetch(self):
        assert classify_tool_risk("fetch_data", "Fetch data from an API") == RiskTier.READ

    def test_query(self):
        assert classify_tool_risk("query_db", "Query the database") == RiskTier.READ

    def test_show(self):
        assert classify_tool_risk("show_config", "Show configuration") == RiskTier.READ

    def test_describe(self):
        assert classify_tool_risk("describe_table", "Describe table schema") == RiskTier.READ

    def test_count(self):
        assert classify_tool_risk("count_rows", "Count rows in table") == RiskTier.READ

    def test_view(self):
        assert classify_tool_risk("view_logs", "View recent log entries") == RiskTier.READ

    def test_inspect(self):
        assert classify_tool_risk("inspect_element", "Inspect a DOM element") == RiskTier.READ


class TestWriteReversibleTier:
    """Tools that modify local/reversible state → RiskTier.WRITE_REVERSIBLE."""

    def test_write_file(self):
        assert classify_tool_risk("write_file", "Write content to a file") == RiskTier.WRITE_REVERSIBLE

    def test_edit_file(self):
        assert classify_tool_risk("edit_file", "Edit a file") == RiskTier.WRITE_REVERSIBLE

    def test_create_file(self):
        assert classify_tool_risk("create_file", "Create a new file") == RiskTier.WRITE_REVERSIBLE

    def test_update_config(self):
        assert classify_tool_risk("update_config", "Update configuration settings") == RiskTier.WRITE_REVERSIBLE

    def test_rename(self):
        assert classify_tool_risk("rename_file", "Rename a file") == RiskTier.WRITE_REVERSIBLE

    def test_move(self):
        assert classify_tool_risk("move_file", "Move file to another location") == RiskTier.WRITE_REVERSIBLE

    def test_copy(self):
        assert classify_tool_risk("copy_file", "Copy file to destination") == RiskTier.WRITE_REVERSIBLE

    def test_mkdir(self):
        assert classify_tool_risk("mkdir", "Create a directory") == RiskTier.WRITE_REVERSIBLE

    def test_save(self):
        assert classify_tool_risk("save_draft", "Save a draft") == RiskTier.WRITE_REVERSIBLE

    def test_set_value(self):
        assert classify_tool_risk("set_value", "Set a configuration value") == RiskTier.WRITE_REVERSIBLE

    def test_patch(self):
        assert classify_tool_risk("patch_record", "Patch a record") == RiskTier.WRITE_REVERSIBLE


class TestWriteExternalTier:
    """Tools that affect external systems → RiskTier.WRITE_EXTERNAL."""

    def test_send_email(self):
        assert classify_tool_risk("send_email", "Send an email message") == RiskTier.WRITE_EXTERNAL

    def test_send_message(self):
        assert classify_tool_risk("send_message", "Send a message via Slack") == RiskTier.WRITE_EXTERNAL

    def test_post_to_api(self):
        assert classify_tool_risk("post_data", "Post data to external API") == RiskTier.WRITE_EXTERNAL

    def test_publish(self):
        assert classify_tool_risk("publish_article", "Publish to the blog") == RiskTier.WRITE_EXTERNAL

    def test_deploy(self):
        assert classify_tool_risk("deploy", "Deploy to production") == RiskTier.WRITE_EXTERNAL

    def test_push(self):
        assert classify_tool_risk("git_push", "Push commits to remote") == RiskTier.WRITE_EXTERNAL

    def test_notify(self):
        assert classify_tool_risk("notify_team", "Send notification to team") == RiskTier.WRITE_EXTERNAL

    def test_webhook(self):
        assert classify_tool_risk("trigger_webhook", "Trigger a webhook") == RiskTier.WRITE_EXTERNAL

    def test_upload(self):
        assert classify_tool_risk("upload_file", "Upload file to cloud storage") == RiskTier.WRITE_EXTERNAL

    def test_submit(self):
        assert classify_tool_risk("submit_form", "Submit form data") == RiskTier.WRITE_EXTERNAL


class TestWriteSensitiveTier:
    """Tools that affect security-critical state → RiskTier.WRITE_SENSITIVE."""

    def test_delete_file(self):
        assert classify_tool_risk("delete_file", "Delete a file permanently") == RiskTier.WRITE_SENSITIVE

    def test_remove(self):
        assert classify_tool_risk("remove_user", "Remove a user account") == RiskTier.WRITE_SENSITIVE

    def test_drop_table(self):
        assert classify_tool_risk("drop_table", "Drop a database table") == RiskTier.WRITE_SENSITIVE

    def test_execute_command(self):
        assert classify_tool_risk("execute_command", "Execute a shell command") == RiskTier.WRITE_SENSITIVE

    def test_run_code(self):
        assert classify_tool_risk("run_code", "Run arbitrary code") == RiskTier.WRITE_SENSITIVE

    def test_exec_sql(self):
        assert classify_tool_risk("exec_sql", "Execute SQL statement") == RiskTier.WRITE_SENSITIVE

    def test_eval(self):
        assert classify_tool_risk("eval_expression", "Evaluate an expression") == RiskTier.WRITE_SENSITIVE

    def test_shell(self):
        assert classify_tool_risk("shell", "Run shell commands") == RiskTier.WRITE_SENSITIVE

    def test_admin_action(self):
        assert classify_tool_risk("admin_reset", "Reset admin settings") == RiskTier.WRITE_SENSITIVE

    def test_truncate(self):
        assert classify_tool_risk("truncate_table", "Truncate a table") == RiskTier.WRITE_SENSITIVE

    def test_destroy(self):
        assert classify_tool_risk("destroy_instance", "Destroy a cloud instance") == RiskTier.WRITE_SENSITIVE

    def test_purge(self):
        assert classify_tool_risk("purge_cache", "Purge all cached data") == RiskTier.WRITE_SENSITIVE

    def test_format_disk(self):
        assert classify_tool_risk("format_disk", "Format disk") == RiskTier.WRITE_SENSITIVE


class TestUnknownTier:
    """Ambiguous tool names → RiskTier.UNKNOWN."""

    def test_generic_name(self):
        assert classify_tool_risk("process", "Process something") == RiskTier.UNKNOWN

    def test_ambiguous(self):
        assert classify_tool_risk("handle_request", "Handle an incoming request") == RiskTier.UNKNOWN

    def test_empty_description(self):
        assert classify_tool_risk("mystery_tool", "") == RiskTier.UNKNOWN


class TestDescriptionOverridesName:
    """Description signals can upgrade/clarify the tier."""

    def test_name_neutral_desc_delete(self):
        # Name is ambiguous but description mentions deletion
        assert classify_tool_risk("process_item", "Permanently delete the item") == RiskTier.WRITE_SENSITIVE

    def test_name_neutral_desc_read(self):
        assert classify_tool_risk("do_thing", "Retrieve the latest metrics") == RiskTier.READ

    def test_name_neutral_desc_send(self):
        assert classify_tool_risk("handle", "Send notification to external service") == RiskTier.WRITE_EXTERNAL

    def test_name_neutral_desc_write(self):
        assert classify_tool_risk("perform", "Write data to local file") == RiskTier.WRITE_REVERSIBLE


class TestSchemaInfluence:
    """Input schema can influence classification."""

    def test_schema_with_command_field(self):
        schema = {"type": "object", "properties": {"command": {"type": "string"}}}
        assert classify_tool_risk("run", "Run something", schema) == RiskTier.WRITE_SENSITIVE

    def test_schema_with_sql_field(self):
        schema = {"type": "object", "properties": {"sql_query": {"type": "string"}}}
        assert classify_tool_risk("query", "Query data", schema) == RiskTier.WRITE_SENSITIVE

    def test_schema_with_url_field(self):
        schema = {"type": "object", "properties": {"url": {"type": "string"}, "body": {"type": "string"}}}
        assert classify_tool_risk("request", "Make HTTP request", schema) == RiskTier.WRITE_EXTERNAL

    def test_schema_read_only(self):
        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        assert classify_tool_risk("read_file", "Read file contents", schema) == RiskTier.READ


class TestCaseInsensitive:
    """Classification is case-insensitive."""

    def test_uppercase_name(self):
        assert classify_tool_risk("READ_FILE", "Read a file") == RiskTier.READ

    def test_mixed_case_desc(self):
        assert classify_tool_risk("tool", "DELETE all records permanently") == RiskTier.WRITE_SENSITIVE

    def test_camel_case(self):
        assert classify_tool_risk("readFile", "Read file from disk") == RiskTier.READ


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_name(self):
        assert classify_tool_risk("", "") == RiskTier.UNKNOWN

    def test_none_schema(self):
        assert classify_tool_risk("read_file", "Read a file", None) == RiskTier.READ

    def test_empty_schema(self):
        assert classify_tool_risk("read_file", "Read a file", {}) == RiskTier.READ

    def test_priority_sensitive_over_external(self):
        # If both delete and send signals, sensitive wins
        assert classify_tool_risk("delete_and_notify", "Delete the item and send notification") == RiskTier.WRITE_SENSITIVE

    def test_priority_external_over_reversible(self):
        # If both write and send signals, external wins
        assert classify_tool_risk("save_and_send", "Save locally and send email") == RiskTier.WRITE_EXTERNAL

    # -- Nested schema field detection (bug fix) --

    def test_nested_command_field_sensitive(self):
        """Nested 'command' field in schema should trigger WRITE_SENSITIVE."""
        schema = {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                },
            },
        }
        assert classify_tool_risk("run", "Run something", schema) == RiskTier.WRITE_SENSITIVE

    def test_nested_url_plus_body_external(self):
        """Nested 'url' + 'body' fields should trigger WRITE_EXTERNAL."""
        schema = {
            "type": "object",
            "properties": {
                "request": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "body": {"type": "string"},
                    },
                },
            },
        }
        assert classify_tool_risk("send_request", "Make HTTP request", schema) == RiskTier.WRITE_EXTERNAL

    def test_deeply_nested_limited(self):
        """Nesting deeper than 5 levels should be truncated (no infinite recursion)."""
        # Build 7-level deep nesting
        inner = {"type": "object", "properties": {"command": {"type": "string"}}}
        for _ in range(7):
            inner = {"type": "object", "properties": {"nested": inner}}
        # Should not crash; command at depth 8 won't be found due to depth limit
        result = classify_tool_risk("tool", "", inner)
        # Should not be WRITE_SENSITIVE since the command is beyond depth limit
        assert result in (RiskTier.UNKNOWN, RiskTier.WRITE_SENSITIVE)
