"""Tests for mcp_shield.security.injection — InjectionDetector."""

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.injection import InjectionDetector


def _tool(name: str = "test_tool", input_schema: dict | None = None) -> ToolInfo:
    return ToolInfo(name=name, description="A tool.", input_schema=input_schema or {})


class TestInjectionDetector:
    def setup_method(self):
        self.detector = InjectionDetector()

    # -- clean schemas --

    def test_clean_schema_no_findings(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
            },
        })
        findings = self.detector.scan_tool(tool)
        assert findings == []

    def test_empty_dict_schema_no_findings(self):
        """An empty schema with type=object is not flagged."""
        tool = _tool(input_schema={"type": "object"})
        findings = self.detector.scan_tool(tool)
        assert findings == []

    # -- risky field names --

    def test_command_field_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd_findings) == 1
        assert cmd_findings[0].severity == "high"

    def test_query_field_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "sql_query": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        assert any("INJECT-CMD" in f.finding_id for f in findings)

    def test_shell_field_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "shell": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        assert any("INJECT-CMD" in f.finding_id for f in findings)

    def test_eval_field_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "eval_expression": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        assert any("INJECT-CMD" in f.finding_id for f in findings)

    def test_risky_name_integer_type_not_flagged(self):
        """A 'command' field with type=integer is not a string injection risk."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "integer"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd_findings == []

    # -- path fields --

    def test_path_without_pattern_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert len(path_findings) == 1
        assert path_findings[0].severity == "medium"

    def test_path_with_pattern_not_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "pattern": r"^[a-zA-Z0-9/._-]+$"},
            },
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert path_findings == []

    def test_path_with_enum_not_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "directory": {"type": "string", "enum": ["/tmp", "/var/log"]},
            },
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert path_findings == []

    def test_url_field_flagged(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        assert any("INJECT-PATH" in f.finding_id for f in findings)

    # -- empty schema --

    def test_no_properties_no_type_flagged(self):
        """Schema with no properties and no type=object is flagged."""
        tool = _tool(input_schema={"description": "anything goes"})
        findings = self.detector.scan_tool(tool)
        empty_findings = [f for f in findings if "INJECT-EMPTY" in f.finding_id]
        assert len(empty_findings) == 1

    # -- edge cases --

    def test_non_dict_schema_no_crash(self):
        tool = _tool(input_schema=None)  # type: ignore[arg-type]
        tool.input_schema = "not a dict"  # type: ignore[assignment]
        findings = self.detector.scan_tool(tool)
        assert findings == []

    def test_non_dict_properties_no_crash(self):
        tool = _tool(input_schema={"type": "object", "properties": "invalid"})
        findings = self.detector.scan_tool(tool)
        assert findings == []

    def test_multiple_risky_fields(self):
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "query": {"type": "string"},
                "filepath": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert len(cmd_findings) == 2  # command + query
        assert len(path_findings) == 1  # filepath

    # -- IV-10: Union types --

    def test_union_string_null_command_flagged(self):
        """type: ["string", "null"] should still be detected as string."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "command": {"type": ["string", "null"]},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd_findings) == 1

    def test_union_string_null_path_flagged(self):
        """Union type with string should detect path traversal risk."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "filepath": {"type": ["string", "null"]},
            },
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert len(path_findings) == 1

    def test_union_integer_null_not_flagged(self):
        """type: ["integer", "null"] — no string, should not flag."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "command": {"type": ["integer", "null"]},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd_findings == []

    def test_union_path_with_pattern_not_flagged(self):
        """Union type with pattern constraint should not flag path traversal."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "filepath": {
                    "type": ["string", "null"],
                    "pattern": r"^[a-zA-Z0-9/._-]+$",
                },
            },
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert path_findings == []

    # -- DC-10: oneOf/anyOf/allOf --

    def test_oneof_command_field_flagged(self):
        """Command field inside oneOf branch should be detected."""
        tool = _tool(input_schema={
            "type": "object",
            "oneOf": [
                {
                    "properties": {
                        "command": {"type": "string"},
                    },
                },
                {
                    "properties": {
                        "name": {"type": "string"},
                    },
                },
            ],
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd_findings) == 1

    def test_anyof_path_field_flagged(self):
        """Path field inside anyOf branch should be detected."""
        tool = _tool(input_schema={
            "type": "object",
            "anyOf": [
                {
                    "properties": {
                        "filepath": {"type": "string"},
                    },
                },
            ],
        })
        findings = self.detector.scan_tool(tool)
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert len(path_findings) == 1

    def test_allof_combined_detection(self):
        """Fields from allOf branches should all be scanned."""
        tool = _tool(input_schema={
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "query": {"type": "string"},
                    },
                },
                {
                    "properties": {
                        "filepath": {"type": "string"},
                    },
                },
            ],
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        path_findings = [f for f in findings if "INJECT-PATH" in f.finding_id]
        assert len(cmd_findings) == 1  # query
        assert len(path_findings) == 1  # filepath

    # -- Context-aware query severity --

    def test_search_tool_query_downgraded_to_medium(self):
        """'query' field in a search tool should be MEDIUM, not HIGH."""
        tool = _tool(name="search_nodes", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd_findings) == 1
        assert cmd_findings[0].severity == "medium"

    def test_search_tool_query_variants(self):
        """Various search-like tool names should downgrade query severity."""
        for tool_name in [
            "duckduckgo_web_search", "search_location", "find_packages",
            "lookup_user", "resolve-library-id", "browse_catalog",
        ]:
            tool = _tool(name=tool_name, input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
            })
            findings = self.detector.scan_tool(tool)
            cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
            assert len(cmd) == 1, f"{tool_name}: expected 1 finding"
            assert cmd[0].severity == "medium", (
                f"{tool_name}: expected medium, got {cmd[0].severity}"
            )

    def test_sql_tool_query_stays_high(self):
        """'query' field in a non-search tool (e.g. read_query) stays HIGH."""
        tool = _tool(name="read_query", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd_findings) == 1
        assert cmd_findings[0].severity == "high"

    def test_write_query_stays_high(self):
        tool = _tool(name="write_query", input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd[0].severity == "high"

    def test_command_always_high_even_in_search_tool(self):
        """'command' field stays HIGH regardless of tool name."""
        tool = _tool(name="search_commands", input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd[0].severity == "high"

    def test_description_not_flagged(self):
        """'description' should NOT match 'script'."""
        tool = _tool(name="start_process", input_schema={
            "type": "object",
            "properties": {"description": {"type": "string"}},
        })
        findings = self.detector.scan_tool(tool)
        cmd_findings = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd_findings == []

    # -- Field description context --

    def test_query_with_search_description_downgraded(self):
        """'query' field with search-like description → MEDIUM even in non-search tool."""
        tool = _tool(name="db_tool", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term to look up"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd) == 1
        assert cmd[0].severity == "medium"

    def test_query_with_sql_description_stays_high(self):
        """'query' field with SQL description → stays HIGH."""
        tool = _tool(name="data_tool", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query to execute"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd) == 1
        assert cmd[0].severity == "high"

    def test_command_with_safe_description_stays_high(self):
        """'command' field stays HIGH regardless of description."""
        tool = _tool(name="runner", input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "A harmless label"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd[0].severity == "high"

    def test_query_with_keyword_description_downgraded(self):
        """'query' field with 'keyword' description → MEDIUM."""
        tool = _tool(name="api_tool", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Keyword to filter by"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd[0].severity == "medium"

    def test_query_no_description_uses_tool_name_context(self):
        """'query' with no field description → fallback to tool name check."""
        tool = _tool(name="data_manager", input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd[0].severity == "high"

    def test_schema_with_oneof_not_flagged_as_empty(self):
        """Schema with oneOf but no direct properties should not be flagged as empty."""
        tool = _tool(input_schema={
            "oneOf": [
                {"type": "object", "properties": {"name": {"type": "string"}}},
            ],
        })
        findings = self.detector.scan_tool(tool)
        empty_findings = [f for f in findings if "INJECT-EMPTY" in f.finding_id]
        assert empty_findings == []

    # -- Hyphenated field names (bug fix) --

    def test_hyphenated_sql_query_field(self):
        """Hyphenated field name 'sql-query' must be detected."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "sql-query": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd) >= 1
        assert "sql-query" in cmd[0].finding_id

    def test_hyphenated_run_command_field(self):
        """Hyphenated field name 'run-command' must be detected."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "run-command": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd) >= 1

    def test_hyphenated_shell_exec_field(self):
        """Hyphenated field name 'shell-exec' must be detected."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "shell-exec": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert len(cmd) >= 1

    def test_hyphenated_safe_field_not_flagged(self):
        """Hyphenated field 'user-name' should not be flagged."""
        tool = _tool(input_schema={
            "type": "object",
            "properties": {
                "user-name": {"type": "string"},
            },
        })
        findings = self.detector.scan_tool(tool)
        cmd = [f for f in findings if "INJECT-CMD" in f.finding_id]
        assert cmd == []
