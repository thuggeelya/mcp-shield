"""Tests for mcp_shield.security.dangerous_ops — DangerousOpDetector."""

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.dangerous_ops import DangerousOpDetector


def _tool(name: str, description: str = "A tool.") -> ToolInfo:
    return ToolInfo(name=name, description=description, input_schema={})


class TestDangerousOpDetector:
    def setup_method(self):
        self.detector = DangerousOpDetector()

    # -- Destructive operations (HIGH) --

    def test_delete_flagged(self):
        findings = self.detector.scan_tool(_tool("delete_file"))
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "DANGER-DESTRUCT" in findings[0].finding_id

    def test_drop_flagged(self):
        findings = self.detector.scan_tool(_tool("drop_table"))
        assert any("DANGER-DESTRUCT" in f.finding_id for f in findings)

    def test_git_clean_flagged(self):
        findings = self.detector.scan_tool(_tool("git_clean"))
        assert any("DANGER-DESTRUCT" in f.finding_id for f in findings)

    def test_purge_flagged(self):
        findings = self.detector.scan_tool(_tool("purge_cache"))
        assert any(f.severity == "high" for f in findings)

    def test_remove_flagged(self):
        findings = self.detector.scan_tool(_tool("remove_user"))
        assert any("DANGER-DESTRUCT" in f.finding_id for f in findings)

    # -- Dangerous write operations (MEDIUM) --

    def test_git_push_flagged(self):
        findings = self.detector.scan_tool(_tool("git_push"))
        write = [f for f in findings if "DANGER-WRITE" in f.finding_id]
        assert len(write) == 1
        assert write[0].severity == "medium"

    def test_deploy_flagged(self):
        findings = self.detector.scan_tool(_tool("deploy_app"))
        assert any("DANGER-WRITE" in f.finding_id for f in findings)

    def test_git_reset_flagged(self):
        findings = self.detector.scan_tool(_tool("git_reset"))
        assert any("DANGER-WRITE" in f.finding_id for f in findings)

    def test_git_rebase_flagged(self):
        findings = self.detector.scan_tool(_tool("git_rebase"))
        assert any("DANGER-WRITE" in f.finding_id for f in findings)

    def test_force_push_double_flagged(self):
        """force_push matches both 'force' (write) and 'push' (write)."""
        findings = self.detector.scan_tool(_tool("force_push"))
        write = [f for f in findings if "DANGER-WRITE" in f.finding_id]
        assert len(write) >= 1

    # -- Execution operations (MEDIUM) --

    def test_run_code_flagged(self):
        findings = self.detector.scan_tool(_tool("run_code"))
        exec_f = [f for f in findings if "DANGER-EXEC" in f.finding_id]
        assert len(exec_f) == 1
        assert exec_f[0].severity == "medium"

    def test_exec_command_flagged(self):
        findings = self.detector.scan_tool(_tool("exec_command"))
        assert any("DANGER-EXEC" in f.finding_id for f in findings)

    def test_start_process_flagged(self):
        findings = self.detector.scan_tool(_tool("start_process"))
        assert any("DANGER-EXEC" in f.finding_id for f in findings)

    def test_kill_process_flagged(self):
        findings = self.detector.scan_tool(_tool("kill_process"))
        assert any("DANGER-EXEC" in f.finding_id for f in findings)

    def test_terminate_flagged(self):
        findings = self.detector.scan_tool(_tool("terminate_worker"))
        assert any("DANGER-EXEC" in f.finding_id for f in findings)

    # -- Safe operations (no findings) --

    def test_read_file_clean(self):
        findings = self.detector.scan_tool(_tool("read_file"))
        assert findings == []

    def test_list_directory_clean(self):
        findings = self.detector.scan_tool(_tool("list_directory"))
        assert findings == []

    def test_get_status_clean(self):
        findings = self.detector.scan_tool(_tool("git_status"))
        assert findings == []

    def test_search_clean(self):
        findings = self.detector.scan_tool(_tool("search_nodes"))
        assert findings == []

    def test_add_clean(self):
        findings = self.detector.scan_tool(_tool("git_add"))
        assert findings == []

    def test_commit_clean(self):
        findings = self.detector.scan_tool(_tool("git_commit"))
        assert findings == []

    # -- Multiple categories --

    def test_multiple_categories(self):
        """A tool can match multiple danger categories."""
        findings = self.detector.scan_tool(_tool("execute_delete_command"))
        categories = {f.finding_id.split("-")[1] for f in findings}
        assert "DESTRUCT" in categories
        assert "EXEC" in categories

    # -- Description-based detection --

    def test_description_deletes_data(self):
        """Detect dangerous ops from description even when name is safe."""
        tool = ToolInfo(name="manage_data", description="Permanently deletes all user records.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1
        assert desc_findings[0].severity == "medium"

    def test_description_executes_commands(self):
        tool = ToolInfo(name="admin_action", description="Executes arbitrary shell commands on the host.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    def test_description_drops_database(self):
        tool = ToolInfo(name="db_admin", description="Drops the entire database schema.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    def test_description_safe_no_findings(self):
        """Safe descriptions should produce no description-based findings."""
        tool = ToolInfo(name="read_config", description="Reads the current configuration file.")
        findings = self.detector.scan_tool(tool)
        assert findings == []

    def test_description_no_duplicate_with_name(self):
        """If name already flagged, description check for same category is skipped."""
        tool = ToolInfo(name="delete_file", description="Permanently deletes a file from disk.")
        findings = self.detector.scan_tool(tool)
        # Should have name-based DESTRUCT, but NOT description-based too
        destruct = [f for f in findings if "DESTRUCT" in f.finding_id]
        assert len(destruct) == 1  # only name-based

    def test_description_force_overwrites(self):
        tool = ToolInfo(name="update_config", description="Force-overwrites the existing configuration without backup.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    def test_description_deploys_to_production(self):
        tool = ToolInfo(name="release_manager", description="Deploys the application to production servers.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    def test_description_kills_process(self):
        tool = ToolInfo(name="process_manager", description="Kills running processes by PID.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    # -- Negation in descriptions (bug fix) --

    def test_description_does_not_delete(self):
        """'does not delete' should NOT trigger destructive finding."""
        tool = ToolInfo(name="safe_tool", description="This tool does not delete any records.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert desc_findings == []

    def test_description_cannot_remove(self):
        """'cannot remove' should NOT trigger destructive finding."""
        tool = ToolInfo(name="read_only", description="This operation cannot remove users from the system.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert desc_findings == []

    def test_description_never_deletes(self):
        """'never deletes' should NOT trigger destructive finding."""
        tool = ToolInfo(name="archiver", description="Archives old data but never deletes it.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert desc_findings == []

    def test_description_wont_overwrite(self):
        """'won't overwrite' should NOT trigger write finding."""
        tool = ToolInfo(name="safe_save", description="Saves data but won't overwrite existing files.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert desc_findings == []

    def test_description_prevent_deletion(self):
        """'prevent deletion' should NOT trigger destructive finding."""
        tool = ToolInfo(name="protector", description="Helps prevent deletion of important resources.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC-DESTRUCT" in f.finding_id]
        assert desc_findings == []

    def test_description_actual_delete_still_flagged(self):
        """Genuine destructive description without negation should still be flagged."""
        tool = ToolInfo(name="cleanup", description="Permanently deletes all temporary files.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC-DESTRUCT" in f.finding_id]
        assert len(desc_findings) == 1

    def test_description_actual_deploy_still_flagged(self):
        """Genuine deploy description without negation should still be flagged."""
        tool = ToolInfo(name="release_manager", description="Deploys the application to production.")
        findings = self.detector.scan_tool(tool)
        desc_findings = [f for f in findings if "DESC" in f.finding_id]
        assert len(desc_findings) == 1

    # -- Protocol compliance --

    def test_implements_detector_protocol(self):
        from mcp_shield.security.base import Detector
        assert isinstance(self.detector, Detector)
