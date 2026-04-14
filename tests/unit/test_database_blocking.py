"""Tests for database access blocking — command-level and network-level.

Ensures that direct database client tools and database server ports
are blocked in all sandbox configurations. This is critical for
environments with sensitive data on SQL Server (SSMS), PostgreSQL,
MySQL, MongoDB, etc.
"""

import pytest

from lasso.config.schema import CommandConfig, CommandMode, NetworkConfig, NetworkMode
from lasso.core.commands import DANGEROUS_ARGS, CommandGate
from lasso.core.network import NetworkPolicy

# ---------------------------------------------------------------------------
# Command-level database tool blocking
# ---------------------------------------------------------------------------

class TestDatabaseClientToolsBlocked:
    """All database client CLI tools must be blocked by DANGEROUS_ARGS."""

    @pytest.fixture
    def gate(self):
        """Gate with database tools in the whitelist — they should STILL be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=[
                "ls", "cat", "python3",
                # Even if someone adds these to whitelist, DANGEROUS_ARGS blocks them
                "sqlcmd", "bcp", "psql", "mysql", "mongo", "redis-cli",
            ],
        )
        return CommandGate(config)

    @pytest.mark.parametrize("tool", [
        "sqlcmd",       # MSSQL / SSMS
        "bcp",          # MSSQL bulk copy
        "osql",         # Legacy MSSQL
        "isql",         # ODBC interactive SQL
        "sqlplus",      # Oracle
        "mysql",        # MySQL
        "psql",         # PostgreSQL
        "mongo",        # MongoDB (legacy)
        "mongosh",      # MongoDB shell
        "redis-cli",    # Redis
        "cqlsh",        # Cassandra
        "clickhouse-client",  # ClickHouse
    ])
    def test_db_tool_blocked_even_if_whitelisted(self, gate, tool):
        """Database tools are blocked — either by whitelist or DANGEROUS_ARGS."""
        v = gate.check(f"{tool} -S myserver -d mydb")
        assert v.blocked, f"{tool} should be blocked but was allowed"

    def test_all_db_tools_in_dangerous_args(self):
        """Verify all database tools are registered in DANGEROUS_ARGS."""
        db_tools = [
            "sqlcmd", "bcp", "osql", "isql", "sqlplus",
            "mysql", "psql", "mongo", "mongosh",
            "redis-cli", "cqlsh", "clickhouse-client",
        ]
        for tool in db_tools:
            assert tool in DANGEROUS_ARGS, f"{tool} missing from DANGEROUS_ARGS"
            assert DANGEROUS_ARGS[tool] == [], f"{tool} should have empty pattern list (full block)"

    def test_sqlcmd_with_connection_string_blocked(self, gate):
        v = gate.check("sqlcmd -S localhost,1433 -U sa -P password -d master -Q 'SELECT * FROM users'")
        assert v.blocked

    def test_bcp_export_blocked(self, gate):
        v = gate.check("bcp mydb.dbo.users out users.csv -S server -T -c")
        assert v.blocked

    def test_psql_connection_blocked(self, gate):
        v = gate.check("psql postgresql://user:pass@dbhost:5432/mydb")
        assert v.blocked

    def test_mysql_connection_blocked(self, gate):
        v = gate.check("mysql -h dbhost -u root -p mydb")
        assert v.blocked

    def test_mongo_connection_blocked(self, gate):
        v = gate.check("mongo mongodb://user:pass@dbhost:27017/admin")
        assert v.blocked

    def test_normal_commands_still_work(self, gate):
        """Blocking DB tools doesn't affect normal commands."""
        assert gate.check("ls -la").allowed
        assert gate.check("cat file.txt").allowed
        assert gate.check("python3 script.py").allowed


# ---------------------------------------------------------------------------
# Python database library detection in commands
# ---------------------------------------------------------------------------

class TestPythonDBLibraryDetection:
    """Python scripts that import database libraries should be audited.

    Note: LASSO doesn't block `python3` itself — it blocks the DB
    client tools and network ports. Python scripts connecting to DBs
    via libraries (pyodbc, psycopg2) are blocked at the NETWORK level
    (ports 1433, 5432, etc. are dropped by iptables).
    """

    @pytest.fixture
    def gate(self):
        return CommandGate(CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3"],
        ))

    def test_python3_allowed(self, gate):
        """python3 itself is allowed — DB access blocked at network level."""
        v = gate.check("python3 script.py")
        assert v.allowed

    def test_python3_script_allowed(self, gate):
        """Python scripts are allowed — DB access blocked at network level."""
        v = gate.check("python3 analyze.py --output results.csv")
        assert v.allowed


# ---------------------------------------------------------------------------
# Network-level database port blocking
# ---------------------------------------------------------------------------

class TestDatabasePortBlocking:
    """Database server ports must be blocked at the iptables level."""

    @pytest.fixture
    def restricted_policy(self):
        return NetworkPolicy(NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            allowed_domains=["pypi.org"],
            allowed_ports=[80, 443],
        ))

    @pytest.fixture
    def full_policy(self):
        return NetworkPolicy(NetworkConfig(mode=NetworkMode.FULL))

    @pytest.mark.parametrize("port,db_name", [
        (1433, "MSSQL/SQL Server"),
        (1434, "MSSQL Browser"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (27017, "MongoDB"),
        (6379, "Redis"),
        (9042, "Cassandra"),
        (8123, "ClickHouse"),
        (9000, "ClickHouse"),
        (1521, "Oracle"),
        (5984, "CouchDB"),
    ])
    def test_db_port_blocked_in_restricted_mode(self, restricted_policy, port, db_name):
        allowed, reason = restricted_policy.check_destination("dbserver.internal", port)
        assert not allowed
        assert "BLOCKED" in reason or "not in allowed" in reason

    @pytest.mark.parametrize("port,db_name", [
        (1433, "MSSQL/SQL Server"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (27017, "MongoDB"),
        (6379, "Redis"),
    ])
    def test_db_port_blocked_in_full_mode(self, full_policy, port, db_name):
        """Database ports blocked even in FULL network mode."""
        allowed, reason = full_policy.check_destination("dbserver.internal", port)
        assert not allowed
        assert "BLOCKED" in reason
        assert db_name in reason or "database" in reason

    def test_web_ports_still_allowed(self, restricted_policy):
        """Normal web ports are not affected by DB blocking."""
        # These still depend on domain allowlist in restricted mode
        allowed, reason = restricted_policy.check_destination("pypi.org", 443)
        assert allowed

    def test_iptables_includes_db_port_rules(self, full_policy):
        """iptables rules include DROP rules for all DB ports."""
        rules = full_policy.generate_iptables_rules()
        rule_strs = [" ".join(r) for r in rules]

        for port in [1433, 3306, 5432, 27017, 6379]:
            found = any(str(port) in r and "DROP" in r for r in rule_strs)
            assert found, f"No iptables DROP rule for port {port}"

    def test_iptables_db_rules_before_allow_rules(self, restricted_policy):
        """DB port blocks should appear before any ACCEPT rules."""
        rules = restricted_policy.generate_iptables_rules()
        rule_strs = [" ".join(r) for r in rules]

        # Find first DB DROP rule and first non-loopback ACCEPT
        first_db_drop = None
        first_accept = None
        for i, r in enumerate(rule_strs):
            if "1433" in r and "DROP" in r and first_db_drop is None:
                first_db_drop = i
            if "ACCEPT" in r and "lo" not in r and first_accept is None:
                first_accept = i

        if first_db_drop is not None and first_accept is not None:
            assert first_db_drop < first_accept, "DB port blocks should come before ACCEPT rules"

    def test_policy_explains_blocked_db_ports(self, restricted_policy):
        """explain_policy() shows blocked database ports."""
        policy = restricted_policy.explain_policy()
        assert "blocked_ports_database" in policy
        assert 1433 in policy["blocked_ports_database"]
        assert 5432 in policy["blocked_ports_database"]


# ---------------------------------------------------------------------------
# Profile-level DB blocking visibility
# ---------------------------------------------------------------------------

class TestProfileDBBlockingVisibility:
    """Profiles should clearly show that DB access is blocked."""

    def test_default_network_config_has_blocked_ports(self):
        config = NetworkConfig()
        assert 1433 in config.blocked_ports  # MSSQL
        assert 3306 in config.blocked_ports  # MySQL
        assert 5432 in config.blocked_ports  # PostgreSQL

    def test_minimal_profile_blocks_db(self):
        from lasso.config.defaults import evaluation_profile
        p = evaluation_profile("/tmp/test")
        # No network at all
        assert p.network.mode == NetworkMode.NONE

    def test_development_profile_blocks_db_ports(self):
        from lasso.config.defaults import standard_profile
        p = standard_profile("/tmp/test")
        assert 1433 in p.network.blocked_ports
        assert 5432 in p.network.blocked_ports

    def test_strict_profile_blocks_db(self):
        from lasso.config.defaults import strict_profile
        p = strict_profile("/tmp/test")
        # No network at all
        assert p.network.mode == NetworkMode.NONE
