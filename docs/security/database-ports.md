# SQL Database Port Blocking

LASSO blocks direct database access at two layers: network ports (iptables) and command gate (client tools). This document covers the network port blocking layer.

## Blocked Ports (Default)

All of these ports are blocked in every network mode (including `full`), defined in `NetworkConfig.blocked_ports`:

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 1433 | TCP | Microsoft SQL Server / SSMS | Default instance port |
| 1434 | UDP/TCP | MSSQL Browser Service | Instance discovery; used by named instances |
| 3306 | TCP | MySQL | Default port |
| 5432 | TCP | PostgreSQL | Default port |
| 27017 | TCP | MongoDB | Default port |
| 6379 | TCP | Redis | Default port; also used by KeyDB, Dragonfly |
| 9042 | TCP | Apache Cassandra (CQL) | Native transport |
| 8123 | TCP | ClickHouse (HTTP) | HTTP interface |
| 9000 | TCP | ClickHouse (native) | Native TCP protocol |
| 1521 | TCP | Oracle Database | Default listener port |
| 5984 | TCP | Apache CouchDB | HTTP API |

Source: `lasso/config/schema.py`, `NetworkConfig.blocked_ports` field default.

## How NetworkConfig.blocked_ports Works

### In the schema (`lasso/config/schema.py`)

The `blocked_ports` field is a list of integers on the `NetworkConfig` model:

```python
class NetworkConfig(BaseModel):
    blocked_ports: list[int] = Field(
        default_factory=lambda: [
            1433, 1434, 3306, 5432, 27017, 6379,
            9042, 8123, 9000, 1521, 5984,
        ],
        description="TCP ports always blocked (database servers). Applied even in full network mode.",
    )
```

### In the network policy (`lasso/core/network.py`)

The `NetworkPolicy.generate_iptables_rules()` method creates DROP rules for every blocked port. These rules are applied **before** any allow rules, in all network modes:

```python
# Block database ports in ALL modes (FULL and RESTRICTED)
for port in self.config.blocked_ports:
    rules.append([
        "iptables", "-A", "OUTPUT", "-p", "tcp",
        "--dport", str(port), "-j", "DROP",
    ])
```

The `check_destination()` pre-flight check also rejects connections to blocked ports with a descriptive message:

```python
if port in self.config.blocked_ports:
    return False, f"BLOCKED: Port {port} ({db_name}) -- direct database access is not permitted."
```

### In the command gate (`lasso/core/commands.py`)

Database client tools are also blocked at the command level via `DANGEROUS_ARGS` with empty pattern lists (meaning the command is blocked entirely):

```python
DANGEROUS_ARGS = {
    "sqlcmd": [],    "bcp": [],       "osql": [],
    "isql": [],      "sqlplus": [],   "mysql": [],
    "psql": [],      "mongo": [],     "mongosh": [],
    "redis-cli": [], "cqlsh": [],     "clickhouse-client": [],
}
```

This provides defense in depth: even if a port is unblocked, the client tools are still rejected by the command gate.

### Enforcement in NONE mode

When `network.mode = "none"`, the default iptables policy is DROP on all chains. Blocked port rules are not generated separately because all traffic is already dropped. Only loopback is allowed.

## Adding Custom Blocked Ports in Team Profiles

### Override the default list

To add ports while keeping the defaults, list all ports (TOML replaces the entire list):

```toml
[network]
blocked_ports = [
    # Defaults
    1433, 1434, 3306, 5432, 27017, 6379,
    9042, 8123, 9000, 1521, 5984,
    # Team additions
    11211,  # Memcached
    9200,   # Elasticsearch HTTP
    9300,   # Elasticsearch transport
    7474,   # Neo4j HTTP
    7687,   # Neo4j Bolt
    26257,  # CockroachDB
    28015,  # RethinkDB
]
```

### In a team profile using extends

When using `extends`, the `blocked_ports` field in your profile replaces the base profile's list entirely. Always include the default ports:

```toml
# profiles/team-strict.toml
extends = "strict"

[network]
# strict has mode = "none", so ports are moot there.
# But if you switch to restricted mode, these will apply:
blocked_ports = [
    1433, 1434, 3306, 5432, 27017, 6379,
    9042, 8123, 9000, 1521, 5984,
    11211, 9200, 9300,
]
```

### Removing a default blocked port

If your team legitimately needs database access (e.g., a read-only analytics sandbox connecting to a staging database), remove the port from the list:

```toml
[network]
mode = "restricted"
allowed_domains = ["staging-db.internal.example.com"]
allowed_ports = [443, 5432]
# PostgreSQL removed from blocked list; all others remain blocked
blocked_ports = [
    1433, 1434, 3306, 27017, 6379,
    9042, 8123, 9000, 1521, 5984,
]
```

Note: even with port 5432 unblocked at the network level, the `psql` command is still blocked by the command gate (`DANGEROUS_ARGS`). The agent would need to use a Python library (e.g., `psycopg2`) to connect, which provides an additional point of control and audit logging.

## Test Coverage

Database port blocking is tested in:
- `tests/unit/test_database_blocking.py` — verifies both port blocking (network layer) and client tool blocking (command gate)
- `tests/unit/test_network.py` — verifies iptables rule generation for blocked ports
- `tests/unit/test_network_enforcement.py` — verifies `check_destination()` rejects blocked ports with correct error messages
