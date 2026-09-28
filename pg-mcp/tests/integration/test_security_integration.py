"""Security integration tests against a real PostgreSQL instance.

These tests verify that the SQLExecutor's database-level defenses actually
hold: read-only transactions, row limiting, timeouts, and type serialization.
They exercise the second line of defense behind SQLValidator (layer 1).

Case IDs (SEC-INT-*) map to docs/TEST_CASES.md.
Requires: PostgreSQL reachable via DATABASE_* env vars (.env), default
localhost:5444/blog_small. Tests skip automatically when the DB is down.
"""

import decimal

import asyncpg
import pytest

from pg_mcp.config.settings import DatabaseConfig, SecurityConfig
from pg_mcp.models.errors import DatabaseError, ExecutionTimeoutError
from pg_mcp.services.sql_executor import SQLExecutor
from pg_mcp.services.sql_validator import SQLValidator

pytestmark = pytest.mark.integration


@pytest.fixture
async def pool():
    """Function-scoped connection pool; skips the test if DB is unreachable.

    Function scope is required because pytest-asyncio creates a fresh event
    loop per test; asyncpg connections cannot cross loops.
    """
    db_config = DatabaseConfig()
    try:
        test_pool = await asyncpg.create_pool(
            dsn=db_config.dsn,
            min_size=1,
            max_size=5,
            timeout=5,
        )
        # Fail fast on bad credentials
        async with test_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
    except (OSError, asyncpg.PostgresError) as exc:
        pytest.skip(f"PostgreSQL not available ({db_config.host}:{db_config.port}): {exc}")
    yield test_pool
    await test_pool.close()


@pytest.fixture
async def executor(pool: asyncpg.Pool) -> SQLExecutor:
    return SQLExecutor(pool, SecurityConfig(), DatabaseConfig())


@pytest.fixture
async def validator() -> SQLValidator:
    return SQLValidator(SecurityConfig())


async def users_row_count(executor: SQLExecutor) -> int:
    rows, _ = await executor.execute("SELECT COUNT(*) AS n FROM users")
    return rows[0]["n"]


# ============================================================================
# Layer-2 defense: read-only transaction enforcement
# ============================================================================


class TestReadOnlyEnforcement:
    """Executor must make writes impossible even if the validator misses them."""

    async def test_direct_delete_blocked(self, executor: SQLExecutor) -> None:
        """SEC-INT-001: DELETE inside read-only transaction raises and writes nothing."""
        before = await users_row_count(executor)

        with pytest.raises(DatabaseError):
            await executor.execute("DELETE FROM users")

        after = await users_row_count(executor)
        assert before == after, "data changed despite read-only transaction!"

    async def test_data_modifying_cte_blocked(self, executor: SQLExecutor) -> None:
        """SEC-INT-002: write-CTE is caught by the read-only transaction (layer 2)."""
        before = await users_row_count(executor)

        with pytest.raises(DatabaseError):
            await executor.execute("WITH d AS (DELETE FROM users) SELECT 1")

        after = await users_row_count(executor)
        assert before == after

    async def test_select_into_blocked(self, executor: SQLExecutor) -> None:
        """SEC-INT-003: SELECT INTO (table creation) fails in read-only transaction."""
        with pytest.raises(DatabaseError):
            await executor.execute("SELECT * INTO hacked_users FROM users")

        # The table must not exist
        rows, _ = await executor.execute(
            "SELECT COUNT(*) AS n FROM information_schema.tables "
            "WHERE table_name = 'hacked_users'"
        )
        assert rows[0]["n"] == 0

    async def test_update_blocked(self, executor: SQLExecutor) -> None:
        """SEC-INT-004: UPDATE raises DatabaseError."""
        with pytest.raises(DatabaseError):
            await executor.execute("UPDATE users SET name = 'hacked'")

    async def test_insert_blocked(self, executor: SQLExecutor) -> None:
        """SEC-INT-005: INSERT raises DatabaseError."""
        with pytest.raises(DatabaseError):
            await executor.execute("INSERT INTO users (id) VALUES (999999)")


# ============================================================================
# Resource controls
# ============================================================================


class TestResourceControls:
    """Row limiting and timeout behavior."""

    async def test_row_limit_and_total_count(self, executor: SQLExecutor) -> None:
        """SEC-INT-006: max_rows truncates results but reports the true total."""
        rows, total = await executor.execute(
            "SELECT g FROM generate_series(1, 50) g",
            max_rows=10,
        )
        assert len(rows) == 10
        assert total == 50
        assert [r["g"] for r in rows] == list(range(1, 11))

    async def test_row_limit_default_applied(self, executor: SQLExecutor) -> None:
        """SEC-INT-007: unset max_rows falls back to config (10000)."""
        rows, total = await executor.execute(
            "SELECT g FROM generate_series(1, 12000) g",
        )
        assert len(rows) == 10000
        assert total == 12000

    async def test_query_timeout(self, executor: SQLExecutor) -> None:
        """SEC-INT-008: long-running query raises ExecutionTimeoutError."""
        with pytest.raises(ExecutionTimeoutError):
            await executor.execute("SELECT pg_sleep(10)", timeout=1.0)

    async def test_fast_query_survives_timeout_config(self, executor: SQLExecutor) -> None:
        """SEC-INT-009: timeout settings do not break fast queries."""
        rows, total = await executor.execute("SELECT 1 AS one", timeout=5.0)
        assert total == 1
        assert rows[0]["one"] == 1


# ============================================================================
# Type serialization
# ============================================================================


class TestTypeSerialization:
    """PostgreSQL-specific types must serialize to JSON-compatible values."""

    async def test_pg_types_serialized(self, executor: SQLExecutor) -> None:
        """SEC-INT-010: timestamp/numeric/uuid/bool serialize to str/float/str/bool."""
        rows, _ = await executor.execute(
            "SELECT '2024-01-01 12:00:00'::timestamp AS ts, "
            "99.99::numeric AS price, "
            "'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid AS uid, "
            "true AS active",
        )
        row = rows[0]
        assert isinstance(row["ts"], str) and row["ts"].startswith("2024-01-01T12:00:00")
        assert isinstance(row["price"], float) and row["price"] == pytest.approx(99.99)
        assert row["uid"] == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
        assert row["active"] is True
        assert not isinstance(row["price"], decimal.Decimal)

    async def test_null_serialized(self, executor: SQLExecutor) -> None:
        """SEC-INT-011: NULL values survive serialization as None."""
        rows, _ = await executor.execute("SELECT NULL AS nothing")
        assert rows[0]["nothing"] is None

    async def test_multibyte_text_roundtrip(self, executor: SQLExecutor) -> None:
        """SEC-INT-012: Chinese text round-trips through the executor."""
        rows, _ = await executor.execute("SELECT '数据库安全测试' AS label")
        assert rows[0]["label"] == "数据库安全测试"


# ============================================================================
# End-to-end: validator (layer 1) + executor (layer 2)
# ============================================================================


class TestValidatorExecutorE2E:
    """Validated queries execute; rejected queries never touch the database."""

    async def test_validated_query_executes(
        self, executor: SQLExecutor, validator: SQLValidator
    ) -> None:
        """SEC-INT-013: happy path — validate then execute."""
        sql = "SELECT id, username, full_name FROM users ORDER BY id LIMIT 3"
        is_valid, error = validator.validate(sql)
        assert is_valid, error

        rows, total = await executor.execute(sql)
        assert total == len(rows)
        assert len(rows) <= 3

    async def test_rejected_query_never_executes(
        self, executor: SQLExecutor, validator: SQLValidator
    ) -> None:
        """SEC-INT-014: validator rejection short-circuits before any DB call."""
        sql = "WITH d AS (DELETE FROM users) SELECT * FROM d"
        is_valid, _ = validator.validate(sql)
        assert not is_valid  # layer 1 catches it (DEFECT-01 fixed)
        # If layer 1 were bypassed, layer 2 (read-only txn) would still hold —
        # covered by TestReadOnlyEnforcement.

    async def test_schema_qualified_read(
        self, executor: SQLExecutor, validator: SQLValidator
    ) -> None:
        """SEC-INT-015: qualified identifiers execute fine in the public schema."""
        sql = "SELECT COUNT(*) AS n FROM public.users"
        is_valid, error = validator.validate(sql)
        assert is_valid, error
        rows, _ = await executor.execute(sql)
        assert rows[0]["n"] == await users_row_count(executor)
