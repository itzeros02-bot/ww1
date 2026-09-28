"""Adversarial security tests for SQLValidator.

AI-generated test suite covering attack vectors against the read-only SQL
validation layer. Case IDs (SEC-*) map 1:1 to docs/TEST_CASES.md.

Known defects documented by this suite (see docs/DEFECT_REPORT.md):
- DEFECT-01: data-modifying CTEs passed validation      -> FIXED (recursive tree check)
- DEFECT-02: EXPLAIN ANALYZE executed inner statements  -> FIXED (ANALYZE keyword check)
- DEFECT-03: SELECT INTO created tables                 -> FIXED (Select.into check)
- DEFECT-04: SELECT * bypasses blocked_columns          -> KNOWN LIMITATION (needs schema)
"""

import pytest

from pg_mcp.config.settings import SecurityConfig
from pg_mcp.services.sql_validator import SQLValidator


@pytest.fixture
def validator() -> SQLValidator:
    """Default validator: EXPLAIN disabled, no table/column restrictions."""
    return SQLValidator(SecurityConfig())


@pytest.fixture
def explain_validator() -> SQLValidator:
    """Validator with EXPLAIN explicitly enabled (DEFECT-02 attack surface)."""
    return SQLValidator(SecurityConfig(), allow_explain=True)


@pytest.fixture
def restricted_validator() -> SQLValidator:
    """Validator with blocked tables and a sensitive column configured."""
    return SQLValidator(
        SecurityConfig(),
        blocked_tables=["secrets", "audit_log", "user_credentials"],
        blocked_columns=["password", "credit_card"],
    )


def assert_blocked(validator: SQLValidator, sql: str, expect_keyword: str | None = None) -> None:
    """Assert SQL is rejected; optionally require a keyword in the error."""
    is_valid, error = validator.validate(sql)
    assert not is_valid, f"SECURITY LEAK: validator allowed: {sql!r}"
    assert error, f"rejection must carry an error message: {sql!r}"
    if expect_keyword:
        assert expect_keyword.lower() in error.lower(), (
            f"error {error!r} does not mention {expect_keyword!r} for {sql!r}"
        )


def assert_allowed(validator: SQLValidator, sql: str) -> None:
    """Assert legitimate read-only SQL passes validation."""
    is_valid, error = validator.validate(sql)
    assert is_valid, f"false positive: legitimate query rejected: {sql!r} ({error})"


# ============================================================================
# DEFECT-01 regression: data-modifying CTEs (WITH ... AS (DELETE/INSERT/UPDATE))
# PostgreSQL executes CTE writes eagerly; the top-level check only saw SELECT.
# ============================================================================


class TestDataModifyingCTE:
    """Write operations hidden inside WITH clauses must be rejected (SEC-CTE-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-CTE-001", "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d"),
            ("SEC-CTE-002", "WITH d AS (DELETE FROM users) SELECT 1"),
            ("SEC-CTE-003", "WITH i AS (INSERT INTO users VALUES (1) RETURNING *) SELECT * FROM i"),
            ("SEC-CTE-004", "WITH u AS (UPDATE users SET name = 'x' RETURNING *) SELECT * FROM u"),
            ("SEC-CTE-005", "WITH u AS (UPDATE users SET name = 'x') SELECT 1"),
            (
                "SEC-CTE-006",
                "WITH a AS (SELECT 1), d AS (DELETE FROM users RETURNING *) SELECT * FROM a",
            ),
            (
                "SEC-CTE-007",
                "SELECT * FROM (WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d) s",
            ),
            ("SEC-CTE-008", "WITH t AS (WITH d AS (DELETE FROM users) SELECT 1) SELECT * FROM t"),
            ("SEC-CTE-009", "WITH d AS (DELETE FROM users) SELECT 1 UNION SELECT 2"),
            ("SEC-CTE-010", "WITH drop1 AS (DROP TABLE users) SELECT 1"),
            ("SEC-CTE-011", "WITH c AS (CREATE TABLE stolen AS SELECT * FROM users) SELECT 1"),
            ("SEC-CTE-012", "with d as (delete from users returning *) select * from d"),
        ],
    )
    def test_write_cte_blocked(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(validator, sql, expect_keyword="not allowed")

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-CTE-101", "WITH t AS (SELECT id FROM users) SELECT * FROM t"),
            ("SEC-CTE-102", "WITH RECURSIVE t AS (SELECT 1) SELECT * FROM t"),
            (
                "SEC-CTE-103",
                "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a JOIN b ON true",
            ),
        ],
    )
    def test_readonly_cte_allowed(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_allowed(validator, sql)


# ============================================================================
# DEFECT-02 regression: EXPLAIN ANALYZE actually executes the inner statement
# ============================================================================


class TestExplainExecutionBypass:
    """EXPLAIN ANALYZE variants must be rejected; plain EXPLAIN stays allowed (SEC-EXP-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-EXP-001", "EXPLAIN ANALYZE DELETE FROM users"),
            ("SEC-EXP-002", "EXPLAIN ANALYZE UPDATE users SET name = 'x'"),
            ("SEC-EXP-003", "EXPLAIN ANALYZE INSERT INTO users VALUES (1)"),
            ("SEC-EXP-004", "EXPLAIN (ANALYZE) SELECT 1"),
            ("SEC-EXP-005", "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1"),
            ("SEC-EXP-006", "explain analyze delete from users"),
            ("SEC-EXP-007", "EXPLAIN ANALYZE SELECT * FROM users WHERE id > 100"),
            ("SEC-EXP-008", "  EXPLAIN   ANALYZE   DELETE FROM users"),
        ],
    )
    def test_explain_analyze_blocked(
        self, explain_validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(explain_validator, sql, expect_keyword="analyze")

    def test_plain_explain_still_allowed(self, explain_validator: SQLValidator) -> None:
        """SEC-EXP-101: plan-only EXPLAIN (no execution) stays permitted."""
        assert_allowed(explain_validator, "EXPLAIN SELECT * FROM users")
        assert_allowed(explain_validator, "EXPLAIN DELETE FROM users")  # plans, never executes

    def test_explain_disabled_by_default(self, validator: SQLValidator) -> None:
        """SEC-EXP-102: default config rejects all EXPLAIN."""
        assert_blocked(validator, "EXPLAIN SELECT 1", expect_keyword="explain")


# ============================================================================
# DEFECT-03 regression: SELECT INTO creates tables
# ============================================================================


class TestSelectIntoSmuggling:
    """SELECT INTO must be rejected because it materializes new tables (SEC-INTO-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-INTO-001", "SELECT * INTO tmp FROM users"),
            ("SEC-INTO-002", "SELECT id INTO TEMP t2 FROM users"),
            ("SEC-INTO-003", "SELECT id INTO UNLOGGED t3 FROM users"),
            ("SEC-INTO-004", "select id into new_users from users where id = 1"),
        ],
    )
    def test_select_into_blocked(self, validator: SQLValidator, case_id: str, sql: str) -> None:
        assert_blocked(validator, sql)

    def test_into_word_as_alias_allowed(self, validator: SQLValidator) -> None:
        """SEC-INTO-101: 'into' as a plain identifier must not false-positive."""
        assert_allowed(validator, "SELECT into_col FROM users")


# ============================================================================
# DEFECT-04: SELECT * bypasses column blacklist (documented limitation)
# ============================================================================


class TestStarExpansionColumnBypass:
    """SELECT * cannot be checked against blocked_columns without schema info.

    Documented as DEFECT-04 (known limitation): mitigation must come from the
    database layer (REVOKE on columns) or schema-aware star expansion.
    These tests pin the *current* behavior so any silent change is detected.
    """

    def test_star_bypasses_column_blacklist(self, restricted_validator: SQLValidator) -> None:
        """SEC-COL-001: known limitation — star expansion hides blocked columns."""
        assert_allowed(restricted_validator, "SELECT * FROM users")

    def test_named_blocked_column_rejected(self, restricted_validator: SQLValidator) -> None:
        """SEC-COL-002: explicit reference to a blocked column is rejected."""
        assert_blocked(restricted_validator, "SELECT password FROM users")

    def test_qualified_blocked_column_rejected(self, restricted_validator: SQLValidator) -> None:
        """SEC-COL-003: qualified reference u.password is rejected too."""
        assert_blocked(restricted_validator, "SELECT u.password FROM users u")
        assert_blocked(restricted_validator, "SELECT users.password FROM users")

    def test_star_in_specific_column_list(self, restricted_validator: SQLValidator) -> None:
        """SEC-COL-004: users.* is also expanded server-side (same limitation)."""
        assert_allowed(restricted_validator, "SELECT users.* FROM users")


# ============================================================================
# Function-call obfuscation
# ============================================================================


class TestFunctionObfuscation:
    """Dangerous functions must be caught regardless of spelling tricks (SEC-FN-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-FN-001", "SELECT pg_sleep(1)"),
            ("SEC-FN-002", "SELECT PG_SLEEP(1)"),
            ("SEC-FN-003", "SELECT Pg_Sleep(1)"),
            ("SEC-FN-004", 'SELECT "pg_sleep"(1)'),
            ("SEC-FN-005", 'SELECT "PG_SLEEP"(1)'),
            ("SEC-FN-006", "SELECT pg_catalog.pg_sleep(1)"),
            ("SEC-FN-007", "SELECT public.pg_sleep(1)"),
            ("SEC-FN-008", "SELECT/*x*/pg_sleep(1)"),
            ("SEC-FN-009", "SELECT pg_sleep/**/(1)"),
            ("SEC-FN-010", "SELECT  pg_sleep (1)"),
            ("SEC-FN-011", "SELECT 1 WHERE EXISTS (SELECT pg_sleep(1))"),
            ("SEC-FN-012", "SELECT * FROM users ORDER BY pg_sleep(1)"),
            ("SEC-FN-013", "WITH t AS (SELECT pg_sleep(1)) SELECT * FROM t"),
            ("SEC-FN-014", "SELECT CASE WHEN pg_sleep(1) IS NULL THEN 1 ELSE 2 END"),
            ("SEC-FN-015", "SELECT lo_export(1, '/tmp/x')"),
            ("SEC-FN-016", "SELECT dblink('dbname=other', 'SELECT 1')"),
            ("SEC-FN-017", "SELECT pg_read_file('/etc/passwd')"),
            ("SEC-FN-018", "SELECT pg_terminate_backend(123)"),
        ],
    )
    def test_dangerous_function_blocked(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(validator, sql, expect_keyword="blocked")

    def test_custom_blocked_function_case_insensitive(self) -> None:
        """SEC-FN-019: config-provided blocked list is matched case-insensitively."""
        validator = SQLValidator(SecurityConfig(blocked_functions=["MY_EVIL_FUNC"]))
        assert_blocked(validator, "SELECT my_evil_func()")
        assert_blocked(validator, "SELECT My_Evil_Func()")

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-FN-101", "SELECT count(*) FROM users"),
            ("SEC-FN-102", "SELECT lower(name), upper(email) FROM users"),
            ("SEC-FN-103", "SELECT coalesce(nickname, name) FROM users"),
            ("SEC-FN-104", "SELECT now(), current_date"),
            ("SEC-FN-105", "SELECT string_agg(tag, ',' ORDER BY tag) FROM tags"),
        ],
    )
    def test_safe_functions_allowed(self, validator: SQLValidator, case_id: str, sql: str) -> None:
        assert_allowed(validator, sql)


# ============================================================================
# Statement smuggling (unsupported syntax falls back to Command/other nodes)
# ============================================================================


class TestStatementSmuggling:
    """Non-SELECT statements must never reach the database (SEC-SMUG-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-SMUG-001", "PREPARE p AS INSERT INTO users VALUES (1)"),
            ("SEC-SMUG-002", "EXECUTE p"),
            ("SEC-SMUG-003", "CALL some_proc()"),
            ("SEC-SMUG-004", "DO $$ BEGIN DELETE FROM users; END $$;"),
            ("SEC-SMUG-005", "VACUUM users"),
            ("SEC-SMUG-006", "SET statement_timeout = 0"),
            ("SEC-SMUG-007", "BEGIN"),
            ("SEC-SMUG-008", "COMMIT"),
            ("SEC-SMUG-009", "FETCH ALL IN c"),
            ("SEC-SMUG-010", "CLOSE c"),
            ("SEC-SMUG-011", "DECLARE c CURSOR FOR SELECT 1"),
            ("SEC-SMUG-012", "CREATE TABLE t AS SELECT 1"),
            ("SEC-SMUG-013", "TRUNCATE users"),
            ("SEC-SMUG-014", "REINDEX TABLE users"),
            ("SEC-SMUG-015", "CHECKPOINT"),
            ("SEC-SMUG-016", "CLUSTER users"),
            ("SEC-SMUG-017", "COMMENT ON TABLE users IS 'x'"),
            ("SEC-SMUG-018", "LISTEN channel"),
            ("SEC-SMUG-019", "NOTIFY channel"),
            ("SEC-SMUG-020", "INSERT INTO users (id) VALUES (1)"),
            ("SEC-SMUG-021", "UPDATE users SET name = 'x'"),
            ("SEC-SMUG-022", "DELETE FROM users"),
            ("SEC-SMUG-023", "DROP TABLE users"),
            ("SEC-SMUG-024", "ALTER TABLE users ADD COLUMN x int"),
            ("SEC-SMUG-025", "GRANT ALL ON users TO PUBLIC"),
            ("SEC-SMUG-026", "REVOKE ALL ON users FROM PUBLIC"),
            (
                "SEC-SMUG-027",
                "MERGE INTO users USING (VALUES (1)) s ON true WHEN MATCHED THEN DO NOTHING",
            ),
        ],
    )
    def test_non_select_blocked(self, validator: SQLValidator, case_id: str, sql: str) -> None:
        assert_blocked(validator, sql)


# ============================================================================
# Multi-statement & injection payloads
# ============================================================================


class TestMultiStatementAndInjection:
    """Stacked queries and classic injection payloads (SEC-MS-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-MS-001", "SELECT 1; DROP TABLE users"),
            ("SEC-MS-002", "SELECT 1; DELETE FROM users;"),
            ("SEC-MS-003", "SELECT 1; INSERT INTO users VALUES (1)"),
            ("SEC-MS-004", ";;;"),
            ("SEC-MS-005", "SELECT 1;;SELECT 2"),
        ],
    )
    def test_stacked_queries_blocked(self, validator: SQLValidator, case_id: str, sql: str) -> None:
        assert_blocked(validator, sql)

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            # Trailing comment after a complete statement: single statement, benign
            ("SEC-MS-101", "SELECT 1 --; DROP TABLE users"),
            ("SEC-MS-102", "SELECT 1 /* ; */"),
            ("SEC-MS-103", "SELECT 1;"),
            ("SEC-MS-104", "  \t\n SELECT 1 \n"),
        ],
    )
    def test_comment_tricks_safe_forms_allowed(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_allowed(validator, sql)


# ============================================================================
# Table / column access controls
# ============================================================================


class TestAccessControls:
    """Blocked-table and blocked-column enforcement (SEC-TBL-* / SEC-COL-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-TBL-001", "SELECT * FROM secrets"),
            ("SEC-TBL-002", "SELECT * FROM SECRETS"),
            ("SEC-TBL-003", 'SELECT * FROM "secrets"'),
            ("SEC-TBL-004", "SELECT * FROM public.secrets"),
            ("SEC-TBL-005", "SELECT * FROM users JOIN secrets ON true"),
            ("SEC-TBL-006", "SELECT * FROM (SELECT * FROM secrets) s"),
            ("SEC-TBL-007", "SELECT * FROM secrets s1 JOIN secrets s2 ON s1.id = s2.id"),
            ("SEC-TBL-008", "WITH t AS (SELECT * FROM secrets) SELECT * FROM t"),
            ("SEC-TBL-009", "SELECT * FROM audit_log"),
            ("SEC-TBL-010", "SELECT * FROM user_credentials"),
        ],
    )
    def test_blocked_tables_rejected(
        self, restricted_validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(restricted_validator, sql, expect_keyword="not allowed")

    def test_unblocked_table_allowed(self, restricted_validator: SQLValidator) -> None:
        """SEC-TBL-101: tables outside the blacklist pass through."""
        assert_allowed(restricted_validator, "SELECT id, name FROM users")

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-COL-011", "SELECT credit_card FROM payments"),
            ("SEC-COL-012", "SELECT password FROM users"),
            ("SEC-COL-013", "SELECT PASSWORD FROM users"),
            ("SEC-COL-014", "SELECT u.password FROM users u"),
            ("SEC-COL-015", "SELECT id FROM users WHERE password = 'x'"),
            ("SEC-COL-016", "SELECT name FROM users ORDER BY password"),
        ],
    )
    def test_blocked_columns_rejected(
        self, restricted_validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(restricted_validator, sql)

    def test_unblocked_column_allowed(self, restricted_validator: SQLValidator) -> None:
        """SEC-COL-101: columns outside the blacklist pass through."""
        assert_allowed(restricted_validator, "SELECT password_hint FROM users")


# ============================================================================
# Parser edge cases & robustness
# ============================================================================


class TestParserEdgeCases:
    """Degenerate inputs must fail cleanly, never crash or pass through (SEC-EDGE-*)."""

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-EDGE-001", ""),
            ("SEC-EDGE-002", "   "),
            ("SEC-EDGE-003", "-- only a comment"),
            ("SEC-EDGE-004", "/* block comment */"),
            ("SEC-EDGE-006", "SELECT FROM"),
            ("SEC-EDGE-007", "SELECRT 1"),
            ("SEC-EDGE-008", "))((**"),
        ],
    )
    def test_degenerate_inputs_rejected(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_blocked(validator, sql)

    def test_bare_select_lenient_parse(self, validator: SQLValidator) -> None:
        """SEC-EDGE-005: bare SELECT passes sqlglot's lenient parse.

        Not a security hole (PostgreSQL itself rejects the statement), but the
        leniency is pinned here so a parser upgrade that changes behavior is
        noticed.
        """
        is_valid, error = validator.validate("SELECT")
        assert is_valid
        assert error is None

    def test_null_byte_rejected(self, validator: SQLValidator) -> None:
        """SEC-EDGE-009: NUL byte must not crash the validator (hardened: rejected)."""
        is_valid, error = validator.validate("SELECT 1\x00")
        assert not is_valid
        assert error

    def test_large_input_handled(self, validator: SQLValidator) -> None:
        """SEC-EDGE-010: a 1 MB query must return a verdict, not hang or crash."""
        big = "SELECT " + "1," * 100_000 + "1"
        is_valid, error = validator.validate(big)
        assert is_valid  # huge but harmless projection list
        assert error is None

    @pytest.mark.parametrize(
        ("case_id", "sql"),
        [
            ("SEC-EDGE-101", "SELECT U&'\\0041'"),
            ("SEC-EDGE-102", "SELECT $tag$body$tag$"),
            ("SEC-EDGE-103", "SELECT E'\\x41'"),
            ("SEC-EDGE-104", "SELECT '中文' AS label"),
        ],
    )
    def test_exotic_string_syntax_allowed(
        self, validator: SQLValidator, case_id: str, sql: str
    ) -> None:
        assert_allowed(validator, sql)
