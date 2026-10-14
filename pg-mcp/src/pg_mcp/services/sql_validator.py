"""SQL Security Validator using SQLGlot.

This module provides SQL validation and security checking using SQLGlot parser.
It ensures that only safe, read-only queries are executed and blocks potentially
dangerous operations.
"""

from typing import ClassVar

import sqlglot
from sqlglot import exp

from pg_mcp.config.settings import SecurityConfig
from pg_mcp.models.errors import SecurityViolationError, SQLParseError


class SQLValidator:
    """SQL security validator using SQLGlot for parsing and validation.

    This validator ensures queries are safe by:
    - Allowing only SELECT statements
    - Blocking dangerous functions (pg_sleep, file operations, etc.)
    - Preventing access to blocked tables and columns
    - Rejecting multi-statement queries
    - Validating subquery safety
    """

    # Allowed statement types at the top level (including set operations)
    ALLOWED_STATEMENT_TYPES: ClassVar = {
        exp.Select, exp.Union, exp.Intersect, exp.Except
    }

    # Allowed top-level expressions (including CTEs)
    ALLOWED_TOP_LEVEL: ClassVar = {
        exp.Select, exp.Union, exp.Intersect, exp.Except, exp.With, exp.Subquery
    }

    # Forbidden statement types
    FORBIDDEN_STATEMENT_TYPES: ClassVar = {
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Drop,
        exp.Create,
        exp.Alter,
        exp.Grant,
        exp.Revoke,
        exp.Set,
        exp.Command,
        exp.Use,
        exp.Merge,
    }

    # Built-in dangerous PostgreSQL functions
    BUILTIN_DANGEROUS_FUNCTIONS: ClassVar = {
        "pg_sleep",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "dblink_open",
        "pg_write_file",
        "pg_execute_sql",
        "copy_from",
        "copy_to",
    }

    def __init__(
        self,
        config: SecurityConfig,
        blocked_tables: list[str] | None = None,
        blocked_columns: list[str] | None = None,
        allowed_schemas: list[str] | None = None,
        allow_explain: bool = False,
        allow_explain_analyze: bool = False,
    ) -> None:
        """Initialize SQL validator.

        Args:
            config: Security configuration containing blocked functions and settings.
            blocked_tables: Optional list of table names to block access to.
                Defaults to config.blocked_tables when not provided.
            blocked_columns: Optional list of column names to block access to.
                Defaults to config.blocked_columns when not provided.
            allowed_schemas: Optional allow-list of schemas for table access.
                Empty/None means all schemas are permitted. Defaults to
                config.allowed_schemas when not provided.
            allow_explain: Whether to allow EXPLAIN statements.
            allow_explain_analyze: Whether to allow EXPLAIN ANALYZE. WARNING:
                EXPLAIN ANALYZE executes the inner statement, so this should
                only be enabled in trusted environments.
        """
        self.config = config
        self.blocked_tables = {
            t.lower() for t in (blocked_tables if blocked_tables is not None else config.blocked_tables)
        }
        self.blocked_columns = {
            c.lower()
            for c in (blocked_columns if blocked_columns is not None else config.blocked_columns)
        }
        self.allowed_schemas = {
            s.lower() for s in (allowed_schemas if allowed_schemas is not None else config.allowed_schemas)
        }
        self.allow_explain = allow_explain
        self.allow_explain_analyze = allow_explain_analyze

        # Combine built-in dangerous functions with custom blocked functions
        self.blocked_functions = self.BUILTIN_DANGEROUS_FUNCTIONS | {
            f.lower() for f in config.blocked_functions
        }

    def validate(self, sql: str) -> tuple[bool, str | None]:
        """Validate SQL query for security compliance.

        Args:
            sql: SQL query string to validate.

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is None.
        """
        try:
            self.validate_or_raise(sql)
            return (True, None)
        except (SecurityViolationError, SQLParseError) as e:
            return (False, str(e))

    def validate_or_raise(self, sql: str) -> None:
        """Validate SQL query and raise exception on violation.

        Args:
            sql: SQL query string to validate.

        Raises:
            SQLParseError: If SQL cannot be parsed.
            SecurityViolationError: If SQL violates security constraints.
        """
        # Check for empty or whitespace-only SQL
        if not sql or not sql.strip():
            raise SQLParseError("SQL query cannot be empty")

        # Reject embedded NUL bytes: they are never valid in SQL text and some
        # downstream layers may truncate input at NUL. Fail closed.
        if "\x00" in sql:
            raise SQLParseError("SQL query contains invalid NUL byte")

        # Parse SQL using SQLGlot
        try:
            parsed = sqlglot.parse(sql, read="postgres")
        except Exception as e:
            raise SQLParseError(f"Failed to parse SQL: {e}") from e

        # Check for multiple statements
        if len(parsed) > 1:
            raise SecurityViolationError(
                "Multiple statements not allowed. Only single SELECT queries are permitted."
            )

        if not parsed:
            raise SQLParseError("No valid SQL statement found")

        statement = parsed[0]

        # Check for null or empty statement (e.g., comment-only SQL)
        if statement is None or isinstance(statement, type(None)):
            raise SQLParseError("No valid SQL statement found")

        # Handle EXPLAIN statements (parsed as Command in sqlglot 28.5.0)
        if isinstance(statement, exp.Command):
            # Check if it's an EXPLAIN command
            cmd_name = str(statement.this).upper() if statement.this else ""
            if cmd_name == "EXPLAIN":
                if not self.allow_explain:
                    raise SecurityViolationError("EXPLAIN statements are not allowed")
                # Reject EXPLAIN ANALYZE: it *executes* the inner statement
                # (e.g. "EXPLAIN ANALYZE DELETE FROM users" really deletes rows).
                # The inner SQL is kept raw in `expression` because sqlglot 28.5.0
                # cannot parse EXPLAIN syntax reliably (falls back to Command).
                # Note: fail-closed — a string literal containing the word ANALYZE
                # is also rejected (safe over-rejection).
                explain_tail = str(statement.expression or "").upper()
                if "ANALYZE" in explain_tail and not self.allow_explain_analyze:
                    raise SecurityViolationError(
                        "EXPLAIN ANALYZE is not allowed because it executes the "
                        "inner statement. Use plain EXPLAIN instead."
                    )
                # Plain EXPLAIN only produces a query plan without executing.
                # Even "EXPLAIN DELETE" is safe as it won't actually delete data.
                return None
            else:
                # Other commands are not allowed
                raise SecurityViolationError(
                    f"Command '{cmd_name}' is not allowed. Only SELECT queries are permitted."
                )

        # Reject forbidden statements anywhere in the syntax tree. This covers
        # data-modifying CTEs (e.g. "WITH d AS (DELETE FROM users RETURNING *)
        # SELECT * FROM d"), which are valid PostgreSQL and would otherwise slip
        # past the top-level statement-type check.
        if error := self._check_tree_for_forbidden(statement):
            raise SecurityViolationError(error)

        # Handle CTE (WITH) statements - extract the main query
        if isinstance(statement, exp.With):
            # WITH statements are allowed, but we need to validate the main query
            if statement.this:
                main_query = statement.this
            else:
                raise SQLParseError("WITH statement has no main query")
        else:
            main_query = statement

        # Perform security checks
        if error := self._check_statement_type(main_query):
            raise SecurityViolationError(error)

        if error := self._check_dangerous_functions(statement):
            raise SecurityViolationError(error)

        if error := self._check_blocked_tables(statement):
            raise SecurityViolationError(error)

        if error := self._check_allowed_schemas(statement):
            raise SecurityViolationError(error)

        if error := self._check_blocked_columns(statement):
            raise SecurityViolationError(error)

        if error := self._check_subquery_safety(statement):
            raise SecurityViolationError(error)

    def _check_statement_type(self, statement: exp.Expression) -> str | None:
        """Check if statement type is allowed.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        # Check for forbidden statement types
        for forbidden_type in self.FORBIDDEN_STATEMENT_TYPES:
            if isinstance(statement, forbidden_type):
                stmt_name = forbidden_type.__name__.upper()
                return f"{stmt_name} statements are not allowed. Only SELECT queries are permitted."

        # Ensure statement is an allowed type (SELECT or set operations)
        if not isinstance(statement, tuple(self.ALLOWED_STATEMENT_TYPES)):
            stmt_type = type(statement).__name__
            return f"Statement type {stmt_type} is not allowed. Only SELECT queries are permitted."

        # Reject SELECT INTO: it creates a new table (e.g. "SELECT * INTO tmp FROM users")
        if isinstance(statement, exp.Select) and statement.args.get("into") is not None:
            return (
                "SELECT INTO is not allowed because it creates tables. "
                "Only read-only SELECT queries are permitted."
            )

        return None

    def _check_tree_for_forbidden(self, statement: exp.Expression) -> str | None:
        """Check for forbidden statement types anywhere in the syntax tree.

        The top-level type check only inspects the root node, so write
        operations hidden inside CTEs (WITH ... AS (DELETE ...)) or nested
        expressions would be missed. This check walks every node.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if a forbidden statement is found, None otherwise.
        """
        for node in statement.walk():
            for forbidden_type in self.FORBIDDEN_STATEMENT_TYPES:
                if isinstance(node, forbidden_type):
                    stmt_name = forbidden_type.__name__.upper()
                    return (
                        f"{stmt_name} statements are not allowed. "
                        "Only read-only SELECT queries are permitted."
                    )
        return None

    def _check_dangerous_functions(self, statement: exp.Expression) -> str | None:
        """Check for use of blocked/dangerous functions.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        # Find all function calls in the query
        for func in statement.find_all(exp.Func):
            func_name = func.name.lower() if func.name else ""

            if func_name in self.blocked_functions:
                return f"Function '{func_name}' is blocked for security reasons"

        return None

    def _check_blocked_tables(self, statement: exp.Expression) -> str | None:
        """Check for access to blocked tables.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        if not self.blocked_tables:
            return None

        # Find all table references
        for table in statement.find_all(exp.Table):
            table_name = table.name.lower() if table.name else ""

            if table_name in self.blocked_tables:
                return f"Access to table '{table_name}' is not allowed"

        return None

    def _check_allowed_schemas(self, statement: exp.Expression) -> str | None:
        """Check that qualified table references stay within allowed schemas.

        Unqualified table names resolve through search_path (locked to
        safe_search_path at execution time) and are always permitted here.
        When allowed_schemas is empty, all schemas are permitted.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        if not self.allowed_schemas:
            return None

        for table in statement.find_all(exp.Table):
            schema = (table.db or "").lower()
            if schema and schema not in self.allowed_schemas:
                return f"Access to schema '{schema}' is not allowed"

        return None

    def _check_blocked_columns(self, statement: exp.Expression) -> str | None:
        """Check for access to blocked columns.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        if not self.blocked_columns:
            return None

        # Find all column references
        for column in statement.find_all(exp.Column):
            column_name = column.name.lower() if column.name else ""

            # Check for exact match
            if column_name in self.blocked_columns:
                return f"Access to column '{column_name}' is not allowed"

            # Check for qualified column names (table.column)
            if column.table:
                qualified_name = f"{column.table.lower()}.{column_name}"
                if qualified_name in self.blocked_columns:
                    return f"Access to column '{qualified_name}' is not allowed"

        return None

    def _check_subquery_safety(self, statement: exp.Expression) -> str | None:
        """Check that all subqueries only contain SELECT statements.

        Args:
            statement: Parsed SQL statement.

        Returns:
            Error message if check fails, None otherwise.
        """
        # Find all subqueries
        for subquery in statement.find_all(exp.Subquery):
            if subquery.this:
                inner_stmt = subquery.this

                # Check if the inner statement is a forbidden type
                for forbidden_type in self.FORBIDDEN_STATEMENT_TYPES:
                    if isinstance(inner_stmt, forbidden_type):
                        stmt_name = forbidden_type.__name__.upper()
                        return f"{stmt_name} statements in subqueries are not allowed"

                # Ensure it's a SELECT
                if not isinstance(inner_stmt, (exp.Select, exp.With)):
                    return "Subqueries must contain only SELECT statements"

        return None

    def normalize_sql(self, sql: str) -> str:
        """Normalize SQL query to a canonical form.

        This removes extra whitespace, standardizes formatting, and makes
        queries easier to compare or cache.

        Args:
            sql: SQL query string to normalize.

        Returns:
            Normalized SQL string.

        Raises:
            SQLParseError: If SQL cannot be parsed.
        """
        try:
            parsed = sqlglot.parse_one(sql, read="postgres")
            # Generate normalized SQL
            return parsed.sql(dialect="postgres", pretty=False)
        except Exception as e:
            raise SQLParseError(f"Failed to normalize SQL: {e}") from e

    def extract_tables(self, sql: str) -> list[str]:
        """Extract all table names referenced in the SQL query.

        Args:
            sql: SQL query string.

        Returns:
            List of table names (in lowercase).

        Raises:
            SQLParseError: If SQL cannot be parsed.
        """
        try:
            parsed = sqlglot.parse_one(sql, read="postgres")
            tables = []

            for table in parsed.find_all(exp.Table):
                if table.name:
                    tables.append(table.name.lower())

            return sorted(set(tables))
        except Exception as e:
            raise SQLParseError(f"Failed to extract tables: {e}") from e
