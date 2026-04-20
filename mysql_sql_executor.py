#!/usr/bin/env python3
"""
MySQL SQL Executor - Secure SELECT Query Executor
=================================================

This script provides a secure way to execute SELECT queries against a MySQL database.
(Intentionally limited only to SELECT queries to prevent any data modification risks.)
It includes comprehensive validation checks to ensure that only safe and well-formed
queries are executed, including SQL injection protection.

Credentials are loaded from a .env file located in the same directory as this script.

Author: Suchen Oguri
Date: 2025-08-13
"""

import sys
import os
import re
import json
import argparse
import logging
from typing import Optional, List, Any
from dataclasses import dataclass

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import mysql.connector
    import mysql.connector.errorcode as errorcode
except ImportError:
    print("Error: mysql-connector-python package not installed. Please run: pip install mysql-connector-python")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("Error: python-dotenv package not installed. Please run: pip install python-dotenv")
    sys.exit(1)

# Configure logging — log file is always placed next to this script
_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mysql_sql_executor.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_LOG_FILE)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Data class to hold query results"""
    columns: List[str]
    rows: List[List[Any]]
    row_count: int
    execution_time: float


class MySQLExecutor:
    """Secure MySQL SQL Executor for SELECT queries only"""

    # Dangerous keywords that must never appear in SELECT queries
    DANGEROUS_KEYWORDS = {
        'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
        'MERGE', 'UPSERT', 'GRANT', 'REVOKE', 'COMMIT', 'ROLLBACK',
        'EXEC', 'EXECUTE', 'CALL', 'DECLARE', 'SET', 'USE',
        'LOAD', 'OUTFILE', 'DUMPFILE', 'INTO'
    }

    # SQL comment patterns that could be used for injection
    COMMENT_PATTERNS = [
        r'--.*$',           # Single-line comments
        r'/\*.*?\*/',       # Multi-line comments
        r'#.*$',            # MySQL-style single-line comments
    ]

    MAX_QUERY_LENGTH = 10000  # 10 KB

    def __init__(self):
        self.connection = None
        self.cursor = None

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _remove_comments(self, sql: str) -> str:
        """Strip SQL comments to prevent comment-based injection."""
        cleaned = sql
        for pattern in self.COMMENT_PATTERNS:
            cleaned = re.sub(pattern, '', cleaned, flags=re.MULTILINE | re.DOTALL)
        return cleaned

    def _validate_query_length(self, sql: str) -> bool:
        if len(sql) > self.MAX_QUERY_LENGTH:
            logger.error(f"Query too long: {len(sql)} characters (max: {self.MAX_QUERY_LENGTH})")
            return False
        return True

    def _validate_sql_structure(self, sql: str) -> bool:
        """Ensure query is a SELECT statement with a FROM clause."""
        normalized = ' '.join(sql.strip().split())
        if not normalized.upper().startswith('SELECT'):
            logger.warning("Query does not start with SELECT")
            return False
        if not re.match(r'^\s*SELECT\s+.+\s+FROM\s+', sql, re.IGNORECASE | re.DOTALL):
            logger.warning("Invalid SELECT query structure — missing FROM clause")
            return False
        return True

    def _check_dangerous_keywords(self, sql: str) -> bool:
        """Reject any query containing DML/DDL/DCL keywords."""
        sql_upper = sql.upper()
        for keyword in self.DANGEROUS_KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', sql_upper):
                logger.error(f"Dangerous keyword detected: {keyword}")
                return False
        return True

    def _check_semicolons(self, sql: str) -> bool:
        """Allow at most one trailing semicolon (no stacked statements)."""
        stripped = re.sub(r"'[^']*'", '', sql)
        stripped = re.sub(r'"[^"]*"', '', stripped)
        count = stripped.count(';')
        if count > 1:
            logger.error("Multiple statements detected (possible SQL injection)")
            return False
        if count == 1 and not sql.strip().endswith(';'):
            logger.error("Semicolon found in middle of query (possible SQL injection)")
            return False
        return True

    def _validate_parentheses_balance(self, sql: str) -> bool:
        """Check that all parentheses are properly balanced."""
        stripped = re.sub(r"'[^']*'", '', sql)
        stripped = re.sub(r'"[^"]*"', '', stripped)
        if stripped.count('(') != stripped.count(')'):
            logger.error("Unbalanced parentheses detected")
            return False
        return True

    def validate_query(self, sql: str) -> tuple[bool, str]:
        """
        Run all security and structural checks on a query.

        Returns:
            (True, 'Query is valid') on success, or (False, <reason>) on failure.
        """
        if not sql or not sql.strip():
            return False, "Empty query provided"

        if not self._validate_query_length(sql):
            return False, "Query exceeds maximum length limit"

        cleaned = self._remove_comments(sql)

        if not self._validate_sql_structure(cleaned):
            return False, "Invalid SQL structure — must be a SELECT … FROM … query"

        if not self._check_dangerous_keywords(cleaned):
            return False, "Query contains dangerous keywords"

        if not self._check_semicolons(cleaned):
            return False, "Multiple statements detected (possible SQL injection)"

        if not self._validate_parentheses_balance(cleaned):
            return False, "Unbalanced parentheses in query"

        logger.info("Query validation passed")
        return True, "Query is valid"

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Load credentials from .env and establish a MySQL connection.

        Returns:
            True on success, False otherwise.
        """
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

        if not os.path.exists(env_file):
            template = (
                "# MySQL connection credentials\n"
                "# WARNING: Do NOT commit this file to source control.\n"
                "MYSQL_HOST=\n"
                "MYSQL_PORT=3306\n"
                "MYSQL_USER=\n"
                "MYSQL_PASSWORD=\n"
                "MYSQL_DATABASE=\n"
            )
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write(template)
            logger.error(".env not found — template created at: %s", env_file)
            print(f"\n❌ Credentials file not found: .env")
            print(f"   A template has been created at: {env_file}")
            print("   Please fill in MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE")
            print("   Then re-run the script.\n")
            return False

        load_dotenv(env_file, override=True)

        host = os.getenv('MYSQL_HOST')
        port_str = os.getenv('MYSQL_PORT', '3306')
        user = os.getenv('MYSQL_USER')
        password = os.getenv('MYSQL_PASSWORD')
        database = os.getenv('MYSQL_DATABASE')

        missing = [k for k, v in {'MYSQL_HOST': host, 'MYSQL_USER': user,
                                   'MYSQL_PASSWORD': password, 'MYSQL_DATABASE': database}.items() if not v]
        if missing:
            for key in missing:
                logger.error("%s not set in .env", key)
                print(f"Error: {key} is required in .env")
            return False

        try:
            port = int(port_str)
        except ValueError:
            logger.error("Invalid MYSQL_PORT value: %s", port_str)
            print(f"Error: Invalid MYSQL_PORT value: {port_str}")
            return False

        try:
            self.connection = mysql.connector.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database,
                ssl_disabled=False,          # Always attempt TLS for RDS
                connection_timeout=30,
            )
            self.cursor = self.connection.cursor()
            logger.info("Connected to MySQL database '%s' at %s:%s", database, host, port)
            return True

        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                logger.error("Access denied — check MYSQL_USER / MYSQL_PASSWORD")
                print("❌ Access denied: invalid username or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                logger.error("Database '%s' does not exist", database)
                print(f"❌ Database '{database}' does not exist")
            else:
                logger.error("Connection failed: %s", err)
                print(f"❌ Connection failed: {err}")
            return False

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def _add_row_limit(self, sql: str, max_rows: int) -> str:
        """Append a LIMIT clause if none is present."""
        if 'LIMIT' in sql.upper():
            return sql
        return f"{sql.rstrip(';')} LIMIT {max_rows}"

    def execute_query(self, sql: str, max_rows: int = 1000) -> Optional[QueryResult]:
        """
        Validate and execute a SELECT query.

        Args:
            sql:      SQL SELECT statement.
            max_rows: Maximum rows to fetch (default 1000).

        Returns:
            QueryResult on success, None on failure.
        """
        import time

        is_valid, error_msg = self.validate_query(sql)
        if not is_valid:
            logger.error("Query validation failed: %s", error_msg)
            print(f"❌ Query validation failed: {error_msg}")
            return None

        if not self.connection or not self.cursor:
            logger.error("No database connection available")
            print("❌ Not connected to database")
            return None

        try:
            limited_sql = self._add_row_limit(sql, max_rows)
            logger.info("Executing: %s …", limited_sql[:120])

            start = time.time()
            self.cursor.execute(limited_sql)
            raw_rows = self.cursor.fetchall()
            elapsed = time.time() - start

            columns = [desc[0] for desc in self.cursor.description]
            rows = [list(row) for row in raw_rows]

            result = QueryResult(
                columns=columns,
                rows=rows,
                row_count=len(rows),
                execution_time=elapsed,
            )
            logger.info("Query returned %d rows in %.2fs", result.row_count, elapsed)
            return result

        except mysql.connector.Error as err:
            logger.error("Query execution failed: %s", err)
            print(f"❌ Query execution failed: {err}")
            return None

    # ------------------------------------------------------------------
    # Result display
    # ------------------------------------------------------------------

    def display_results(self, result: QueryResult, format_type: str = 'table') -> None:
        if not result or result.row_count == 0:
            print("No results found.")
            return

        print(f"\n{'='*60}")
        print(f"Query Results: {result.row_count} rows ({result.execution_time:.2f}s)")
        print(f"{'='*60}")

        if format_type == 'json':
            self._display_json(result)
        elif format_type == 'csv':
            self._display_csv(result)
        else:
            self._display_table(result)

    def _display_table(self, result: QueryResult) -> None:
        col_widths = []
        for i, col in enumerate(result.columns):
            max_w = len(str(col))
            for row in result.rows:
                if i < len(row):
                    max_w = max(max_w, len(str(row[i])))
            col_widths.append(min(max_w, 50))

        header = " | ".join(col.ljust(col_widths[i]) for i, col in enumerate(result.columns))
        print(header)
        print("-" * len(header))
        for row in result.rows:
            print(" | ".join(
                str(row[i] if i < len(row) else "").ljust(col_widths[i])[:col_widths[i]]
                for i in range(len(result.columns))
            ))

    def _display_json(self, result: QueryResult) -> None:
        data = [
            {col: (row[i] if i < len(row) else None) for i, col in enumerate(result.columns)}
            for row in result.rows
        ]
        print(json.dumps(data, indent=2, default=str))

    def _display_csv(self, result: QueryResult) -> None:
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(result.columns)
        for row in result.rows:
            writer.writerow(row)
        print(buf.getvalue())
        buf.close()

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def disconnect(self) -> None:
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection and self.connection.is_connected():
                self.connection.close()
            logger.info("Database connection closed")
        except mysql.connector.Error as err:
            logger.error("Error closing connection: %s", err)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="MySQL SQL Executor — Secure SELECT Query Tool",
        epilog=(
            "Examples:\n"
            '  python mysql_sql_executor.py "SELECT * FROM users LIMIT 10"\n'
            "  python mysql_sql_executor.py --file query.sql --format json\n"
            "  python mysql_sql_executor.py --interactive\n"
            "  python mysql_sql_executor.py --validate-only --file query.sql"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("query", nargs="?", help="SQL SELECT query to execute")
    group.add_argument("-f", "--file", help="File containing SQL query")
    group.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")

    parser.add_argument("--format", choices=["table", "json", "csv"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("--max-rows", type=int, default=1000,
                        help="Maximum rows to fetch (default: 1000)")
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate query without executing")

    args = parser.parse_args()
    executor = MySQLExecutor()
    sql = None

    try:
        if args.query:
            sql = args.query
        elif args.file:
            try:
                with open(args.file, 'r', encoding='utf-8') as fh:
                    sql = fh.read()
            except FileNotFoundError:
                print(f"Error: File '{args.file}' not found")
                return 1
            except OSError as err:
                print(f"Error reading file: {err}")
                return 1
        elif args.interactive:
            return _interactive_mode(executor, args)

        if sql is None:
            print("Error: No query provided")
            return 1

        is_valid, error_msg = executor.validate_query(sql)
        if not is_valid:
            print(f"❌ Query validation failed: {error_msg}")
            return 1

        print("✅ Query validation passed")

        if args.validate_only:
            return 0

        if not executor.connect():
            print("❌ Failed to connect to database")
            return 1

        result = executor.execute_query(sql, args.max_rows)
        if result:
            executor.display_results(result, args.format)
        else:
            print("❌ Query execution failed")
            return 1

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        return 1
    except Exception as err:  # pylint: disable=broad-except
        logger.error("Unexpected error: %s", err)
        print(f"❌ Unexpected error: {err}")
        return 1
    finally:
        executor.disconnect()

    return 0


def _interactive_mode(executor: MySQLExecutor, args) -> int:
    print("🔧 MySQL SQL Executor — Interactive Mode")
    print("Type 'exit' or 'quit' to leave, 'help' for commands")
    print("-" * 50)

    if not executor.connect():
        print("❌ Failed to connect to database")
        return 1

    while True:
        try:
            query = input("\nSQL> ").strip()
            if query.lower() in ('exit', 'quit'):
                break
            if query.lower() == 'help':
                _print_help()
                continue
            if not query:
                continue

            is_valid, error_msg = executor.validate_query(query)
            if not is_valid:
                print(f"❌ {error_msg}")
                continue

            result = executor.execute_query(query, args.max_rows)
            if result:
                executor.display_results(result, args.format)
            else:
                print("❌ Query execution failed")

        except KeyboardInterrupt:
            print("\n⚠️  Use 'exit' to quit")
        except EOFError:
            break
        except Exception as err:  # pylint: disable=broad-except
            print(f"❌ Error: {err}")

    return 0


def _print_help() -> None:
    print("""
Available commands:
  help    - Show this help message
  exit    - Exit the program
  quit    - Exit the program

Security features:
  ✓ Only SELECT queries allowed
  ✓ Dangerous keyword detection (INSERT, UPDATE, DELETE, DROP, …)
  ✓ SQL comment stripping
  ✓ Multi-statement / stacked query detection
  ✓ Parenthesis balance check
  ✓ Query length limit (10 KB)
  ✓ Row limit enforcement

Credentials:
  Loaded from .env in the same directory as this script.
  Fields: MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE

Example queries:
  SELECT * FROM users LIMIT 10;
  SELECT COUNT(*) FROM orders WHERE status = 'ACTIVE';
  SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name;
""")


if __name__ == "__main__":
    sys.exit(main())
