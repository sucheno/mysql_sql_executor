# mysql_sql_executor

Secure, read-only MySQL query executor. Accepts only `SELECT` statements and blocks all DML/DDL/DCL operations to prevent accidental or malicious data modification.

---

## Directory layout

```
mysql_sql_executor/
├── mysql_sql_executor.py   # Main executor script
├── .env                    # Database credentials (never commit this)
├── mysql_sql_executor.log  # Runtime log (auto-created on first run)
└── README.md               # This file
```

---

## Prerequisites

- Python 3.10+
- Virtual environment activated (`.venv` in the workspace root)

Install required packages:

```bash
pip install mysql-connector-python python-dotenv
```

---

## Credentials — `.env`

The `.env` file must exist in the **same directory as the script** (`mysql_sql_executor/.env`).

```dotenv
MYSQL_HOST=<hostname or IP>
MYSQL_PORT=3306
MYSQL_USER=<username>
MYSQL_PASSWORD=<password>
MYSQL_DATABASE=<database name>
```

> **Security:** `.env` is never auto-committed. Add it to `.gitignore`.  
> If `.env` is missing at runtime, the script creates a blank template and exits with instructions.

---

## Usage

Run all commands from the **workspace root** (`hana_team_hurricane_tools/`).

### Inline query

```bash
python mysql_sql_executor/mysql_sql_executor.py "SELECT * FROM users LIMIT 10"
```

### Query from a `.sql` file

```bash
python mysql_sql_executor/mysql_sql_executor.py --file path/to/query.sql
```

### Choose output format

```bash
# table (default)
python mysql_sql_executor/mysql_sql_executor.py --file query.sql --format table

# JSON
python mysql_sql_executor/mysql_sql_executor.py --file query.sql --format json

# CSV
python mysql_sql_executor/mysql_sql_executor.py --file query.sql --format csv
```

### Limit rows returned (default: 1000)

```bash
python mysql_sql_executor/mysql_sql_executor.py "SELECT * FROM orders" --max-rows 50
```

### Validate a query without executing it

```bash
python mysql_sql_executor/mysql_sql_executor.py --validate-only "SELECT id FROM users"
```

Expected output on success:
```
✅ Query validation passed
```

### Interactive mode

```bash
python mysql_sql_executor/mysql_sql_executor.py --interactive
```

Prompt: `SQL>` — type `help` for available commands, `exit` or `quit` to leave.

---

## Security features

| Check | Description |
|---|---|
| SELECT-only | Query must start with `SELECT` and contain a `FROM` clause |
| Dangerous keyword detection | Blocks `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`, `EXEC`, `CALL`, `GRANT`, `LOAD`, `INTO`, etc. |
| Comment stripping | Removes `--`, `/* */`, and `#` comments before validation |
| Stacked statement detection | Rejects queries with more than one `;` or a `;` mid-query |
| Parenthesis balance | Rejects queries with mismatched `(` / `)` |
| Query length limit | Rejects queries longer than 10 000 characters |
| Row cap | Appends `LIMIT <max-rows>` automatically if not already present |
| TLS | `ssl_disabled=False` — always attempts TLS when connecting to MySQL |

---

## Output formats

### `table` (default)

```
TABLE_NAME   | TABLE_ROWS
--------------------------
users        | 4
orders       | 1068
```

### `json`

```json
[
  {"TABLE_NAME": "users", "TABLE_ROWS": 4},
  {"TABLE_NAME": "orders", "TABLE_ROWS": 1068}
]
```

### `csv`

```
TABLE_NAME,TABLE_ROWS
users,4
orders,1068
```

---

## Logging

All activity is appended to `mysql_sql_executor/mysql_sql_executor.log`.  
Log entries include timestamps, log level, connection events, query text (first 120 chars), row counts, and errors.

---

## Error reference

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation failure, connection error, or query execution error |

| Message | Cause |
|---|---|
| `❌ Credentials file not found: .env` | `.env` is missing — a blank template is created |
| `❌ Access denied` | Wrong `MYSQL_USER` or `MYSQL_PASSWORD` |
| `❌ Database '...' does not exist` | Wrong `MYSQL_DATABASE` value |
| `❌ Query validation failed: Invalid SQL structure` | Query is not a `SELECT … FROM …` statement |
| `❌ Query validation failed: Query contains dangerous keywords` | A blocked keyword was found in the query |
| `❌ Query validation failed: Multiple statements detected` | More than one `;` detected (stacked query attempt) |

---

## AI agent usage notes

- **Script path (relative to workspace root):** `mysql_sql_executor/mysql_sql_executor.py`
- **Credentials path:** `mysql_sql_executor/.env`
- **Log path:** `mysql_sql_executor/mysql_sql_executor.log`
- **Python executable:** use the venv: `<workspace_root>/.venv/Scripts/python.exe` (Windows) or `<workspace_root>/.venv/bin/python` (Linux/macOS)
- **Only `SELECT` queries are accepted.** Do not attempt `INSERT`, `UPDATE`, `DELETE`, or any DDL.
- **Queries must include a `FROM` clause.** `SELECT 1` without `FROM` will be rejected.
- **Row limit is enforced automatically.** Pass `--max-rows` to override (max meaningful value depends on available memory).
- **To list all tables in the connected database:**
  ```sql
  SELECT TABLE_NAME, TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'testdb'
  ```
- **Return values:** `QueryResult` dataclass with `.columns` (list of str), `.rows` (list of lists), `.row_count` (int), `.execution_time` (float seconds).
