import re
import mysql.connector
from config import DATABASE_CONFIG
import json
from decimal import Decimal
import os
import sqlparse
from difflib import get_close_matches
import traceback
from cerebras.cloud.sdk import Cerebras

# Set API Key
os.environ["CEREBRAS_API_KEY"] = "csk-thjnkvvhc6kkrfyr5thr8knftctktwnd4de86j5tdwfrxe4j"

# ============================================================
# SAFETY LAYER
# ============================================================

# Dangerous SQL operations that must NEVER be executed
DANGEROUS_SQL_KEYWORDS = [
    "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
    "ALTER", "CREATE", "REPLACE", "RENAME", "EXEC",
    "EXECUTE", "GRANT", "REVOKE", "LOCK", "UNLOCK",
    "CALL", "LOAD", "OUTFILE", "DUMPFILE", "INTO"
]

# Suspicious patterns in natural language input that suggest malicious intent.
# Each entry is a (pattern, user_facing_message) tuple.
# Messages always use standard SQL terms (DELETE/INSERT/UPDATE) regardless of user's word.
SUSPICIOUS_INPUT_PATTERNS = [
    # ── DELETE-class: delete, drop, truncate, remove, erase, wipe ────────
    (r"\bdelete\b",   "This tool is read-only. DELETE operations are not allowed."),
    (r"\bdrop\b",     "This tool is read-only. DELETE operations are not allowed."),
    (r"\btruncate\b", "This tool is read-only. DELETE operations are not allowed."),
    (r"\bremove\b",   "This tool is read-only. DELETE operations are not allowed."),
    (r"\berase\b",    "This tool is read-only. DELETE operations are not allowed."),
    (r"\bwipe\b",     "This tool is read-only. DELETE operations are not allowed."),

    # ── INSERT-class: insert, add, create, store, save, put, push, append ─
    (r"\binsert\b",   "This tool is read-only. INSERT operations are not allowed."),
    (r"\badd\b",      "This tool is read-only. INSERT operations are not allowed."),
    (r"\bcreate\b",   "This tool is read-only. INSERT operations are not allowed."),
    (r"\bstore\b",    "This tool is read-only. INSERT operations are not allowed."),
    (r"\bsave\b",     "This tool is read-only. INSERT operations are not allowed."),
    (r"\bput\b",      "This tool is read-only. INSERT operations are not allowed."),
    (r"\bpush\b",     "This tool is read-only. INSERT operations are not allowed."),
    (r"\bappend\b",   "This tool is read-only. INSERT operations are not allowed."),

    # ── UPDATE-class: update, modify, change, set, alter, rename ─────────
    (r"\bupdate\b",   "This tool is read-only. UPDATE operations are not allowed."),
    (r"\bmodify\b",   "This tool is read-only. UPDATE operations are not allowed."),
    (r"\bchange\b",   "This tool is read-only. UPDATE operations are not allowed."),
    (r"\bset\b",      "This tool is read-only. UPDATE operations are not allowed."),
    (r"\balter\b",    "This tool is read-only. UPDATE operations are not allowed."),
    (r"\brename\b",   "This tool is read-only. UPDATE operations are not allowed."),
    # Catches key=value pairs like "Salary = 76000" — strong signal of write intent
    (r"\w+\s*=\s*\S+", "This tool is read-only. UPDATE operations are not allowed."),

    # ── SQL injection / obfuscation tricks ───────────────────────────────
    (r";\s*(drop|delete|update|insert|truncate|alter)",
                             "Query contains potentially harmful content and has been blocked."),
    (r"\/\*.*?\*\/",         "Query contains potentially harmful content and has been blocked."),
    (r"--\s*(drop|delete|update|insert|truncate)",
                             "Query contains potentially harmful content and has been blocked."),

    # ── Dangerous system-level commands ──────────────────────────────────
    (r"\bexec\b",            "Query contains potentially harmful content and has been blocked."),
    (r"\bexecute\b",         "Query contains potentially harmful content and has been blocked."),
    (r"\bgrant\b",           "Query contains potentially harmful content and has been blocked."),
    (r"\brevoke\b",          "Query contains potentially harmful content and has been blocked."),
    (r"\bshutdown\b",        "Query contains potentially harmful content and has been blocked."),
    (r"\bxp_cmdshell\b",     "Query contains potentially harmful content and has been blocked."),
]


def sanitize_input(user_input: str) -> tuple[bool, str]:
    """
    Check natural language input for suspicious or malicious content.

    Returns:
        (is_safe: bool, reason: str)
        is_safe=True  → input is clean, proceed
        is_safe=False → input is flagged, block with reason (user-friendly message)
    """
    lowered = user_input.lower().strip()

    # Block empty queries
    if not lowered:
        return False, "Query cannot be empty."

    # Block excessively long inputs (potential prompt injection)
    if len(user_input) > 1000:
        return False, "Query is too long. Please keep it under 1000 characters."

    # Check for suspicious patterns — return the specific user-facing message
    for pattern, message in SUSPICIOUS_INPUT_PATTERNS:
        if re.search(pattern, lowered, re.IGNORECASE | re.DOTALL):
            return False, message

    return True, "OK"


def validate_sql(sql_query: str) -> tuple[bool, str]:
    """
    Validate that the generated SQL is a safe SELECT-only query.

    Checks:
    1. Must start with SELECT (after stripping whitespace/comments)
    2. Must not contain any dangerous DML/DDL keywords
    3. Must not contain multiple statements (stacked queries)
    4. Must not contain comment-based obfuscation tricks

    Returns:
        (is_safe: bool, reason: str)
    """
    if not sql_query or not sql_query.strip():
        return False, "Generated SQL query is empty."

    # Strip SQL comments before checking (catch obfuscation like SE/**/LECT)
    stripped = re.sub(r"/\*.*?\*/", " ", sql_query, flags=re.DOTALL)
    stripped = re.sub(r"--[^\n]*", " ", stripped)
    stripped = stripped.strip()

    # Rule 1: Must be a SELECT statement
    if not re.match(r"^\s*SELECT\b", stripped, re.IGNORECASE):
        return False, f"Only SELECT queries are allowed. Blocked query type detected."

    # Rule 2: Check for dangerous keywords as whole words
    for keyword in DANGEROUS_SQL_KEYWORDS:
        # Use word boundaries to avoid false positives (e.g. "INSERTED" in a column name)
        pattern = rf"\b{keyword}\b"
        if re.search(pattern, stripped, re.IGNORECASE):
            return False, f"Dangerous operation '{keyword}' detected in generated SQL. Query blocked."

    # Rule 3: Block stacked/multiple statements
    parsed = sqlparse.split(sql_query)
    if len(parsed) > 1:
        return False, "Multiple SQL statements detected. Only single SELECT queries are allowed."

    # Rule 4: Block UNION-based injection attempts that try to access sensitive tables
    sensitive_tables = ["information_schema", "mysql", "performance_schema", "sys"]
    for table in sensitive_tables:
        if re.search(rf"\b{table}\b", stripped, re.IGNORECASE):
            return False, f"Access to system table '{table}' is not permitted."

    return True, "OK"


def safe_error_message(error: Exception) -> str:
    """
    Sanitize error messages so internal DB details are never leaked to the client.
    Logs the full error internally but returns a generic message externally.
    """
    full_error = str(error)

    # Log full error server-side for debugging
    print(f"[INTERNAL ERROR] {full_error}")

    # Patterns that reveal sensitive info — return generic message instead
    sensitive_patterns = [
        r"Access denied for user",
        r"password",
        r"host '[\w.]+' is not allowed",
        r"Table '[\w.]+' doesn't exist",
        r"Unknown column '[\w.]+' in",
    ]

    for pattern in sensitive_patterns:
        if re.search(pattern, full_error, re.IGNORECASE):
            return "A database error occurred. Please check your query and try again."

    # For non-sensitive DB errors, return a cleaned version
    return f"Query execution failed. Please rephrase your question."

# ============================================================
# END SAFETY LAYER
# ============================================================
# ============================================================
# TOKEN OPTIMIZATION LAYER
# ============================================================

# Common English stop-words to ignore when scoring schema relevance
_STOP_WORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "used", "to", "of", "in", "on", "at", "by", "for", "with", "about",
    "from", "into", "through", "during", "before", "after", "above",
    "below", "between", "each", "all", "both", "few", "more", "most",
    "other", "some", "such", "no", "nor", "not", "only", "own", "same",
    "so", "than", "too", "very", "just", "me", "my", "myself", "we",
    "our", "you", "your", "he", "she", "it", "its", "they", "them",
    "their", "what", "which", "who", "whom", "this", "that", "these",
    "those", "i", "s", "t", "don", "how", "find", "get", "give", "show",
    "list", "tell", "many", "much", "number", "count", "total", "average",
    "avg", "max", "min", "sum", "and", "or", "where", "when", "whose",
    "top", "bottom", "first", "last", "between", "like", "any", "every",
}

# How many top-scoring tables to keep in the prompt (raises to full set if needed)
MAX_TABLES_IN_PROMPT = 3


def estimate_tokens(text: str) -> int:
    """
    Rough token estimator: ~1 token per 4 characters (standard heuristic).
    Good enough for logging savings; not used for billing.
    """
    return max(1, len(text) // 4)


def extract_query_keywords(query: str) -> set[str]:
    """
    Pull meaningful lowercase words from the natural language query,
    stripping stop-words, digits, and single characters.
    """
    raw_tokens = re.findall(r"\b[a-zA-Z_]+\b", query.lower())
    keywords = {t for t in raw_tokens if t not in _STOP_WORDS and len(t) > 1}
    return keywords


def score_table_relevance(table_name: str, columns: set, keywords: set) -> int:
    """
    Score a table by keyword overlap against its name and column names.
    Handles plural keywords (e.g. "customers" matches "customer_data").
      - Table name match:       3 pts
      - Exact column match:     2 pts
      - Partial column match:   1 pt
    """
    score = 0
    tl = table_name.lower()
    for kw in keywords:
        # Also check singular form — strips trailing "s" for plural keywords
        kw_s = kw.rstrip("s") if kw.endswith("s") and len(kw) > 3 else kw
        # Table name match (full keyword or singular form)
        if kw in tl or tl in kw or kw_s in tl or tl in kw_s:
            score += 3
        # Column name match
        for col in columns:
            cl = col.lower()
            if kw == cl or kw_s == cl:
                score += 2
            elif kw in cl or cl in kw or kw_s in cl or cl in kw_s:
                score += 1
    return score


def filter_schema_for_query(table_schema: dict, query: str) -> dict:
    """
    Return a reduced schema containing only the most relevant tables
    for the given natural language query.

    Strategy:
      1. Extract keywords from the query.
      2. Score every table by keyword overlap.
      3. Keep the top MAX_TABLES_IN_PROMPT tables (minimum 1, always).
      4. If ALL tables score 0 (very generic query), return the full schema
         so the model still has something to work with.

    Also logs token savings to the console.
    """
    keywords = extract_query_keywords(query)
    print(f"[TOKEN OPT] Query keywords: {keywords}")

    # Score every table
    scores = {
        table: score_table_relevance(table, cols, keywords)
        for table, cols in table_schema.items()
    }
    print(f"[TOKEN OPT] Table scores: {scores}")

    # Sort by score descending
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    # If everything scores 0, fall back to full schema
    if ranked[0][1] == 0:
        print("[TOKEN OPT] No strong match found — using full schema as fallback.")
        filtered = table_schema
    else:
        # Keep top-N tables; always include any table with score > 0
        top_tables = [t for t, s in ranked[:MAX_TABLES_IN_PROMPT] if s > 0]
        # Safety: never return empty
        if not top_tables:
            top_tables = [ranked[0][0]]
        filtered = {t: table_schema[t] for t in top_tables}

    print(f"[TOKEN OPT] Tables sent to Cerebras: {list(filtered.keys())}")
    return filtered

# ============================================================
# END TOKEN OPTIMIZATION LAYER
# ============================================================




def is_calculation_preview(natural_query: str, sql_query: str) -> bool:
    """
    Detect when a user's query has write-sounding intent (raise, increase,
    apply discount, deduct, etc.) but the generated SQL is still a safe SELECT
    with arithmetic — meaning the result is a calculated PREVIEW, not a DB change.

    Returns True if we should show the 'preview only' disclaimer.
    """
    # Natural language patterns that suggest the user wanted a write operation
    # but phrased it as a calculation (e.g. "give a 10% raise", "apply 5% discount")
    WRITE_INTENT_PATTERNS = [
        r"\bgive\b.*\braise\b",
        r"\bincrease\b.*\bsalary\b",
        r"\bapply\b.*\b(raise|discount|bonus|deduction|hike)\b",
        r"\b(raise|hike|bump)\b.*\b(salary|pay|wage|compensation)\b",
        r"\b(salary|pay|wage)\b.*\b(raise|hike|increase|bump)\b",
        r"\badd\b.*\bbonus\b",
        r"\bdeduct\b.*\b(salary|pay|amount)\b",
        r"\bcut\b.*\b(salary|pay|wage)\b",
        r"\bdiscount\b.*\bprice\b",
        r"\bprice\b.*\bdiscount\b",
        r"\bafter\b.*\b(raise|tax|deduction|discount|bonus)\b",
        r"\bwith\b.*\b(raise|bonus|discount|deduction)\b",
        r"\b\d+\s*(%|percent)\s*(raise|hike|increase|discount|bonus|deduction)\b",
        r"\b(raise|hike|increase|discount|bonus|deduction)\s*\d+\s*(%|percent)\b",
    ]

    # SQL patterns that confirm it is a SELECT with arithmetic (not a real write)
    SQL_CALCULATION_PATTERNS = [
        r"salary\s*[\*\+\-\/]\s*[\d.]+",   # salary * 1.10 or salary + 5000
        r"price\s*[\*\+\-\/]\s*[\d.]+",
        r"[\*\+\-\/]\s*0\.\d+",             # * 0.90  (discount)
        r"AS\s+\w*(salary|pay|price|bonus|net|gross)\w*",  # aliased calculated column
    ]

    lowered_q = natural_query.lower()
    lowered_sql = sql_query.upper()

    write_intent = any(
        re.search(p, lowered_q, re.IGNORECASE) for p in WRITE_INTENT_PATTERNS
    )
    has_calculation = any(
        re.search(p, sql_query, re.IGNORECASE) for p in SQL_CALCULATION_PATTERNS
    )

    result = write_intent and has_calculation
    if result:
        print("[PREVIEW] Write-intent query detected with arithmetic SELECT — "
              "will show 'preview only' disclaimer.")
    return result


def get_cerebras_client():
    return Cerebras(api_key=os.environ["CEREBRAS_API_KEY"])


def get_table_columns():
    """Fetch available table-column mappings from the database."""
    try:
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE()"
        )
        table_columns = {}
        for table, column in cursor.fetchall():
            if table not in table_columns:
                table_columns[table] = set()
            table_columns[table].add(column)
        cursor.close()
        conn.close()
        print("Fetched Table Schema:", table_columns)
        return table_columns
    except mysql.connector.Error as err:
        print("MySQL Error fetching columns:", str(err))
        return {}


def build_prompt(table_schema, query: str = "") -> str:
    """
    Build a schema-aware prompt for Cerebras.
    Applies Token Optimization when a query is given — filters schema to
    relevant tables only, then logs REAL before/after token counts for the
    FULL request sent to Cerebras (system message + user prompt + question).
    """
    # ── System role content (sent separately but still costs tokens) ─
    system_content = (
        "You are a MySQL expert. Return only raw SQL SELECT queries. "
        "Never generate INSERT, UPDATE, DELETE, DROP, ALTER, or any DDL/DML. "
        "No explanation, no markdown, no backticks."
    )

    # ── Static parts of the user prompt ──────────────────────────────
    system_prefix = (
        "You are a MySQL expert. Convert the user's natural language question "
        "into a valid MySQL SELECT query.\n\n"
        "The database has the following tables and columns:"
    )
    rules_suffix = (
        "\nRules:\n"
        "- Only use tables and columns listed above.\n"
        "- Always use the most relevant table based on the question.\n"
        "- Only generate SELECT queries — no INSERT, UPDATE, DELETE, or DROP.\n"
        "- Return ONLY the raw SQL query with no explanation, no markdown, no backticks.\n\n"
        "Convert this question to SQL:"
    )

    # ── BEFORE: measure the complete request with FULL schema ─────────
    if query:
        full_schema_desc = "".join(
            f"\nTable: {t}\nColumns: {', '.join(sorted(c))}\n"
            for t, c in table_schema.items()
        )
        # Full request = system_content + full user prompt + question
        full_request = system_content + system_prefix + full_schema_desc + rules_suffix + "\n" + query
        tokens_before = estimate_tokens(full_request)

        # Apply token optimization — filter schema to relevant tables only
        optimized_schema = filter_schema_for_query(table_schema, query)
    else:
        optimized_schema = table_schema
        tokens_before = None

    # ── Build the final optimised prompt ──────────────────────────────
    schema_description = "".join(
        f"\nTable: {table}\nColumns: {', '.join(sorted(columns))}\n"
        for table, columns in optimized_schema.items()
    )
    prompt = system_prefix + schema_description + rules_suffix

    # ── AFTER: measure the complete request with FILTERED schema ──────
    if tokens_before is not None:
        # After request = same system_content + optimised user prompt + question
        after_request = system_content + prompt + "\n" + query
        tokens_after = estimate_tokens(after_request)
        saved = tokens_before - tokens_after
        pct   = round((saved / tokens_before) * 100) if tokens_before > 0 else 0
        print(f"[TOKEN OPT] Full request tokens — "
              f"before: {tokens_before}  after: {tokens_after}  "
              f"saved: {saved} ({pct}% reduction)")

    return prompt


def handle_subquery_errors(sql_query):
    """Modify subqueries that return multiple rows to use LIMIT 1 inside the subquery."""
    fixed_query = re.sub(
        r"(\(\s*SELECT\s+[\w.*]+\s+FROM\s+[\w_]+\s+WHERE\s+[\w.]+\s*(=|>|<|>=|<=)\s*('.+?'|\d+)\s*)\)(?!\s*LIMIT\s+1)",
        r"\1 LIMIT 1)",
        sql_query,
        flags=re.IGNORECASE
    )
    return fixed_query


def fix_generated_sql(sql_query, table_schema):
    """Fix SQL queries dynamically based on the table schema."""
    valid_tables = set(table_schema.keys())
    valid_columns = {col for columns in table_schema.values() for col in columns}

    sql_keywords = {
        "SELECT", "FROM", "WHERE", "AND", "OR", "EXISTS", "NOT", "NULL", "LIMIT", "ORDER",
        "BY", "GROUP", "HAVING", "AS", "BETWEEN", "DESC", "ASC",
        "CASE", "WHEN", "THEN", "ELSE", "END", "JOIN", "LEFT", "RIGHT", "INNER", "ON"
    }
    sql_functions = {"MAX", "MIN", "AVG", "COUNT", "SUM", "DISTINCT"}

    # Fix table names
    table_pattern = r"\bFROM\s+([\w_]+)"
    tables_in_query = re.findall(table_pattern, sql_query, re.IGNORECASE)

    for table in tables_in_query:
        if table not in valid_tables:
            closest_match = get_close_matches(table, valid_tables, n=1)
            if closest_match:
                print(f"Replacing table {table} with {closest_match[0]}")
                sql_query = re.sub(rf"\b{table}\b", closest_match[0], sql_query)
            else:
                default_table = next(iter(valid_tables), "employees")
                print(f"No match found for table: {table}, defaulting to '{default_table}'")
                sql_query = re.sub(rf"\b{table}\b", default_table, sql_query)

    # Fix column names
    tokens = re.findall(r'\b\w+\b', sql_query)
    for token in tokens:
        if token.upper() in sql_keywords or token.upper() in sql_functions or token.isdigit() or token in valid_tables:
            continue
        if token not in valid_columns:
            closest_match = get_close_matches(token, valid_columns, n=1)
            if closest_match:
                print(f"Replacing column {token} with {closest_match[0]}")
                sql_query = re.sub(rf'\b{token}\b(?!(\s*\())', closest_match[0], sql_query)

    sql_query = handle_subquery_errors(sql_query)
    print("SQL Query after fixes:", sql_query)
    return sql_query


def get_cerebras_response(question, table_schema):
    """Fetch SQL query from Cerebras API using schema-aware prompt."""
    try:
        client = get_cerebras_client()
        prompt = build_prompt(table_schema, question)  # Token Optimization: filters schema by query

        response = client.chat.completions.create(
            model="llama3.3-70b",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a MySQL expert. Return only raw SQL SELECT queries. "
                        "Never generate INSERT, UPDATE, DELETE, DROP, ALTER, or any DDL/DML. "
                        "No explanation, no markdown, no backticks."
                    )
                },
                {
                    "role": "user",
                    "content": f"{prompt}\n{question}"
                }
            ],
            max_tokens=256,
            temperature=0
        )

        sql_query = response.choices[0].message.content.strip()
        sql_query = sql_query.replace("```sql", "").replace("```", "").strip()
        sql_query = re.sub(r"--.*", "", sql_query)

        queries = sqlparse.split(sql_query)
        if queries:
            sql_query = queries[0].strip()

        sql_query = fix_generated_sql(sql_query, table_schema)
        print("Generated SQL Query:", sql_query)
        return sql_query

    except Exception as e:
        print("Error getting Cerebras response:", str(e))
        traceback.print_exc()
        return None


def process_query(natural_language_query):
    """Process a natural language query and execute it."""
    try:
        # ── SAFETY CHECK 1: Sanitize user input ──────────────────────────
        is_safe, reason = sanitize_input(natural_language_query)
        if not is_safe:
            print(f"[SAFETY] Input blocked: {reason}")
            return {"error": f"Blocked: {reason}"}

        # ── Fetch schema and generate SQL ─────────────────────────────────
        table_schema = get_table_columns()
        print("\n[DEBUG] Table Schema:", table_schema)
        if not table_schema:
            return {"error": "Failed to fetch table schema"}

        sql_query = get_cerebras_response(natural_language_query, table_schema)
        if not sql_query:
            return {"error": "Failed to generate SQL query from Cerebras API"}

        sql_query = fix_generated_sql(sql_query, table_schema)
        print("[DEBUG] Fixed SQL Query:", sql_query)

        # ── SAFETY CHECK 2: Validate the generated SQL ────────────────────
        is_valid, validation_reason = validate_sql(sql_query)
        if not is_valid:
            print(f"[SAFETY] SQL blocked: {validation_reason}")
            return {"error": f"Query blocked for safety: {validation_reason}"}

        # ── Execute the safe, validated query ─────────────────────────────
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor(dictionary=True)
        print("[DEBUG] Executing SQL Query...")
        cursor.execute(sql_query)
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        print("[DEBUG] Query Execution Successful!")

        def convert_values(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, list):
                return [convert_values(item) for item in obj]
            elif isinstance(obj, dict):
                return {key: convert_values(value) for key, value in obj.items()}
            return obj

        formatted_result = convert_values(result)
        # ── PREVIEW FLAG: detect write-intent + arithmetic SELECT ────
        preview = is_calculation_preview(natural_language_query, sql_query)
        return {"sql_query": sql_query, "result": formatted_result, "is_preview": preview}

    except mysql.connector.Error as conn_err:
        # ── SAFETY CHECK 3: Sanitize error output ─────────────────────────
        safe_msg = safe_error_message(conn_err)
        return {"error": safe_msg}

    except ValueError as ve:
        print("Query Fixing Error:", str(ve))
        traceback.print_exc()
        return {"error": "Query could not be processed. Please rephrase your question."}

    except Exception as e:
        safe_msg = safe_error_message(e)
        return {"error": safe_msg}