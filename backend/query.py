import re
import mysql.connector
import google.generativeai as genai
from config import DATABASE_CONFIG
import json
from decimal import Decimal
import os
import sqlparse
from difflib import get_close_matches
import traceback

# Set API Key
os.environ["GOOGLE_API_KEY"] = ""  # Add your API key here 
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

def get_table_columns():
    """Fetch available table-column mappings from the database."""
    try:
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE()")
        table_columns = {}
        for table, column in cursor.fetchall():
            if table not in table_columns:
                table_columns[table] = set()
            table_columns[table].add(column)
        cursor.close()
        conn.close()
        
        print("Fetched Table Schema:", table_columns)  # Debugging output
        return table_columns
    except mysql.connector.Error as err:
        print("MySQL Error fetching columns:", str(err))
        return {}

def handle_subquery_errors(sql_query):
    """Modify subqueries that return multiple rows to use LIMIT 1 inside the subquery."""

    # Ensure LIMIT 1 is inside the subquery only if it's missing
    fixed_query = re.sub(
        r"(\(\s*SELECT\s+[\w.*]+\s+FROM\s+[\w_]+\s+WHERE\s+[\w.]+\s*(=|>|<|>=|<=)\s*('.+?'|\d+)\s*)\)(?!\s*LIMIT\s+1)",
        r"\1 LIMIT 1)",
        sql_query,
        flags=re.IGNORECASE
    )

    return fixed_query

def fix_generated_sql(sql_query, table_schema):
    """Fix SQL queries dynamically based on the table schema and handle multi-row subqueries."""
    
    # Extract available columns and tables from the schema
    valid_tables = set(table_schema.keys())
    valid_columns = {col for columns in table_schema.values() for col in columns}

    print("Valid Columns:", valid_columns)  # Debugging output

    # Define a list of SQL keywords and functions to ignore
    sql_keywords = {
        "SELECT", "FROM", "WHERE", "AND", "OR", "EXISTS", "NOT", "NULL", "LIMIT", "ORDER", 
        "BY", "GROUP", "HAVING", "AS", "BETWEEN", "DESC", "ASC",
        "CASE", "WHEN", "THEN", "ELSE", "END"
    }
    sql_functions = {"MAX", "MIN", "AVG", "COUNT", "SUM"}

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

    # Replace incorrect column names with closest match
    tokens = re.findall(r'\b\w+\b', sql_query)
    for token in tokens:
        if token.upper() in sql_keywords or token.upper() in sql_functions or token.isdigit() or token in valid_tables:
            continue

        if token not in valid_columns:
            closest_match = get_close_matches(token, valid_columns, n=1)
            if closest_match:
                print(f"Replacing column {token} with {closest_match[0]}")
                sql_query = re.sub(rf'\b{token}\b(?!(\s*\())', closest_match[0], sql_query)  # Ensure functions aren't affected
            else:
                print(f"No match found for column: {token}, defaulting to 'name'")  
                sql_query = re.sub(rf'\b{token}\b(?!(\s*\())', "name", sql_query)  

    # Handle subqueries that might return multiple rows
    sql_query = handle_subquery_errors(sql_query)

    # Prevent duplicate LIMIT 1 in the main query
    sql_query = re.sub(r"\b(LIMIT\s+1)\b(?!\s*;)", r"\1", sql_query, flags=re.IGNORECASE)

    print("SQL Query after column and table name replacement:", sql_query)
    return sql_query

def get_gemini_response(question, prompt, table_schema):
    """Fetch a single SQL query from Gemini API and apply necessary fixes."""
    model = genai.GenerativeModel('models/gemini-1.5-pro')
    response = model.generate_content(contents=f"{prompt}\n{question}")
    try:
        if response and response.candidates:
            sql_query = response.candidates[0].content.parts[0].text.strip()
            
            sql_query = sql_query.replace("```sql", "").replace("```", "").strip()
            sql_query = re.sub(r"--.*", "", sql_query)
            
            queries = sqlparse.split(sql_query)
            if queries:
                sql_query = queries[0].strip()

            sql_query = fix_generated_sql(sql_query, table_schema)

            print("Generated SQL Query:", sql_query)
            return sql_query
        else:
            raise ValueError("Invalid response format from Gemini API")
    except Exception as e:
        print("Error extracting SQL query:", str(e))
        return None



def process_query(natural_language_query):
    """Process a natural language query, validate column names, fix potential SQL issues, and execute it."""
    try:
        prompt = "Convert the following natural language query to a SQL query:"
        table_schema = get_table_columns()

        print("\n[DEBUG] Table Schema:", table_schema)  # Debugging output
        if not table_schema:
            return {"error": "Failed to fetch table schema"}

        sql_query = get_gemini_response(natural_language_query, prompt, table_schema)
        if not sql_query:
            return {"error": "Failed to generate SQL query from Gemini API"}

        sql_query = fix_generated_sql(sql_query, table_schema)
        print("[DEBUG] Fixed SQL Query:", sql_query)  # Debugging Output

        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        print("[DEBUG] Executing SQL Query...")  # Debugging Output
        cursor.execute(sql_query)
        result = cursor.fetchall()

        cursor.close()
        conn.close()

        print("[DEBUG] Query Execution Successful!")  # Debugging Output

        # Convert Decimal values to float
        def convert_values(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, list):
                return [convert_values(item) for item in obj]
            elif isinstance(obj, dict):
                return {key: convert_values(value) for key, value in obj.items()}
            return obj

        formatted_result = convert_values(result)
        json_result = json.dumps(formatted_result, indent=2)

        return {"sql_query": sql_query, "result": formatted_result}

    except mysql.connector.Error as conn_err:
        print("Database Connection Failed:", str(conn_err))
        traceback.print_exc()  # Print full error details
        return {"error": f"Database Connection Error: {str(conn_err)}"}

    except mysql.connector.Error as sql_err:
        print("SQL Execution Error:", str(sql_err))
        traceback.print_exc()  # Print full error details
        return {"error": f"MySQL Error: {str(sql_err)}"}

    except ValueError as ve:
        print("Query Fixing Error:", str(ve))
        traceback.print_exc()  # Print full error details
        return {"error": str(ve)}

    except Exception as e:
        print("Unexpected Error:", str(e))
        traceback.print_exc()  # Print full error details
        return {"error": f"Unexpected Error: {str(e)}"}



