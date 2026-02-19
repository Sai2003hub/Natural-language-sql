# Ask Your Database

A full-stack Natural Language to SQL application that lets you query your MySQL database using plain English — no SQL knowledge required.

---

## 🚀 Features

### 🧠 Natural Language to SQL

- Converts plain English questions into valid MySQL SELECT queries
- Powered by Cerebras AI (LLaMA 3.3 70B) for fast, accurate SQL generation
- Schema-aware prompting — only relevant tables are sent to the model

### 🛡️ Multi-Layer Safety System

- **Input Sanitization** — blocks write-intent phrases (delete, update, drop, etc.) before they reach the AI
- **SQL Validation** — validates the generated SQL is a safe SELECT-only query
- **Error Sanitization** — internal database details are never exposed to the client
- Blocks SQL injection patterns, stacked queries, and access to system tables

### ⚡ Token Optimization

- Dynamically filters the database schema to only the most relevant tables per query
- Scores tables by keyword overlap with the user's question
- Reduces token usage and speeds up inference — logs token savings to the console

### 🔧 Smart SQL Fixing

- Auto-corrects table/column name typos using fuzzy matching
- Handles subquery edge cases automatically

### 👀 Preview Mode

- Detects write-intent queries (e.g. "give a 10% raise") that return arithmetic SELECT results
- Shows a **"Preview only — no data was changed"** disclaimer

---

## 🏗️ Tech Stack

**Backend:**
Python, FastAPI, Cerebras Cloud SDK (LLaMA 3.3-70b), MySQL Connector, SQLParse, difflib

**Frontend:**
React.js, Axios, CSS3 (DM Sans + Cherry Bomb One fonts)

---

## ✅ Prerequisites

- Python 3.10+
- Node.js v14+
- MySQL database
- Cerebras API key

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/ask-your-database.git
cd ask-your-database
```

### 2️⃣ Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

Edit `config.py` with your credentials:

```python
CEREBRAS_API_KEY = "your_cerebras_api_key"

DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'your_db_user',
    'password': 'your_db_password',
    'database': 'your_database_name'
}
```

Run the backend:

```bash
uvicorn main:app --reload
```

Runs on: `http://localhost:8000`

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm start
```

Runs on: `http://localhost:3000`

### 4️⃣ (Optional) Create Database Indexes

```bash
python create_indexes.py
```

---

## 📁 Project Structure

```
ask-your-database/
├── backend/
│   ├── config.py
│   ├── create_indexes.py
│   ├── main.py
│   ├── query.py
│   └── requirements.txt
│
└── frontend/
    ├── public/
    │   └── index.html
    └── src/
        ├── App.css
        ├── App.js
        └── index.js
```

---

## 🌐 API Endpoints

### `GET /`
Health check

### `POST /execute_query/`
NL → SQL → execute → return results

**Request:**

```json
{ "query": "Show me the top 5 highest paid employees" }
```

**Response:**

```json
{
  "sql_query": "SELECT name, salary FROM employees ORDER BY salary DESC LIMIT 5",
  "result": [...],
  "is_preview": false
}
```

---

## 🔐 Safety Architecture

```
User Input
    │
[1] Input Sanitizer
    │
[2] Cerebras AI
    │
[3] SQL Validator
    │
MySQL Execution
    │
[4] Error Sanitizer
```

---

## ⚙️ How It Works

1. User types a plain English question
2. Input sanitizer checks for blocked patterns
3. Schema is fetched from MySQL `INFORMATION_SCHEMA`
4. Token optimizer selects only relevant tables
5. Cerebras AI generates a SQL SELECT query
6. SQL fixer corrects table/column mismatches
7. SQL validator confirms the query is safe
8. Results are displayed in a formatted table

---

## 🔮 Future Enhancements

- Support for PostgreSQL and SQLite
- Query history and saved queries
- Export results to CSV/Excel
- Multi-turn conversational querying
- Role-based access control

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.

---

## 👤 Author

- **GitHub:** [https://github.com/Sai2003hub](https://github.com/Sai2003hub)
- **LinkedIn:** [https://www.linkedin.com/in/saiakshaya-r/](https://www.linkedin.com/in/saiakshaya-r/)
- **Email:** saiakshaya2003@gmail.com
