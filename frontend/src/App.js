import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [query, setQuery] = useState('');
  const [sqlQuery, setSqlQuery] = useState('');
  const [result, setResult] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult([]);
    setSqlQuery('');

    try {
      const response = await axios.post('http://localhost:8000/execute_query/', { query });
      setSqlQuery(response.data.sql_query);
      setResult(response.data.result);
    } catch (error) {
      console.error('Error executing query:', error);
      setError('⚠️ Failed to execute query. Please try again.');
    }
    setLoading(false);
  };

  return (
    <div className="App">
      <h1>📝 Natural Language to SQL Converter</h1>
      <form onSubmit={handleSubmit}>
        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter your query in plain English..."
        />
        <button type="submit" disabled={loading}>
          {loading ? '⏳ Executing...' : '🚀 Execute Query'}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {sqlQuery && (
        <div>
          <h2>🛠 Generated SQL Query:</h2>
          <pre>{sqlQuery}</pre>
        </div>
      )}

      {result.length > 0 && (
        <div>
          <h2>📊 Query Result:</h2>
          <table>
            <thead>
              <tr>
                {Object.keys(result[0]).map((key) => (
                  <th key={key}>{key}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.map((row, index) => (
                <tr key={index}>
                  {Object.values(row).map((value, idx) => (
                    <td key={idx}>{value}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default App;
