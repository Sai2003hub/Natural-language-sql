import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [errorType, setErrorType] = useState(''); // 'blocked' | 'system' | ''
  const [hasQueried, setHasQueried] = useState(false);
  const [isPreview, setIsPreview] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError('');
    setErrorType('');
    setResult([]);
    setHasQueried(true);
    setIsPreview(false);

    try {
      const response = await axios.post(
        'http://localhost:8000/execute_query/',
        { query }
      );
      setResult(response.data.result);
      setIsPreview(response.data.is_preview || false);
    } catch (err) {
      // The FastAPI backend raises HTTP 500 with a `detail` field for all errors.
      // The detail message tells us whether it was a safety block or a system error.
      const detail = err?.response?.data?.detail || '';

      if (
        detail.startsWith('Blocked:') ||
        detail.toLowerCase().includes('read-only') ||
        detail.toLowerCase().includes('not allowed') ||
        detail.toLowerCase().includes('blocked for safety')
      ) {
        // Safety layer blocked this query — show as a warning, not a red error
        const friendlyMsg = detail.replace(/^Blocked:\s*/i, '');
        setError(friendlyMsg);
        setErrorType('blocked');
      } else {
        // Genuine system / DB error
        setError('Something went wrong. Please try again or rephrase your question.');
        setErrorType('system');
      }
    }

    setLoading(false);
  };

  return (
    <div className="App">

      <div className="header">
        <h1 className="title">Ask Your Database</h1>
        <p className="subtitle">
          Turn questions into insights from your data
        </p>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>

          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask anything about your data…"
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSubmit(e);
              }
            }}
          />

          <div className="btn-wrap">
            <button type="submit" disabled={loading}>
              {loading ? 'Running Query...' : 'Execute Query'}
            </button>
          </div>
        </form>

        {/* Blocked query — friendly warning banner */}
        {error && errorType === 'blocked' && (
          <div className="error-blocked">
            <span className="error-icon">🚫</span>
            <div>
              <strong>Action not permitted</strong>
              <p>{error}</p>
            </div>
          </div>
        )}

        {/* System error — standard error message */}
        {error && errorType === 'system' && (
          <div className="error">
            {error}
          </div>
        )}

        {/* Preview disclaimer — shown when write-intent query returns a calculated SELECT */}
        {isPreview && result.length > 0 && (
          <div className="preview-notice">
            <span className="preview-icon">ℹ️</span>
            <div>
              <strong>Preview only — no data was changed</strong>
              <p>This shows what the values <em>would</em> look like. Nothing has been saved to the database.</p>
            </div>
          </div>
        )}

        {result.length > 0 && (
          <div className="results-section">

            <div className="results-header">
              <span className="results-title">Results</span>
              <span className="results-count">
                {result.length} rows
              </span>
            </div>

            <div className="table-wrap">
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
                        <td key={idx}>{String(value)}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        )}

        {result.length === 0 && hasQueried && !loading && !error && (
          <div className="empty-state">No results found</div>
        )}

      </div>
    </div>
  );
}

export default App;