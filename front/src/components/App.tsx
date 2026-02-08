import { useVtsData } from '../hooks/useVtsData';
import { Dashboard } from './Dashboard';

export function App() {
  const { data, error, interval, setInterval } = useVtsData(1000);

  return (
    <>
      <h1>Nginx Vhost Traffic Status</h1>

      {error && <p style={{ color: 'red' }}>Error: {error}</p>}

      {data ? (
        <div id="monitor">
          <Dashboard data={data} />
        </div>
      ) : (
        !error && <p>Loading...</p>
      )}

      <div className="update">
        <strong>update interval:</strong>{' '}
        <select
          value={interval / 1000}
          onChange={(e) => setInterval(Number(e.target.value) * 1000)}
        >
          {[1, 2, 3, 4, 5, 6, 7, 8].map((v) => (
            <option key={v} value={v}>{v}</option>
          ))}
        </select>{' '}
        <strong>sec</strong>
      </div>

      <div className="footer">
        <a href="/status/format/json"><strong>JSON</strong></a>
        {' | '}
        <a href="https://github.com/vozlt/nginx-module-vts"><strong>GITHUB</strong></a>
      </div>
    </>
  );
}
