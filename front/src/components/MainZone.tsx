import type { VtsResponse } from '../types';
import { formatDuration, formatBytes } from '../utils/formatters';
import { rateTracker } from '../utils/rateTracker';

interface Props {
  data: VtsResponse;
}

export function MainZone({ data }: Props) {
  const uptime = data.nowMsec - data.loadMsec;
  const c = data.connections;
  const sz = data.sharedZones;

  return (
    <div id="mainZones">
      <h2>Server main</h2>
      <table>
        <thead>
          <tr>
            <th rowSpan={2}>Host</th>
            <th rowSpan={2}>Version</th>
            <th rowSpan={2}>Uptime</th>
            <th colSpan={4}>Connections</th>
            <th colSpan={4}>Requests</th>
            <th colSpan={4}>Shared memory</th>
          </tr>
          <tr>
            <th>active</th>
            <th>reading</th>
            <th>writing</th>
            <th>waiting</th>
            <th>accepted</th>
            <th>handled</th>
            <th>Total</th>
            <th>Req/s</th>
            <th>name</th>
            <th>maxSize</th>
            <th>usedSize</th>
            <th>usedNode</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>{data.hostName}</strong></td>
            <td>{data.nginxVersion}</td>
            <td>{formatDuration(uptime)}</td>
            <td>{c.active}</td>
            <td>{c.reading}</td>
            <td>{c.writing}</td>
            <td>{c.waiting}</td>
            <td>{c.accepted}</td>
            <td>{c.handled}</td>
            <td>{c.requests}</td>
            <td>{rateTracker.getValue('main.connections.requests', c.requests)}</td>
            <td><strong>{sz.name}</strong></td>
            <td>{formatBytes(sz.maxSize)}</td>
            <td>{formatBytes(sz.usedSize)}</td>
            <td>{sz.usedNode}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
