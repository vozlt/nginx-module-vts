import type { UpstreamPeer } from '../types';
import { formatDuration, formatBytes, formatUpstreamState, adjustOverflow } from '../utils/formatters';
import { rateTracker } from '../utils/rateTracker';

interface UpstreamTableProps {
  peers: UpstreamPeer[];
  group: string;
}

function UpstreamTable({ peers, group }: UpstreamTableProps) {
  return (
    <table>
      <thead>
        <tr>
          <th rowSpan={2}>Server</th>
          <th rowSpan={2}>State</th>
          <th rowSpan={2}>Response Time</th>
          <th rowSpan={2}>Weight</th>
          <th rowSpan={2}>MaxFails</th>
          <th rowSpan={2}>FailTimeout</th>
          <th colSpan={3}>Requests</th>
          <th colSpan={6}>Responses</th>
          <th colSpan={4}>Traffic</th>
        </tr>
        <tr>
          <th>Total</th>
          <th>Req/s</th>
          <th>Time</th>
          <th>1xx</th>
          <th>2xx</th>
          <th>3xx</th>
          <th>4xx</th>
          <th>5xx</th>
          <th>Total</th>
          <th>Sent</th>
          <th>Rcvd</th>
          <th>Sent/s</th>
          <th>Rcvd/s</th>
        </tr>
      </thead>
      <tbody>
        {peers.map((peer, i) => {
          const uniq = `upstreamZones.${group}.${peer.server}`;
          const oc = peer.overCounts;
          const maxInt = oc.maxIntegerSize;

          const r1xx = adjustOverflow(peer.responses['1xx'], oc['1xx'], maxInt);
          const r2xx = adjustOverflow(peer.responses['2xx'], oc['2xx'], maxInt);
          const r3xx = adjustOverflow(peer.responses['3xx'], oc['3xx'], maxInt);
          const r4xx = adjustOverflow(peer.responses['4xx'], oc['4xx'], maxInt);
          const r5xx = adjustOverflow(peer.responses['5xx'], oc['5xx'], maxInt);
          const responseTotal = r1xx + r2xx + r3xx + r4xx + r5xx;

          return (
            <tr key={peer.server} className={i % 2 ? 'odd' : ''}>
              <th>{peer.server}</th>
              <td>{formatUpstreamState(peer.backup, peer.down)}</td>
              <td>{formatDuration(peer.responseMsec)}</td>
              <td>{peer.weight}</td>
              <td>{peer.maxFails}</td>
              <td>{peer.failTimeout}</td>
              <td>{adjustOverflow(peer.requestCounter, oc.requestCounter, maxInt)}</td>
              <td>{rateTracker.getValue(`${uniq}.requestCounter`, peer.requestCounter)}</td>
              <td>{formatDuration(peer.requestMsec)}</td>
              <td>{r1xx}</td>
              <td>{r2xx}</td>
              <td>{r3xx}</td>
              <td>{r4xx}</td>
              <td>{r5xx}</td>
              <td>{responseTotal}</td>
              <td>{formatBytes(adjustOverflow(peer.outBytes, oc.outBytes, maxInt))}</td>
              <td>{formatBytes(adjustOverflow(peer.inBytes, oc.inBytes, maxInt))}</td>
              <td>{formatBytes(rateTracker.getValue(`${uniq}.outBytes`, peer.outBytes))}</td>
              <td>{formatBytes(rateTracker.getValue(`${uniq}.inBytes`, peer.inBytes))}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface Props {
  upstreamZones: Record<string, UpstreamPeer[]>;
}

export function UpstreamZones({ upstreamZones }: Props) {
  const groups = Object.keys(upstreamZones);

  return (
    <div id="upstreamZones">
      <h2>Upstreams</h2>
      {groups.map((group) => (
        <div key={group}>
          <h3>{group}</h3>
          <UpstreamTable peers={upstreamZones[group]} group={group} />
        </div>
      ))}
    </div>
  );
}
