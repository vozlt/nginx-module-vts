import type { ServerZone } from '../types';
import { formatDuration, formatBytes, adjustOverflow } from '../utils/formatters';
import { rateTracker } from '../utils/rateTracker';

interface Props {
  zones: Record<string, ServerZone>;
  group: string;
  id: string;
  cache: boolean;
}

export function ServerZoneTable({ zones, group, id, cache }: Props) {
  const names = Object.keys(zones);

  return (
    <table>
      <thead>
        <tr>
          <th rowSpan={2}>Zone</th>
          <th colSpan={3}>Requests</th>
          <th colSpan={6}>Responses</th>
          <th colSpan={4}>Traffic</th>
          {cache && <th colSpan={9}>Cache</th>}
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
          {cache && (
            <>
              <th>Miss</th>
              <th>Bypass</th>
              <th>Expired</th>
              <th>Stale</th>
              <th>Updating</th>
              <th>Revalidated</th>
              <th>Hit</th>
              <th>Scarce</th>
              <th>Total</th>
            </>
          )}
        </tr>
      </thead>
      <tbody>
        {names.map((name, i) => {
          const zone = zones[name];
          const uniq = `${id}.${group}.${name}`;
          const oc = zone.overCounts;
          const maxInt = oc.maxIntegerSize;

          const r1xx = adjustOverflow(zone.responses['1xx'], oc['1xx'], maxInt);
          const r2xx = adjustOverflow(zone.responses['2xx'], oc['2xx'], maxInt);
          const r3xx = adjustOverflow(zone.responses['3xx'], oc['3xx'], maxInt);
          const r4xx = adjustOverflow(zone.responses['4xx'], oc['4xx'], maxInt);
          const r5xx = adjustOverflow(zone.responses['5xx'], oc['5xx'], maxInt);
          const responseTotal = r1xx + r2xx + r3xx + r4xx + r5xx;

          const isCountry = group.indexOf('country') !== -1 && name.length === 2;

          let cacheTotal = 0;
          const cacheValues: number[] = [];
          if (cache && zone.responses.miss !== undefined) {
            const cacheKeys = ['miss', 'bypass', 'expired', 'stale', 'updating', 'revalidated', 'hit', 'scarce'] as const;
            for (const key of cacheKeys) {
              const val = adjustOverflow(zone.responses[key] ?? 0, oc[key], maxInt);
              cacheValues.push(val);
              cacheTotal += val;
            }
          }

          return (
            <tr key={name} className={i % 2 ? 'odd' : ''}>
              <th>
                {isCountry && <img className={`flag flag-${name.toLowerCase()}`} alt={name} />}
                {name}
              </th>
              <td>{adjustOverflow(zone.requestCounter, oc.requestCounter, maxInt)}</td>
              <td>{rateTracker.getValue(`${uniq}.requestCounter`, zone.requestCounter)}</td>
              <td>{formatDuration(zone.requestMsec)}</td>
              <td>{r1xx}</td>
              <td>{r2xx}</td>
              <td>{r3xx}</td>
              <td>{r4xx}</td>
              <td>{r5xx}</td>
              <td>{responseTotal}</td>
              <td>{formatBytes(adjustOverflow(zone.outBytes, oc.outBytes, maxInt))}</td>
              <td>{formatBytes(adjustOverflow(zone.inBytes, oc.inBytes, maxInt))}</td>
              <td>{formatBytes(rateTracker.getValue(`${uniq}.outBytes`, zone.outBytes))}</td>
              <td>{formatBytes(rateTracker.getValue(`${uniq}.inBytes`, zone.inBytes))}</td>
              {cache && (
                <>
                  {cacheValues.map((v, j) => (
                    <td key={j}>{v}</td>
                  ))}
                  <td>{cacheTotal}</td>
                </>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
