import type { CacheZone } from '../types';
import { formatBytes, adjustOverflow } from '../utils/formatters';
import { rateTracker } from '../utils/rateTracker';

interface Props {
  zones: Record<string, CacheZone>;
}

export function CacheZones({ zones }: Props) {
  const names = Object.keys(zones);

  return (
    <div id="cacheZones">
      <h2>Caches</h2>
      <table>
        <thead>
          <tr>
            <th rowSpan={2}>Zone</th>
            <th colSpan={2}>Size</th>
            <th colSpan={4}>Traffic</th>
            <th colSpan={9}>Cache</th>
          </tr>
          <tr>
            <th>Capacity</th>
            <th>Used</th>
            <th>Sent</th>
            <th>Rcvd</th>
            <th>Sent/s</th>
            <th>Rcvd/s</th>
            <th>Miss</th>
            <th>Bypass</th>
            <th>Expired</th>
            <th>Stale</th>
            <th>Updating</th>
            <th>Revalidated</th>
            <th>Hit</th>
            <th>Scarce</th>
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          {names.map((name, i) => {
            const zone = zones[name];
            const uniq = `cacheZones.cache.${name}`;
            const oc = zone.overCounts;
            const maxInt = oc.maxIntegerSize;

            const cacheKeys = ['miss', 'bypass', 'expired', 'stale', 'updating', 'revalidated', 'hit', 'scarce'] as const;
            let cacheTotal = 0;
            const cacheValues: number[] = [];
            for (const key of cacheKeys) {
              const val = adjustOverflow(zone.responses[key] ?? 0, oc[key], maxInt);
              cacheValues.push(val);
              cacheTotal += val;
            }

            return (
              <tr key={name} className={i % 2 ? 'odd' : ''}>
                <th>{name}</th>
                <td>{formatBytes(zone.maxSize)}</td>
                <td>{formatBytes(zone.usedSize)}</td>
                <td>{formatBytes(adjustOverflow(zone.outBytes, oc.outBytes, maxInt))}</td>
                <td>{formatBytes(adjustOverflow(zone.inBytes, oc.inBytes, maxInt))}</td>
                <td>{formatBytes(rateTracker.getValue(`${uniq}.outBytes`, zone.outBytes))}</td>
                <td>{formatBytes(rateTracker.getValue(`${uniq}.inBytes`, zone.inBytes))}</td>
                {cacheValues.map((v, j) => (
                  <td key={j}>{v}</td>
                ))}
                <td>{cacheTotal}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
