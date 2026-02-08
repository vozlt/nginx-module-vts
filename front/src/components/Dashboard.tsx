import type { VtsResponse } from '../types';
import { MainZone } from './MainZone';
import { ServerZoneTable } from './ServerZoneTable';
import { FilterZones } from './FilterZones';
import { UpstreamZones } from './UpstreamZones';
import { CacheZones } from './CacheZones';

interface Props {
  data: VtsResponse;
}

function haveCache(data: VtsResponse): boolean {
  const key = '*';
  if (typeof data.serverZones[key] === 'undefined') {
    return true;
  }
  return Object.keys(data.serverZones[key].responses).length > 5;
}

export function Dashboard({ data }: Props) {
  const cache = haveCache(data);

  return (
    <>
      <MainZone data={data} />

      <div id="serverZones">
        <h2>Server zones</h2>
        <ServerZoneTable
          zones={data.serverZones}
          group="server"
          id="serverZones"
          cache={cache}
        />
      </div>

      {data.filterZones && (
        <FilterZones filterZones={data.filterZones} cache={cache} />
      )}

      {data.upstreamZones && (
        <UpstreamZones upstreamZones={data.upstreamZones} />
      )}

      {data.cacheZones && (
        <CacheZones zones={data.cacheZones} />
      )}
    </>
  );
}
