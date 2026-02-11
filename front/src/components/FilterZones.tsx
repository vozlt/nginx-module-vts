import type { ServerZone } from '../types';
import { ServerZoneTable } from './ServerZoneTable';

interface Props {
  filterZones: Record<string, Record<string, ServerZone>>;
  cache: boolean;
}

export function FilterZones({ filterZones, cache }: Props) {
  const groups = Object.keys(filterZones);

  return (
    <div id="filterZones">
      <h2>Filters</h2>
      {groups.map((group) => (
        <div key={group}>
          <h3>{group}</h3>
          <ServerZoneTable
            zones={filterZones[group]}
            group={group}
            id="filterZones"
            cache={cache}
          />
        </div>
      ))}
    </div>
  );
}
