import { describe, expect, it } from 'vitest';

import { RateTracker } from './rateTracker';

// Two refreshes are needed before a period exists: the first one has nothing
// to subtract from.
function tracker(period = 1000): RateTracker {
  const rt = new RateTracker();

  rt.refresh(0);
  rt.refresh(period);

  return rt;
}

describe('RateTracker', () => {
  it('has nothing to compare the first reading against', () => {
    const rt = tracker();

    expect(rt.getValue('zone.requestCounter', 10)).toBe('n/a');
  });

  it('turns a rise into a rate per second', () => {
    const rt = tracker();

    rt.getValue('zone.requestCounter', 10);

    expect(rt.getValue('zone.requestCounter', 20)).toBe(10);
  });

  // vhost_traffic_status_filter_max_node drops the node of a filter that has
  // not been used for a while, and the next request through it starts a new
  // one from zero. The counter is not monotonic, so a fall says the rate of
  // that interval is unknown rather than negative.
  it('reports a counter that fell as unknown', () => {
    const rt = tracker();

    rt.getValue('filter.requestCounter', 5);

    expect(rt.getValue('filter.requestCounter', 1)).toBe('n/a');
  });

  it('measures the next rise from where the counter restarted', () => {
    const rt = tracker();

    rt.getValue('filter.requestCounter', 5);
    rt.getValue('filter.requestCounter', 1);

    expect(rt.getValue('filter.requestCounter', 3)).toBe(2);
  });

  it('keeps one key from disturbing another', () => {
    const rt = tracker();

    rt.getValue('a.requestCounter', 10);
    rt.getValue('b.requestCounter', 10);
    rt.getValue('a.requestCounter', 5);

    expect(rt.getValue('b.requestCounter', 20)).toBe(10);
  });

  // Two readings that carry the same time leave nothing to divide by.
  it('reports an empty period as unknown', () => {
    const rt = new RateTracker();

    rt.refresh(1000);

    rt.getValue('zone.requestCounter', 10);

    expect(rt.getValue('zone.requestCounter', 20)).toBe('n/a');
  });
});
