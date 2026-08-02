export class RateTracker {
  private data: Record<string, number> = {};
  private lastMsec: number | undefined = undefined;
  private period: number | undefined = undefined;

  getValue(key: string, value: number): string | number {
    if (typeof this.data[key] === 'undefined') {
      this.data[key] = value;
      return 'n/a';
    } else {
      const increase = value - this.data[key];
      this.data[key] = value;

      // A counter does not only rise: filter nodes are dropped once
      // vhost_traffic_status_filter_max_node is reached and the next request
      // through one starts it again from zero. The rate of that interval is
      // unknown, which is not the same as zero.
      if (increase < 0 || !this.period || this.period <= 0) {
        return 'n/a';
      }

      return Math.floor((increase * 1000) / this.period);
    }
  }

  refresh(time: number): void {
    this.period = time - (this.lastMsec ?? time);
    this.lastMsec = time;
  }
}

export const rateTracker = new RateTracker();
