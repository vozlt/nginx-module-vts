class RateTracker {
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
      return Math.floor((increase * 1000) / (this.period ?? 1));
    }
  }

  refresh(time: number): void {
    this.period = time - (this.lastMsec ?? time);
    this.lastMsec = time;
  }
}

export const rateTracker = new RateTracker();
