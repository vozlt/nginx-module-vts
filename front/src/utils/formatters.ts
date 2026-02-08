export function formatDuration(msec: number): string {
  const ms = 1000;
  const m = 60;
  const h = m * m;
  const d = h * 24;

  if (msec < ms) {
    return msec + 'ms';
  }

  if (msec < ms * m) {
    return Math.floor(msec / ms) + '.' + Math.floor((msec % ms) / 10) + 's';
  }

  let s = '';
  const days = Math.floor(msec / (d * ms));
  if (days) {
    s += days + 'd ';
  }

  const hours = Math.floor((msec % (d * ms)) / (h * ms));
  if (days || hours) {
    s += hours + 'h ';
  }

  const minutes = Math.floor(((msec % (d * ms)) % (h * ms)) / (m * ms));
  if (days || hours || minutes) {
    s += minutes + 'm ';
  }

  const seconds = Math.floor((((msec % (d * ms)) % (h * ms)) % (m * ms)) / ms);
  return s + seconds + 's';
}

export function formatBytes(b: number | string): string {
  const kb = 1024;
  if (typeof b !== 'number') {
    return String(b);
  }

  if (b < kb) {
    return b + ' B';
  }

  if (b < kb * kb) {
    return (b / kb).toFixed(1) + ' KiB';
  }

  if (b < kb * kb * kb) {
    return (b / (kb * kb)).toFixed(1) + ' MiB';
  }

  if (b < kb * kb * kb * kb) {
    return (b / (kb * kb * kb)).toFixed(2) + ' GiB';
  }

  return (b / (kb * kb * kb * kb)).toFixed(6) + ' TiB';
}

export function formatUpstreamState(backup: boolean, down: boolean): string {
  if (!backup && !down) {
    return 'up';
  } else if (down) {
    return 'down';
  } else {
    return 'backup';
  }
}

export function adjustOverflow(value: number, overCount: number, maxIntegerSize: number): number {
  return value + maxIntegerSize * overCount;
}
