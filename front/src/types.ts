export interface OverCounts {
  maxIntegerSize: number;
  requestCounter: number;
  inBytes: number;
  outBytes: number;
  '1xx': number;
  '2xx': number;
  '3xx': number;
  '4xx': number;
  '5xx': number;
  miss: number;
  bypass: number;
  expired: number;
  stale: number;
  updating: number;
  revalidated: number;
  hit: number;
  scarce: number;
  requestMsecCounter: number;
  responseMsecCounter?: number;
}

export interface Responses {
  '1xx': number;
  '2xx': number;
  '3xx': number;
  '4xx': number;
  '5xx': number;
  miss?: number;
  bypass?: number;
  expired?: number;
  stale?: number;
  updating?: number;
  revalidated?: number;
  hit?: number;
  scarce?: number;
}

export interface ServerZone {
  requestCounter: number;
  inBytes: number;
  outBytes: number;
  responses: Responses;
  requestMsecCounter: number;
  requestMsec: number;
  requestMsecs: { times: number[]; msecs: number[] };
  requestBuckets: { msecs: number[]; counters: number[] };
  overCounts: OverCounts;
}

export interface UpstreamPeer {
  server: string;
  requestCounter: number;
  inBytes: number;
  outBytes: number;
  responses: { '1xx': number; '2xx': number; '3xx': number; '4xx': number; '5xx': number };
  requestMsecCounter: number;
  requestMsec: number;
  requestMsecs: { times: number[]; msecs: number[] };
  requestBuckets: { msecs: number[]; counters: number[] };
  responseMsecCounter: number;
  responseMsec: number;
  responseMsecs: { times: number[]; msecs: number[] };
  responseBuckets: { msecs: number[]; counters: number[] };
  weight: number;
  maxFails: number;
  failTimeout: number;
  backup: boolean;
  down: boolean;
  overCounts: OverCounts;
}

export interface CacheZone {
  maxSize: number;
  usedSize: number;
  inBytes: number;
  outBytes: number;
  responses: Responses;
  overCounts: OverCounts;
}

export interface Connections {
  active: number;
  reading: number;
  writing: number;
  waiting: number;
  accepted: number;
  handled: number;
  requests: number;
}

export interface SharedZones {
  name: string;
  maxSize: number;
  usedSize: number;
  usedNode: number;
}

export interface VtsResponse {
  hostName: string;
  moduleVersion: string;
  nginxVersion: string;
  loadMsec: number;
  nowMsec: number;
  connections: Connections;
  sharedZones: SharedZones;
  serverZones: Record<string, ServerZone>;
  filterZones?: Record<string, Record<string, ServerZone>>;
  upstreamZones?: Record<string, UpstreamPeer[]>;
  cacheZones?: Record<string, CacheZone>;
}
