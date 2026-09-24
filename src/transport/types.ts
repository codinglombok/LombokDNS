/**
 * LombokDNS — Transport Layer Types & Interfaces
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * Abstract transport interface for DNS query/response exchange.
 * Implementations: UDP, TCP, DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250)
 */

import type { DNSMessage } from '../core/types.js';

// ─── Transport Protocol Enum ──────────────────────────────────

export enum TransportProtocol {
  UDP   = 'udp',
  TCP   = 'tcp',
  DOT   = 'dot',   // DNS over TLS  (RFC 7858)
  DOH   = 'doh',   // DNS over HTTPS (RFC 8484)
  DOQ   = 'doq',   // DNS over QUIC  (RFC 9250)
}

// ─── Query Options ────────────────────────────────────────────

export interface QueryOptions {
  /** Query timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Number of retries on timeout/failure (default: 2) */
  retries?: number;
  /** Automatically retry over TCP on truncation (default: true) */
  tcpFallback?: boolean;
  /** AbortSignal for cancellation */
  signal?: AbortSignal;
}

// ─── Transport Configuration ──────────────────────────────────

export interface TransportConfig {
  /** DNS server address (IP or hostname) */
  server: string;
  /** Server port (default: protocol-dependent) */
  port?: number;
  /** Query timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Number of retries (default: 2) */
  retries?: number;
}

export interface UDPTransportConfig extends TransportConfig {
  /** Use IPv6 socket (default: auto-detect from server address) */
  ipv6?: boolean;
}

export interface TCPTransportConfig extends TransportConfig {
  /** Enable connection keep-alive (default: true) */
  keepAlive?: boolean;
  /** Keep-alive idle time in ms (default: 10000) */
  keepAliveIdle?: number;
  /** Enable query pipelining (default: true) */
  pipeline?: boolean;
}

export interface DoTTransportConfig extends TCPTransportConfig {
  /** Server Name Indication for TLS (defaults to server) */
  servername?: string;
  /** Custom CA certificates (PEM format) */
  ca?: string | string[];
  /** Skip certificate verification (NOT RECOMMENDED) */
  rejectUnauthorized?: boolean;
}

export interface DoHTransportConfig extends TransportConfig {
  /** Full DoH endpoint URL (e.g., https://dns.google/dns-query) */
  url: string;
  /** HTTP method: POST (default, binary) or GET (base64url) */
  method?: 'POST' | 'GET';
  /** Custom HTTP headers */
  headers?: Record<string, string>;
  /** Use JSON wire format instead of binary (RFC 8427) */
  useJson?: boolean;
}

export interface DoQTransportConfig extends TransportConfig {
  /** Server Name Indication for QUIC TLS */
  servername?: string;
  /** Custom CA certificates (PEM format) */
  ca?: string | string[];
  /** Skip certificate verification (NOT RECOMMENDED) */
  rejectUnauthorized?: boolean;
  /** Enable 0-RTT early data (default: false) */
  earlyData?: boolean;
}

// ─── Transport Result ─────────────────────────────────────────

export interface TransportResult {
  /** The DNS response message */
  response: DNSMessage;
  /** Raw response bytes */
  raw: Uint8Array;
  /** Round-trip time in milliseconds */
  rtt: number;
  /** Transport protocol used */
  protocol: TransportProtocol;
  /** Server address queried */
  server: string;
  /** Server port queried */
  port: number;
  /** Whether TCP fallback was used (UDP → TCP on truncation) */
  tcpFallback?: boolean;
  /** Response size in bytes */
  responseSize: number;
}

// ─── Abstract Transport Interface ─────────────────────────────

export interface DNSTransport {
  /** Transport protocol identifier */
  readonly protocol: TransportProtocol;

  /**
   * Send a DNS query and receive a response.
   * @param message - Packed DNS query as Uint8Array
   * @param options - Per-query options
   * @returns Transport result with response
   */
  query(message: Uint8Array, options?: QueryOptions): Promise<TransportResult>;

  /**
   * Close the transport and release resources.
   * For connection-oriented transports (TCP, DoT, DoQ),
   * this closes active connections.
   */
  close(): Promise<void>;
}

// ─── Connection Pool Interface ────────────────────────────────

export interface ConnectionPool {
  /** Number of active connections */
  readonly size: number;
  /** Maximum pool size */
  readonly maxSize: number;

  /** Acquire a connection from the pool */
  acquire(): Promise<PooledConnection>;
  /** Release a connection back to the pool */
  release(conn: PooledConnection): void;
  /** Close all connections */
  drain(): Promise<void>;
}

export interface PooledConnection {
  /** Unique connection ID */
  readonly id: string;
  /** Whether the connection is still usable */
  readonly alive: boolean;
  /** Send data and receive response */
  exchange(data: Uint8Array): Promise<Uint8Array>;
  /** Close this connection */
  close(): Promise<void>;
}

// ─── Default Ports ────────────────────────────────────────────

export const DEFAULT_PORTS: Record<TransportProtocol, number> = {
  [TransportProtocol.UDP]: 53,
  [TransportProtocol.TCP]: 53,
  [TransportProtocol.DOT]: 853,
  [TransportProtocol.DOH]: 443,
  [TransportProtocol.DOQ]: 853,
};

// ─── Transport Errors ─────────────────────────────────────────

export class DNSTransportError extends Error {
  constructor(
    message: string,
    public readonly protocol: TransportProtocol,
    public readonly server: string,
    public readonly port: number,
    public readonly cause?: Error,
  ) {
    super(`[${protocol}] ${server}:${port} — ${message}`);
    this.name = 'DNSTransportError';
  }
}

export class DNSTimeoutError extends DNSTransportError {
  constructor(
    protocol: TransportProtocol,
    server: string,
    port: number,
    public readonly timeoutMs: number,
  ) {
    super(`query timed out after ${timeoutMs}ms`, protocol, server, port);
    this.name = 'DNSTimeoutError';
  }
}

export class DNSTruncatedError extends DNSTransportError {
  constructor(
    server: string,
    port: number,
    public readonly truncatedResponse: Uint8Array,
  ) {
    super('response truncated (TC bit set)', TransportProtocol.UDP, server, port);
    this.name = 'DNSTruncatedError';
  }
}
