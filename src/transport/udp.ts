/**
 * LombokDNS — UDP Transport
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * Standard UDP DNS transport (RFC 1035 §4.2.1).
 * Features:
 *  - IPv4 and IPv6 support (auto-detect)
 *  - Configurable timeout and retries
 *  - Truncation detection (TC bit) with automatic TCP fallback
 *  - Query ID matching for response validation
 */

import * as dgram from 'node:dgram';
import { unpack } from '../core/message.js';
import { HeaderFlags } from '../core/types.js';
import {
  type DNSTransport,
  type TransportResult,
  type QueryOptions,
  type UDPTransportConfig,
  TransportProtocol,
  DEFAULT_PORTS,
  DNSTransportError,
  DNSTimeoutError,
  DNSTruncatedError,
} from './types.js';
import { TCPTransport } from './tcp.js';

// ─── IPv6 Detection ───────────────────────────────────────────

function isIPv6(address: string): boolean {
  return address.includes(':');
}

// ─── UDP Transport ────────────────────────────────────────────

export class UDPTransport implements DNSTransport {
  readonly protocol = TransportProtocol.UDP;
  private readonly server: string;
  private readonly port: number;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly ipv6: boolean;

  constructor(config: UDPTransportConfig) {
    this.server = config.server;
    this.port = config.port ?? DEFAULT_PORTS[TransportProtocol.UDP];
    this.timeout = config.timeout ?? 5000;
    this.retries = config.retries ?? 2;
    this.ipv6 = config.ipv6 ?? isIPv6(config.server);
  }

  async query(message: Uint8Array, options?: QueryOptions): Promise<TransportResult> {
    const timeout = options?.timeout ?? this.timeout;
    const retries = options?.retries ?? this.retries;
    const tcpFallback = options?.tcpFallback ?? true;

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const result = await this.sendQuery(message, timeout, options?.signal);

        // Check for truncation (TC bit)
        if (result.response.header.flags & HeaderFlags.TC) {
          if (tcpFallback) {
            return this.fallbackToTCP(message, timeout, options?.signal);
          }
          throw new DNSTruncatedError(this.server, this.port, result.raw);
        }

        return result;
      } catch (err) {
        lastError = err as Error;
        if (err instanceof DNSTruncatedError) throw err;
        if (options?.signal?.aborted) throw err;
        // Don't retry on non-timeout errors for last attempt
        if (attempt === retries) break;
      }
    }

    throw lastError ?? new DNSTransportError(
      'query failed after all retries',
      TransportProtocol.UDP,
      this.server,
      this.port,
    );
  }

  private sendQuery(
    message: Uint8Array,
    timeout: number,
    signal?: AbortSignal,
  ): Promise<TransportResult> {
    return new Promise((resolve, reject) => {
      const socketType = this.ipv6 ? 'udp6' : 'udp4';
      const socket = dgram.createSocket(socketType);
      const startTime = performance.now();
      let settled = false;

      const cleanup = () => {
        if (!settled) {
          settled = true;
          try { socket.close(); } catch { /* ignore */ }
        }
      };

      // Timeout handler
      const timer = setTimeout(() => {
        cleanup();
        reject(new DNSTimeoutError(
          TransportProtocol.UDP,
          this.server,
          this.port,
          timeout,
        ));
      }, timeout);

      // Abort signal handler
      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          cleanup();
          reject(new DNSTransportError(
            'query aborted',
            TransportProtocol.UDP,
            this.server,
            this.port,
          ));
        };
        if (signal.aborted) {
          onAbort();
          return;
        }
        signal.addEventListener('abort', onAbort, { once: true });
      }

      // Extract query ID for response matching
      const queryId = (message[0]! << 8) | message[1]!;

      socket.on('error', (err) => {
        clearTimeout(timer);
        cleanup();
        reject(new DNSTransportError(
          err.message,
          TransportProtocol.UDP,
          this.server,
          this.port,
          err,
        ));
      });

      socket.on('message', (msg: Buffer) => {
        clearTimeout(timer);
        const rtt = performance.now() - startTime;
        cleanup();

        const raw = new Uint8Array(msg);

        // Validate response ID matches query ID
        if (raw.length >= 2) {
          const responseId = (raw[0]! << 8) | raw[1]!;
          if (responseId !== queryId) {
            reject(new DNSTransportError(
              `response ID ${responseId} does not match query ID ${queryId}`,
              TransportProtocol.UDP,
              this.server,
              this.port,
            ));
            return;
          }
        }

        try {
          const response = unpack(raw);
          resolve({
            response,
            raw,
            rtt,
            protocol: TransportProtocol.UDP,
            server: this.server,
            port: this.port,
            responseSize: raw.length,
          });
        } catch (err) {
          reject(new DNSTransportError(
            `failed to parse response: ${(err as Error).message}`,
            TransportProtocol.UDP,
            this.server,
            this.port,
            err as Error,
          ));
        }
      });

      // Send query
      socket.send(
        Buffer.from(message),
        0,
        message.length,
        this.port,
        this.server,
        (err) => {
          if (err) {
            clearTimeout(timer);
            cleanup();
            reject(new DNSTransportError(
              `send failed: ${err.message}`,
              TransportProtocol.UDP,
              this.server,
              this.port,
              err,
            ));
          }
        },
      );
    });
  }

  private async fallbackToTCP(
    message: Uint8Array,
    timeout: number,
    signal?: AbortSignal,
  ): Promise<TransportResult> {
    const tcp = new TCPTransport({
      server: this.server,
      port: this.port,
      timeout,
      keepAlive: false,
    });

    try {
      const result = await tcp.query(message, { timeout, signal, retries: 0 });
      return {
        ...result,
        tcpFallback: true,
      };
    } finally {
      await tcp.close();
    }
  }

  async close(): Promise<void> {
    // UDP is stateless — nothing to close
  }
}
