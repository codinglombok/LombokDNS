/**
 * LombokDNS — DNS over QUIC (DoQ) Transport
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * RFC 9250 — DNS over Dedicated QUIC Connections.
 *
 * Features:
 *  - QUIC stream-per-query (each query on its own stream)
 *  - 0-RTT early data support
 *  - Connection migration
 *  - TLS 1.3 built-in
 *  - Multiplexed queries without head-of-line blocking
 *
 * Requires Node.js 23+ (node:quic) or platform with QUIC support.
 * Falls back gracefully with clear error if unavailable.
 */

import { unpack } from '../core/message.js';
import { frameTCP, deframeTCP } from './tcp.js';
import {
  type DNSTransport,
  type TransportResult,
  type QueryOptions,
  type DoQTransportConfig,
  TransportProtocol,
  DEFAULT_PORTS,
  DNSTransportError,
  DNSTimeoutError,
} from './types.js';

// ─── QUIC Module Loader ───────────────────────────────────────

interface QUICSession {
  openStream(): Promise<QUICStream>;
  close(): Promise<void>;
  destroy(err?: Error): void;
  closed: Promise<void>;
}

interface QUICStream {
  write(data: Uint8Array): void;
  end(): void;
  on(event: 'data', handler: (chunk: Buffer) => void): void;
  on(event: 'end', handler: () => void): void;
  on(event: 'error', handler: (err: Error) => void): void;
  destroy(): void;
}

let quicModule: {
  connect(options: Record<string, unknown>): Promise<QUICSession>;
} | null = null;
let quicChecked = false;

async function loadQUIC(): Promise<typeof quicModule> {
  if (quicChecked) return quicModule;
  quicChecked = true;
  try {
    quicModule = await import('node:net').then(m => {
      // Node.js QUIC API is experimental — check for availability
      if ('createQuicSocket' in m || 'QuicEndpoint' in m) {
        return m as unknown as typeof quicModule;
      }
      return null;
    });
  } catch {
    quicModule = null;
  }
  return quicModule;
}

// ─── DoQ Transport ────────────────────────────────────────────

export class DoQTransport implements DNSTransport {
  readonly protocol = TransportProtocol.DOQ;
  private readonly server: string;
  private readonly port: number;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly servername: string;
  private readonly ca?: string | string[];
  private readonly rejectUnauthorized: boolean;
  private readonly earlyData: boolean;
  private session: QUICSession | null = null;

  constructor(config: DoQTransportConfig) {
    this.server = config.server;
    this.port = config.port ?? DEFAULT_PORTS[TransportProtocol.DOQ];
    this.timeout = config.timeout ?? 5000;
    this.retries = config.retries ?? 2;
    this.servername = config.servername ?? config.server;
    this.ca = config.ca;
    this.rejectUnauthorized = config.rejectUnauthorized ?? true;
    this.earlyData = config.earlyData ?? false;
  }

  async query(message: Uint8Array, options?: QueryOptions): Promise<TransportResult> {
    const timeout = options?.timeout ?? this.timeout;
    const retries = options?.retries ?? this.retries;

    // Check QUIC availability
    const quic = await loadQUIC();
    if (!quic) {
      throw new DNSTransportError(
        'QUIC not available — requires Node.js 23+ with --experimental-quic flag, ' +
        'or a platform with QUIC support. Consider using DoT or DoH as alternatives.',
        TransportProtocol.DOQ,
        this.server,
        this.port,
      );
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await this.sendQuery(quic, message, timeout, options?.signal);
      } catch (err) {
        lastError = err as Error;
        if (options?.signal?.aborted) throw err;
        // Reset session on error
        await this.destroySession();
        if (attempt === retries) break;
      }
    }

    throw lastError ?? new DNSTransportError(
      'query failed after all retries',
      TransportProtocol.DOQ,
      this.server,
      this.port,
    );
  }

  private async getSession(
    quic: NonNullable<typeof quicModule>,
  ): Promise<QUICSession> {
    if (this.session) return this.session;

    this.session = await quic.connect({
      host: this.server,
      port: this.port,
      servername: this.servername,
      ca: this.ca,
      rejectUnauthorized: this.rejectUnauthorized,
      alpnProtocols: ['doq'],      // RFC 9250 §4
      maxStreamData: 65535,
      earlyData: this.earlyData,
    });

    return this.session;
  }

  private async sendQuery(
    quic: NonNullable<typeof quicModule>,
    message: Uint8Array,
    timeout: number,
    signal?: AbortSignal,
  ): Promise<TransportResult> {
    const session = await this.getSession(quic);
    const startTime = performance.now();

    return new Promise(async (resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new DNSTimeoutError(
          TransportProtocol.DOQ,
          this.server,
          this.port,
          timeout,
        ));
      }, timeout);

      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          reject(new DNSTransportError(
            'query aborted',
            TransportProtocol.DOQ,
            this.server,
            this.port,
          ));
        };
        if (signal.aborted) { clearTimeout(timer); onAbort(); return; }
        signal.addEventListener('abort', onAbort, { once: true });
      }

      try {
        // RFC 9250 §4.2 — Each query on a new stream with length prefix
        const stream = await session.openStream();
        const framed = frameTCP(message); // Same 2-byte length prefix as TCP
        let receiveBuffer = new Uint8Array(0);

        stream.on('data', (chunk: Buffer) => {
          const merged = new Uint8Array(receiveBuffer.length + chunk.length);
          merged.set(receiveBuffer);
          merged.set(new Uint8Array(chunk), receiveBuffer.length);
          receiveBuffer = merged;
        });

        stream.on('end', () => {
          clearTimeout(timer);
          const rtt = performance.now() - startTime;
          const { messages } = deframeTCP(receiveBuffer);

          if (messages.length === 0) {
            reject(new DNSTransportError(
              'empty response from QUIC stream',
              TransportProtocol.DOQ,
              this.server,
              this.port,
            ));
            return;
          }

          const raw = messages[0]!;
          try {
            const response = unpack(raw);
            resolve({
              response,
              raw,
              rtt,
              protocol: TransportProtocol.DOQ,
              server: this.server,
              port: this.port,
              responseSize: raw.length,
            });
          } catch (err) {
            reject(new DNSTransportError(
              `failed to parse response: ${(err as Error).message}`,
              TransportProtocol.DOQ,
              this.server,
              this.port,
              err as Error,
            ));
          }
        });

        stream.on('error', (err: Error) => {
          clearTimeout(timer);
          reject(new DNSTransportError(
            err.message,
            TransportProtocol.DOQ,
            this.server,
            this.port,
            err,
          ));
        });

        // Send framed query and signal end-of-data
        stream.write(framed);
        stream.end();
      } catch (err) {
        clearTimeout(timer);
        reject(new DNSTransportError(
          (err as Error).message,
          TransportProtocol.DOQ,
          this.server,
          this.port,
          err as Error,
        ));
      }
    });
  }

  private async destroySession(): Promise<void> {
    if (this.session) {
      try { this.session.destroy(); } catch { /* ignore */ }
      this.session = null;
    }
  }

  async close(): Promise<void> {
    await this.destroySession();
  }
}
