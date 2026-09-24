/**
 * LombokDNS — TCP Transport
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * TCP DNS transport (RFC 1035 §4.2.2).
 * Features:
 *  - Length-prefix framing (2-byte big-endian length)
 *  - Connection keep-alive and reuse
 *  - Query pipelining (multiple in-flight queries)
 *  - Connection pooling with idle timeout
 *  - Query ID matching
 */

import * as net from 'node:net';
import { unpack } from '../core/message.js';
import {
  type DNSTransport,
  type TransportResult,
  type QueryOptions,
  type TCPTransportConfig,
  TransportProtocol,
  DEFAULT_PORTS,
  DNSTransportError,
  DNSTimeoutError,
} from './types.js';

// ─── TCP Framing Helpers ──────────────────────────────────────

/** Prepend 2-byte length prefix (RFC 1035 §4.2.2) */
export function frameTCP(message: Uint8Array): Uint8Array {
  const framed = new Uint8Array(2 + message.length);
  framed[0] = (message.length >> 8) & 0xFF;
  framed[1] = message.length & 0xFF;
  framed.set(message, 2);
  return framed;
}

/** Parse length-prefixed TCP DNS messages from a buffer */
export function deframeTCP(buffer: Uint8Array): { messages: Uint8Array[]; remaining: Uint8Array } {
  const messages: Uint8Array[] = [];
  let offset = 0;

  while (offset + 2 <= buffer.length) {
    const len = (buffer[offset]! << 8) | buffer[offset + 1]!;
    if (offset + 2 + len > buffer.length) break; // incomplete message
    messages.push(buffer.slice(offset + 2, offset + 2 + len));
    offset += 2 + len;
  }

  return {
    messages,
    remaining: buffer.slice(offset),
  };
}

// ─── Pending Query Tracker ────────────────────────────────────

interface PendingQuery {
  queryId: number;
  resolve: (result: { raw: Uint8Array; rtt: number }) => void;
  reject: (err: Error) => void;
  startTime: number;
  timer: ReturnType<typeof setTimeout>;
}

// ─── TCP Transport ────────────────────────────────────────────

export class TCPTransport implements DNSTransport {
  readonly protocol: TransportProtocol = TransportProtocol.TCP;
  protected readonly server: string;
  protected readonly port: number;
  protected readonly timeout: number;
  protected readonly retries: number;
  protected readonly keepAlive: boolean;
  protected readonly keepAliveIdle: number;
  protected readonly pipeline: boolean;

  protected socket: net.Socket | null = null;
  protected receiveBuffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  protected pending = new Map<number, PendingQuery>();
  protected connecting = false;
  protected connectPromise: Promise<net.Socket> | null = null;

  constructor(config: TCPTransportConfig) {
    this.server = config.server;
    this.port = config.port ?? DEFAULT_PORTS[TransportProtocol.TCP];
    this.timeout = config.timeout ?? 5000;
    this.retries = config.retries ?? 2;
    this.keepAlive = config.keepAlive ?? true;
    this.keepAliveIdle = config.keepAliveIdle ?? 10000;
    this.pipeline = config.pipeline ?? true;
  }

  async query(message: Uint8Array, options?: QueryOptions): Promise<TransportResult> {
    const timeout = options?.timeout ?? this.timeout;
    const retries = options?.retries ?? this.retries;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const socket = await this.getConnection();
        const result = await this.sendQuery(socket, message, timeout, options?.signal);

        const response = unpack(result.raw);
        return {
          response,
          raw: result.raw,
          rtt: result.rtt,
          protocol: this.protocol,
          server: this.server,
          port: this.port,
          responseSize: result.raw.length,
        };
      } catch (err) {
        lastError = err as Error;
        if (options?.signal?.aborted) throw err;
        // Reset connection on error
        this.destroySocket();
        if (attempt === retries) break;
      }
    }

    throw lastError ?? new DNSTransportError(
      'query failed after all retries',
      this.protocol,
      this.server,
      this.port,
    );
  }

  protected getConnection(): Promise<net.Socket> {
    if (this.socket && !this.socket.destroyed) {
      return Promise.resolve(this.socket);
    }

    if (this.connectPromise) {
      return this.connectPromise;
    }

    this.connectPromise = this.createConnection();
    return this.connectPromise;
  }

  protected createConnection(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: this.server,
        port: this.port,
      });

      const connectTimeout = setTimeout(() => {
        socket.destroy();
        reject(new DNSTimeoutError(
          this.protocol,
          this.server,
          this.port,
          this.timeout,
        ));
      }, this.timeout);

      socket.once('connect', () => {
        clearTimeout(connectTimeout);
        if (this.keepAlive) {
          socket.setKeepAlive(true, this.keepAliveIdle);
        }
        socket.setNoDelay(true);
        this.socket = socket;
        this.connectPromise = null;
        this.setupSocketHandlers(socket);
        resolve(socket);
      });

      socket.once('error', (err) => {
        clearTimeout(connectTimeout);
        this.connectPromise = null;
        reject(new DNSTransportError(
          err.message,
          this.protocol,
          this.server,
          this.port,
          err,
        ));
      });
    });
  }

  protected setupSocketHandlers(socket: net.Socket): void {
    socket.on('data', (chunk: Buffer) => {
      this.onData(new Uint8Array(chunk));
    });

    socket.on('error', (err) => {
      this.rejectAllPending(new DNSTransportError(
        err.message,
        this.protocol,
        this.server,
        this.port,
        err,
      ));
      this.destroySocket();
    });

    socket.on('close', () => {
      this.rejectAllPending(new DNSTransportError(
        'connection closed',
        this.protocol,
        this.server,
        this.port,
      ));
      this.socket = null;
    });
  }

  protected onData(chunk: Uint8Array): void {
    // Append to buffer
    const merged = new Uint8Array(this.receiveBuffer.length + chunk.length);
    merged.set(this.receiveBuffer);
    merged.set(chunk, this.receiveBuffer.length);
    this.receiveBuffer = merged;

    // Parse complete messages
    const { messages, remaining } = deframeTCP(this.receiveBuffer);
    this.receiveBuffer = remaining;

    for (const msg of messages) {
      if (msg.length < 2) continue;
      const responseId = (msg[0]! << 8) | msg[1]!;
      const pending = this.pending.get(responseId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(responseId);
        pending.resolve({
          raw: msg,
          rtt: performance.now() - pending.startTime,
        });
      }
    }
  }

  protected sendQuery(
    socket: net.Socket,
    message: Uint8Array,
    timeout: number,
    signal?: AbortSignal,
  ): Promise<{ raw: Uint8Array; rtt: number }> {
    return new Promise((resolve, reject) => {
      if (message.length < 2) {
        reject(new DNSTransportError(
          'message too short',
          this.protocol,
          this.server,
          this.port,
        ));
        return;
      }

      const queryId = (message[0]! << 8) | message[1]!;
      const startTime = performance.now();

      const timer = setTimeout(() => {
        this.pending.delete(queryId);
        reject(new DNSTimeoutError(
          this.protocol,
          this.server,
          this.port,
          timeout,
        ));
      }, timeout);

      // Abort signal
      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          this.pending.delete(queryId);
          reject(new DNSTransportError(
            'query aborted',
            this.protocol,
            this.server,
            this.port,
          ));
        };
        if (signal.aborted) {
          clearTimeout(timer);
          onAbort();
          return;
        }
        signal.addEventListener('abort', onAbort, { once: true });
      }

      this.pending.set(queryId, {
        queryId,
        resolve,
        reject,
        startTime,
        timer,
      });

      // Send length-prefixed message
      const framed = frameTCP(message);
      socket.write(Buffer.from(framed), (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(queryId);
          reject(new DNSTransportError(
            `send failed: ${err.message}`,
            this.protocol,
            this.server,
            this.port,
            err,
          ));
        }
      });
    });
  }

  protected rejectAllPending(err: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pending.clear();
  }

  protected destroySocket(): void {
    if (this.socket) {
      try { this.socket.destroy(); } catch { /* ignore */ }
      this.socket = null;
    }
    this.receiveBuffer = new Uint8Array(0);
  }

  async close(): Promise<void> {
    this.rejectAllPending(new DNSTransportError(
      'transport closed',
      this.protocol,
      this.server,
      this.port,
    ));
    this.destroySocket();
  }
}
