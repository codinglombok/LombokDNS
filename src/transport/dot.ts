/**
 * LombokDNS — DNS over TLS (DoT) Transport
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * RFC 7858 — DNS over Transport Layer Security.
 * Extends TCP transport with TLS encryption.
 *
 * Features:
 *  - TLS 1.2/1.3 encryption
 *  - Certificate validation with configurable CA
 *  - Server Name Indication (SNI)
 *  - Connection reuse and pipelining (inherited from TCP)
 *  - Session resumption (TLS layer)
 */

import * as tls from 'node:tls';
import * as net from 'node:net';
import { TCPTransport } from './tcp.js';
import {
  type DoTTransportConfig,
  TransportProtocol,
  DEFAULT_PORTS,
  DNSTransportError,
  DNSTimeoutError,
} from './types.js';

// ─── DoT Transport ────────────────────────────────────────────

export class DoTTransport extends TCPTransport {
  override readonly protocol: TransportProtocol = TransportProtocol.DOT;
  private readonly servername: string;
  private readonly ca?: string | string[];
  private readonly rejectUnauthorized: boolean;

  constructor(config: DoTTransportConfig) {
    super({
      ...config,
      port: config.port ?? DEFAULT_PORTS[TransportProtocol.DOT],
    });
    this.servername = config.servername ?? config.server;
    this.ca = config.ca;
    this.rejectUnauthorized = config.rejectUnauthorized ?? true;
  }

  protected override createConnection(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: this.server,
        port: this.port,
        servername: this.servername,
        ca: this.ca,
        rejectUnauthorized: this.rejectUnauthorized,
        minVersion: 'TLSv1.2',
      });

      const connectTimeout = setTimeout(() => {
        socket.destroy();
        reject(new DNSTimeoutError(
          TransportProtocol.DOT,
          this.server,
          this.port,
          this.timeout,
        ));
      }, this.timeout);

      socket.once('secureConnect', () => {
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
          TransportProtocol.DOT,
          this.server,
          this.port,
          err,
        ));
      });
    });
  }
}
