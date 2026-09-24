/**
 * LombokDNS — DNS over HTTPS (DoH) Transport
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * RFC 8484 — DNS Queries over HTTPS.
 *
 * Features:
 *  - HTTP POST with application/dns-message (binary wire format)
 *  - HTTP GET with base64url-encoded query (RFC 8484 §4.1)
 *  - JSON wire format support (RFC 8427, application/dns-json)
 *  - Custom headers and authentication support
 *  - Works with any DoH endpoint (Google, Cloudflare, Quad9, etc.)
 *  - Browser-compatible (uses fetch API when available)
 */

import { unpack } from '../core/message.js';
import { RRType, RRClass, type DNSMessage } from '../core/types.js';
import { base64UrlEncode } from '../utils/encoding.js';
import {
  type DNSTransport,
  type TransportResult,
  type QueryOptions,
  type DoHTransportConfig,
  TransportProtocol,
  DNSTransportError,
  DNSTimeoutError,
} from './types.js';

// ─── Content Types ────────────────────────────────────────────

const DNS_MESSAGE_TYPE = 'application/dns-message';
const DNS_JSON_TYPE = 'application/dns-json';

// ─── DoH Transport ────────────────────────────────────────────

export class DoHTransport implements DNSTransport {
  readonly protocol = TransportProtocol.DOH;
  private readonly url: string;
  private readonly method: 'POST' | 'GET';
  private readonly headers: Record<string, string>;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly server: string;
  private readonly port: number;
  private readonly useJson: boolean;

  constructor(config: DoHTransportConfig) {
    this.url = config.url;
    this.method = config.method ?? 'POST';
    this.headers = config.headers ?? {};
    this.timeout = config.timeout ?? 5000;
    this.retries = config.retries ?? 2;
    this.useJson = config.useJson ?? false;

    // Extract server/port from URL for result metadata
    try {
      const parsed = new URL(config.url);
      this.server = config.server ?? parsed.hostname;
      this.port = config.port ?? (parsed.port ? parseInt(parsed.port) : 443);
    } catch {
      this.server = config.server ?? config.url;
      this.port = config.port ?? 443;
    }
  }

  async query(message: Uint8Array, options?: QueryOptions): Promise<TransportResult> {
    const timeout = options?.timeout ?? this.timeout;
    const retries = options?.retries ?? this.retries;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await this.sendQuery(message, timeout, options?.signal);
      } catch (err) {
        lastError = err as Error;
        if (options?.signal?.aborted) throw err;
        if (attempt === retries) break;
      }
    }

    throw lastError ?? new DNSTransportError(
      'query failed after all retries',
      TransportProtocol.DOH,
      this.server,
      this.port,
    );
  }

  private async sendQuery(
    message: Uint8Array,
    timeout: number,
    signal?: AbortSignal,
  ): Promise<TransportResult> {
    const startTime = performance.now();

    // Create timeout abort controller
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    // Link external signal
    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer);
        throw new DNSTransportError(
          'query aborted',
          TransportProtocol.DOH,
          this.server,
          this.port,
        );
      }
      signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    try {
      const fetchFn = this.getFetch();
      let response: Response;

      if (this.method === 'GET') {
        // RFC 8484 §4.1 — GET with dns parameter (base64url)
        const dnsParam = base64UrlEncode(message);
        const separator = this.url.includes('?') ? '&' : '?';
        const url = `${this.url}${separator}dns=${dnsParam}`;

        response = await fetchFn(url, {
          method: 'GET',
          headers: {
            'Accept': this.useJson ? DNS_JSON_TYPE : DNS_MESSAGE_TYPE,
            ...this.headers,
          },
          signal: controller.signal,
        });
      } else {
        // RFC 8484 §4.1 — POST with binary body
        response = await fetchFn(this.url, {
          method: 'POST',
          headers: {
            'Content-Type': DNS_MESSAGE_TYPE,
            'Accept': this.useJson ? DNS_JSON_TYPE : DNS_MESSAGE_TYPE,
            ...this.headers,
          },
          body: message as unknown as BodyInit,
          signal: controller.signal,
        });
      }

      clearTimeout(timer);
      const rtt = performance.now() - startTime;

      if (!response.ok) {
        throw new DNSTransportError(
          `HTTP ${response.status}: ${response.statusText}`,
          TransportProtocol.DOH,
          this.server,
          this.port,
        );
      }

      const contentType = response.headers.get('content-type') ?? '';

      if (contentType.includes(DNS_JSON_TYPE) || this.useJson) {
        // JSON wire format — parse and convert to standard result
        const json = await response.json();
        return this.parseJsonResponse(json, rtt);
      }

      // Binary wire format
      const buffer = await response.arrayBuffer();
      const raw = new Uint8Array(buffer);
      const parsed = unpack(raw);

      return {
        response: parsed,
        raw,
        rtt,
        protocol: TransportProtocol.DOH,
        server: this.server,
        port: this.port,
        responseSize: raw.length,
      };
    } catch (err) {
      clearTimeout(timer);

      if ((err as Error).name === 'AbortError') {
        if (signal?.aborted) {
          throw new DNSTransportError(
            'query aborted',
            TransportProtocol.DOH,
            this.server,
            this.port,
          );
        }
        throw new DNSTimeoutError(
          TransportProtocol.DOH,
          this.server,
          this.port,
          timeout,
        );
      }

      if (err instanceof DNSTransportError) throw err;

      throw new DNSTransportError(
        (err as Error).message,
        TransportProtocol.DOH,
        this.server,
        this.port,
        err as Error,
      );
    }
  }

  /**
   * Parse JSON wire format response (RFC 8427).
   * Used by providers like Google DNS (dns.google) and Cloudflare (cloudflare-dns.com).
   */
  private parseJsonResponse(
    json: Record<string, unknown>,
    rtt: number,
  ): TransportResult {
    // JSON format from major providers follows this structure:
    // { Status, TC, RD, RA, AD, CD, Question, Answer, Authority, Additional }
    const questions = ((json.Question as Array<Record<string, unknown>>) ?? []).map(q => ({
      name: q.name as string,
      type: q.type as RRType,
      class: RRClass.IN,
    }));

    const parseRecords = (records: Array<Record<string, unknown>> | undefined) =>
      (records ?? []).map(r => ({
        name: r.name as string,
        type: r.type as RRType,
        class: RRClass.IN,
        ttl: (r.TTL as number) ?? 0,
        rdlength: 0,
        rdata: { raw: r.data as string },
      }));

    const message = {
      header: {
        id: 0,
        flags: 0x8000 | ((json.TC ? 0x200 : 0) | (json.RD ? 0x100 : 0) |
               (json.RA ? 0x80 : 0) | (json.AD ? 0x20 : 0) | (json.CD ? 0x10 : 0) |
               ((json.Status as number) ?? 0)),
        qdcount: questions.length,
        ancount: ((json.Answer as unknown[]) ?? []).length,
        nscount: ((json.Authority as unknown[]) ?? []).length,
        arcount: ((json.Additional as unknown[]) ?? []).length,
      },
      questions,
      answers: parseRecords(json.Answer as Array<Record<string, unknown>>),
      authorities: parseRecords(json.Authority as Array<Record<string, unknown>>),
      additionals: parseRecords(json.Additional as Array<Record<string, unknown>>),
    };

    return {
      response: message as DNSMessage,
      raw: new Uint8Array(0), // JSON format — no wire bytes
      rtt,
      protocol: TransportProtocol.DOH,
      server: this.server,
      port: this.port,
      responseSize: JSON.stringify(json).length,
    };
  }

  /**
   * Get the fetch function (works in Node.js 18+, Deno, Bun, browsers).
   */
  private getFetch(): typeof globalThis.fetch {
    if (typeof globalThis.fetch === 'function') {
      return globalThis.fetch;
    }
    throw new DNSTransportError(
      'fetch API not available — requires Node.js 18+, Deno, Bun, or browser',
      TransportProtocol.DOH,
      this.server,
      this.port,
    );
  }

  async close(): Promise<void> {
    // HTTP is stateless per-request — nothing to close
  }
}

// ─── Well-Known DoH Endpoints ─────────────────────────────────

export const DoHEndpoints = {
  GOOGLE:        'https://dns.google/dns-query',
  CLOUDFLARE:    'https://cloudflare-dns.com/dns-query',
  QUAD9:         'https://dns.quad9.net/dns-query',
  OPENDNS:       'https://doh.opendns.com/dns-query',
  ADGUARD:       'https://dns.adguard-dns.com/dns-query',
  NEXTDNS:       'https://dns.nextdns.io',
  MULLVAD:       'https://doh.mullvad.net/dns-query',
  CONTROLD:      'https://freedns.controld.com/p0',
} as const;
