import type { ResolveResult, Listing, StatusResult, ListForSaleResult, EventsFilter, EventsResult } from "./types.js";
import { ZNSError, ErrorType } from "./errors.js";
import { DEFAULT_URL, UFVK } from "./constants.js";
import { rpc } from "./rpc.js";

export interface ClientOptions {
  skipVerify?: boolean;
}

export interface ZNSClient {
  readonly url: string;
  readonly verified: boolean;
  resolve(query: string): Promise<ResolveResult | null>;
  listings(): Promise<Listing[]>;
  status(): Promise<StatusResult>;
  events(filter?: EventsFilter): Promise<EventsResult>;
  isAvailable(name: string): Promise<boolean>;
  getNonce(name: string): Promise<number | null>;
}

export async function createClient(
  url: string = DEFAULT_URL,
  options: ClientOptions = {},
): Promise<ZNSClient> {
  let nextId = 1;
  let verified = false;

  async function call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    return rpc<T>(url, method, params, nextId++);
  }

  if (!options.skipVerify) {
    const s = await call<StatusResult>("status");
    if (s.ufvk !== UFVK) {
      throw new ZNSError(
        ErrorType.UfvkMismatch,
        `UFVK mismatch: indexer returned "${s.ufvk.slice(0, 20)}..." but expected "${UFVK.slice(0, 20)}..."`,
      );
    }
    verified = true;
  }

  const client: ZNSClient = {
    url,
    verified,

    async resolve(query: string) {
      return call<ResolveResult | null>("resolve", { query });
    },

    async listings() {
      const result = await call<ListForSaleResult>("list_for_sale");
      return result.listings;
    },

    async status() {
      return call<StatusResult>("status");
    },

    async isAvailable(name: string) {
      const result = await client.resolve(name);
      return result === null;
    },

    async events(filter: EventsFilter = {}) {
      return call<EventsResult>("events", filter as Record<string, unknown>);
    },

    async getNonce(name: string) {
      const result = await client.resolve(name);
      return result?.nonce ?? null;
    },
  };

  return client;
}
