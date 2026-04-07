import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { createClient, type ZNSClient } from 'zcashname-sdk';

// ── Context shape ───────────────────────────────────────────────────────────

interface ZNSContextValue {
  client: ZNSClient | null;
  ready: boolean;
  error: Error | null;
}

const ZNSContext = createContext<ZNSContextValue>({
  client: null,
  ready: false,
  error: null,
});

// ── Provider ────────────────────────────────────────────────────────────────

export interface ZNSProviderProps {
  /** JSON-RPC endpoint URL. Falls back to the SDK default if omitted. */
  url?: string;
  /** Skip UIVK verification on connect (useful for custom/test indexers). */
  skipVerify?: boolean;
  children: ReactNode;
}

/**
 * Wrap your app (or a subtree) with `<ZNSProvider>` to create a shared
 * `ZNSClient` instance that every hook can consume.
 *
 * The client is created once when the provider mounts (or when `url` /
 * `skipVerify` change). While connecting, `ready` is false. If the
 * connection fails, `error` is set and `client` remains null.
 */
export function ZNSProvider({ url, skipVerify, children }: ZNSProviderProps) {
  const [state, setState] = useState<ZNSContextValue>({
    client: null,
    ready: false,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;

    setState({ client: null, ready: false, error: null });

    createClient(url, { skipVerify })
      .then((client) => {
        if (!cancelled) setState({ client, ready: true, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            client: null,
            ready: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [url, skipVerify]);

  return <ZNSContext.Provider value={state}>{children}</ZNSContext.Provider>;
}

// ── Hook ────────────────────────────────────────────────────────────────────

/**
 * Access the ZNS client directly and its connection status.
 *
 * ```tsx
 * const { client, ready, error } = useZNS();
 * if (ready) {
 *   const result = await client!.resolve("julianito");
 * }
 * ```
 */
export function useZNS(): ZNSContextValue {
  const ctx = useContext(ZNSContext);
  if (ctx === undefined) {
    throw new Error('useZNS must be used within a <ZNSProvider>');
  }
  return ctx;
}
