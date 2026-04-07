import { useEffect, useState, useRef } from 'react';
import type { ResolveResult, Listing, StatusResult, EventsFilter, EventsResult } from 'zcashname-sdk';
import { useZNS } from './provider';

// ── Shared async-query state shape ──────────────────────────────────────────

interface QueryState<T> {
  data: T;
  loading: boolean;
  error: Error | null;
}

// ── useResolve ──────────────────────────────────────────────────────────────

/**
 * Resolve a name (or address, or prefix) via the ZNS indexer.
 *
 * Refetches whenever `query` changes. Returns `null` while loading or if the
 * name is not registered.
 */
export function useResolve(query: string): QueryState<ResolveResult | ResolveResult[] | null> {
  const { client, ready } = useZNS();
  const [state, setState] = useState<QueryState<ResolveResult | ResolveResult[] | null>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!ready || !client) {
      setState((s) => ({ ...s, loading: true }));
      return;
    }

    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    client
      .resolve(query)
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            data: null,
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, ready, query]);

  return state;
}

// ── useListings ─────────────────────────────────────────────────────────────

/**
 * Fetch all names currently listed for sale.
 *
 * Refetches when the client connects (or reconnects).
 */
export function useListings(): QueryState<Listing[]> {
  const { client, ready } = useZNS();
  const [state, setState] = useState<QueryState<Listing[]>>({
    data: [],
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!ready || !client) {
      setState((s) => ({ ...s, loading: true }));
      return;
    }

    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    client
      .listings()
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            data: [],
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, ready]);

  return state;
}

// ── useStatus ───────────────────────────────────────────────────────────────

/**
 * Fetch the indexer status (sync height, pricing, registration count, etc.).
 */
export function useStatus(): QueryState<StatusResult | null> {
  const { client, ready } = useZNS();
  const [state, setState] = useState<QueryState<StatusResult | null>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!ready || !client) {
      setState((s) => ({ ...s, loading: true }));
      return;
    }

    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    client
      .status()
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            data: null,
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, ready]);

  return state;
}

// ── useEvents ───────────────────────────────────────────────────────────────

/**
 * Fetch events from the indexer, optionally filtered by name, action, height,
 * etc. Refetches when the filter object reference changes -- use `useMemo`
 * on the caller side to keep it stable when the fields haven't changed.
 */
export function useEvents(filter?: EventsFilter): QueryState<EventsResult | null> {
  const { client, ready } = useZNS();
  const [state, setState] = useState<QueryState<EventsResult | null>>({
    data: null,
    loading: true,
    error: null,
  });

  // Stabilise the filter reference: only re-run the effect when the
  // serialised value actually changes, so callers don't need useMemo.
  const filterJson = JSON.stringify(filter ?? {});
  const filterRef = useRef(filter);
  if (JSON.stringify(filterRef.current ?? {}) !== filterJson) {
    filterRef.current = filter;
  }
  const stableFilter = filterRef.current;

  useEffect(() => {
    if (!ready || !client) {
      setState((s) => ({ ...s, loading: true }));
      return;
    }

    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    client
      .events(stableFilter)
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            data: null,
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, ready, filterJson]);

  return state;
}

// ── useIsAvailable ──────────────────────────────────────────────────────────

/**
 * Check whether a name is available for registration.
 *
 * Returns `null` while loading. `true` if the name is unregistered, `false`
 * if it's taken.
 */
export function useIsAvailable(name: string): {
  available: boolean | null;
  loading: boolean;
  error: Error | null;
} {
  const { client, ready } = useZNS();
  const [state, setState] = useState<{
    available: boolean | null;
    loading: boolean;
    error: Error | null;
  }>({
    available: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!ready || !client) {
      setState((s) => ({ ...s, loading: true }));
      return;
    }

    // Skip the request for empty names.
    if (!name) {
      setState({ available: null, loading: false, error: null });
      return;
    }

    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    client
      .isAvailable(name)
      .then((available) => {
        if (!cancelled) setState({ available, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            available: null,
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, ready, name]);

  return state;
}
