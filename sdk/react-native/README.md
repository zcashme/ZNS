# zcashname-sdk-react-native

React Native hooks and provider for the Zcash Name System (ZNS). Wraps the core [`zcashname-sdk`](https://www.npmjs.com/package/zcashname-sdk) with a context provider and data-fetching hooks that follow standard React patterns.

## Install

```bash
npm install zcashname-sdk-react-native zcashname-sdk
```

`react` and `react-native` are peer dependencies (you already have them).

## Quick start

### 1. Wrap your app with `<ZNSProvider>`

```tsx
import { ZNSProvider } from 'zcashname-sdk-react-native';

export default function App() {
  return (
    <ZNSProvider>
      <HomeScreen />
    </ZNSProvider>
  );
}
```

Pass `url` to point at a custom indexer, or `skipVerify` to skip UIVK verification:

```tsx
<ZNSProvider url="https://my-indexer.example.com" skipVerify>
  <App />
</ZNSProvider>
```

### 2. Use hooks in components

```tsx
import { useResolve, useIsAvailable, useListings, useStatus, useEvents } from 'zcashname-sdk-react-native';

function ResolveName() {
  const { data, loading, error } = useResolve('julianito');

  if (loading) return <Text>Loading...</Text>;
  if (error) return <Text>Error: {error.message}</Text>;
  if (!data) return <Text>Not found</Text>;

  const result = Array.isArray(data) ? data[0] : data;
  return <Text>{result.name} -> {result.address}</Text>;
}

function CheckAvailability() {
  const { available, loading } = useIsAvailable('satoshi');

  if (loading) return <Text>Checking...</Text>;
  return <Text>{available ? 'Available!' : 'Taken'}</Text>;
}

function MarketplaceListings() {
  const { data: listings, loading } = useListings();

  if (loading) return <Text>Loading listings...</Text>;
  return (
    <FlatList
      data={listings}
      renderItem={({ item }) => (
        <Text>{item.name} - {item.price} zats</Text>
      )}
    />
  );
}

function IndexerStatus() {
  const { data: status, loading } = useStatus();

  if (loading || !status) return <Text>Loading...</Text>;
  return <Text>Synced to height {status.synced_height}, {status.registered} names registered</Text>;
}

function RecentClaims() {
  const filter = useMemo(() => ({ action: 'CLAIM', limit: 10 }), []);
  const { data, loading } = useEvents(filter);

  if (loading || !data) return <Text>Loading...</Text>;
  return (
    <FlatList
      data={data.events}
      renderItem={({ item }) => (
        <Text>{item.name} claimed at height {item.height}</Text>
      )}
    />
  );
}
```

### 3. Direct client access

For operations that aren't covered by the hooks (e.g. building memos, constructing URIs), use `useZNS()` to get the client directly:

```tsx
import { useZNS, buildClaimMemo, buildZcashUri, claimCost } from 'zcashname-sdk-react-native';

function ClaimButton({ name }: { name: string }) {
  const { client, ready } = useZNS();

  async function handleClaim() {
    if (!ready || !client) return;

    const status = await client.status();
    const cost = claimCost(name, status.pricing!.tiers);
    const memo = buildClaimMemo(name);
    const uri = buildZcashUri(status.uivk, cost, memo);

    // Open URI in wallet...
  }

  return <Button title={`Claim ${name}`} onPress={handleClaim} disabled={!ready} />;
}
```

## API

### `<ZNSProvider>`

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `url` | `string` | SDK default | JSON-RPC endpoint URL |
| `skipVerify` | `boolean` | `false` | Skip UIVK verification on connect |
| `children` | `ReactNode` | -- | App subtree |

### `useZNS()`

Returns `{ client: ZNSClient | null, ready: boolean, error: Error | null }`.

### `useResolve(query: string)`

Returns `{ data: ResolveResult | ResolveResult[] | null, loading: boolean, error: Error | null }`.

### `useListings()`

Returns `{ data: Listing[], loading: boolean, error: Error | null }`.

### `useStatus()`

Returns `{ data: StatusResult | null, loading: boolean, error: Error | null }`.

### `useEvents(filter?: EventsFilter)`

Returns `{ data: EventsResult | null, loading: boolean, error: Error | null }`.

The filter is internally stabilised via JSON serialisation, so you don't strictly need `useMemo` -- but it's still recommended for clarity.

### `useIsAvailable(name: string)`

Returns `{ available: boolean | null, loading: boolean, error: Error | null }`.

## Re-exports

Everything from `zcashname-sdk` is re-exported, so you can import types, utilities, memo builders, and ZIP-321 helpers directly:

```tsx
import { isValidName, claimCost, buildZcashUri, type Registration } from 'zcashname-sdk-react-native';
```

## License

MIT
