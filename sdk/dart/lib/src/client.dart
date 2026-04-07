import 'package:http/http.dart' as http;

import 'constants.dart';
import 'errors.dart';
import 'rpc.dart' as rpc_lib;
import 'types.dart';

/// Async client for the Zcash Name System JSON-RPC API.
class ZnsClient {
  /// The JSON-RPC endpoint URL.
  final String url;

  /// Whether the indexer UIVK was verified against known UIVKs.
  bool verified;

  int _nextId = 1;
  final http.Client _http;

  ZnsClient._(this.url, this.verified, this._http);

  /// Create a new client, optionally verifying the indexer UIVK.
  ///
  /// Unless [skipVerify] is true, the client calls `status()` on creation
  /// and checks that the returned UIVK is in [knownUivks].
  static Future<ZnsClient> create({
    String url = defaultUrl,
    bool skipVerify = false,
  }) async {
    final httpClient = http.Client();
    final client = ZnsClient._(url, false, httpClient);

    if (!skipVerify) {
      final s = await client.status();
      if (!knownUivks.contains(s.uivk)) {
        client.dispose();
        throw ZnsError(
          ZnsErrorType.uivkMismatch,
          'UIVK mismatch: indexer returned "${s.uivk.substring(0, 20)}..." '
              'which is not a known ZNS instance',
        );
      }
      client.verified = true;
    }

    return client;
  }

  Future<dynamic> _call(String method, [Map<String, dynamic>? params]) async {
    final result = await rpc_lib.rpc(
      _http,
      url,
      method,
      params: params,
      id: _nextId++,
    );
    return result;
  }

  /// Resolve a name or address.
  ///
  /// Returns a single [ResolveResult] for name queries, a `List<ResolveResult>`
  /// for address queries, or `null` if not found.
  Future<dynamic> resolve(String query) async {
    final result = await _call('resolve', {'query': query});
    if (result == null) return null;
    if (result is List) {
      return result
          .map((e) => ResolveResult.fromJson(e as Map<String, dynamic>))
          .toList();
    }
    return ResolveResult.fromJson(result as Map<String, dynamic>);
  }

  /// Resolve a single ZNS name.
  ///
  /// Returns `null` if the name is not registered.
  Future<ResolveResult?> resolveName(String name) async {
    final result = await resolve(name);
    if (result == null || result is List) return null;
    return result as ResolveResult;
  }

  /// Resolve all names registered to an address.
  Future<List<ResolveResult>> resolveAddress(String address) async {
    final result = await resolve(address);
    if (result == null) return [];
    if (result is List<ResolveResult>) return result;
    return [result as ResolveResult];
  }

  /// Return all names currently listed for sale.
  Future<List<Listing>> listings() async {
    final result = await _call('list_for_sale');
    final listingsData = result['listings'] as List<dynamic>? ?? [];
    return listingsData
        .map((e) => Listing.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Return the current indexer status.
  Future<StatusResult> status() async {
    final result = await _call('status');
    return StatusResult.fromJson(result as Map<String, dynamic>);
  }

  /// Query the event log with optional filters.
  Future<EventsResult> events([EventsFilter? filter]) async {
    final params = filter?.toJson() ?? <String, dynamic>{};
    final result = await _call('events', params);
    return EventsResult.fromJson(result as Map<String, dynamic>);
  }

  /// Check whether a name is available for registration.
  Future<bool> isAvailable(String name) async {
    final result = await resolve(name);
    return result == null;
  }

  /// Return the current nonce for a registered name, or `null`.
  Future<int?> getNonce(String name) async {
    final result = await resolveName(name);
    return result?.nonce;
  }

  /// Close the underlying HTTP client.
  void dispose() {
    _http.close();
  }
}
