import 'dart:math' as math;

import 'package:http/http.dart' as http;

import 'actions.dart';
import 'crypto.dart' as crypto;
import 'exceptions.dart';
import 'models.dart';
import 'networks.dart';
import 'payload_validation.dart' as payload_validation;
import 'prepared_actions.dart';
import 'rpc.dart';
import 'validators.dart' as v;
import 'zip321.dart' as zip321;

/// Async client for the Zcash Name System JSON-RPC API.
class ZNS {
  /// Target network for this client.
  final Network network;

  /// JSON-RPC endpoint URL.
  final Uri url;

  final RpcClient _rpc;
  bool _verified = false;

  ZNS._(this.network, this.url, this._rpc);

  /// Create a new ZNS client. Defaults to [Network.testnet]. If [url] is
  /// supplied, it overrides the network's default URL.
  ///
  /// [timeout] controls how long each RPC call waits before throwing a
  /// [TimeoutException]. Defaults to 10 seconds.
  factory ZNS({
    Network network = Network.testnet,
    Uri? url,
    http.Client? httpClient,
    Duration? timeout,
  }) {
    final resolvedUrl = url ?? networks[network]!.url;
    return ZNS._(
      network,
      resolvedUrl,
      RpcClient(resolvedUrl, httpClient: httpClient, timeout: timeout),
    );
  }

  /// Verify that the connected server's UIVK matches the known UIVK for
  /// [network]. Throws [StateError] on mismatch.
  Future<void> verify() async {
    final s = await status();
    final expected = networks[network]!.uivk;
    if (s.uivk != expected) {
      final preview = s.uivk.substring(0, math.min(20, s.uivk.length));
      throw StateError(
        'UIVK mismatch: indexer returned "$preview..." '
        'which is not a known ZNS instance',
      );
    }
    _verified = true;
  }

  /// True once [verify] has been called and the UIVK matched.
  bool get verified => _verified;

  /// Registry address for the current network.
  String get registryAddress => networks[network]!.registryAddress;

  /// Close the underlying HTTP client. Only needed if you supplied your own.
  void close() => _rpc.close();

  // ── Reads ─────────────────────────────────────────────────────────────────

  /// Current indexer status, including pricing.
  Future<Status> status() async {
    final raw = await _rpc.call<Map<String, dynamic>>('status');
    return Status.fromJson(raw);
  }

  /// Resolve a name. Returns `null` if not registered.
  ///
  /// [name] is normalized to lowercase before querying the indexer, so
  /// `resolveName('Alice')` and `resolveName('alice')` are equivalent.
  Future<Registration?> resolveName(String name) async {
    final raw = await _rpc
        .call<Map<String, dynamic>?>('resolve', {'query': name.toLowerCase()});
    return raw == null ? null : Registration.fromJson(raw);
  }

  /// Resolve a Unified Address to all names pointing to it. Returns an empty
  /// list if none. Pagination via [limit] (server default 50, max 500) and
  /// [offset] (default 0).
  Future<List<Registration>> resolveAddress(
    String address, {
    int? limit,
    int? offset,
  }) async {
    final params = <String, dynamic>{'query': address};
    if (limit != null) params['limit'] = limit;
    if (offset != null) params['offset'] = offset;
    final raw = await _rpc.call<List<dynamic>>('resolve', params);
    return raw
        .map((e) => Registration.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// List all registered names (useful for explorers/browsers). Same
  /// pagination as [resolveAddress].
  Future<List<Registration>> listAllRegistrations({int? limit, int? offset}) async {
    final params = <String, dynamic>{'query': ''};
    if (limit != null) params['limit'] = limit;
    if (offset != null) params['offset'] = offset;
    final raw = await _rpc.call<List<dynamic>>('resolve', params);
    return raw
        .map((e) => Registration.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Check if [name] is available. Returns `false` immediately for
  /// syntactically invalid names without hitting the server.
  Future<bool> isAvailable(String name) async {
    if (!v.isValidName(name)) return false;
    final r = await resolveName(name);
    return r == null;
  }

  /// Paginated listings.
  Future<ListingsResult> listings({int? limit, int? offset}) async {
    final params = <String, dynamic>{};
    if (limit != null) params['limit'] = limit;
    if (offset != null) params['offset'] = offset;
    final raw = await _rpc.call<Map<String, dynamic>>('listings', params);
    return ListingsResult.fromJson(raw);
  }

  /// Query the event log.
  Future<EventsResult> events([EventsFilter? filter]) async {
    final params = filter?.toJson() ?? const <String, dynamic>{};
    final raw = await _rpc.call<Map<String, dynamic>>('events', params);
    return EventsResult.fromJson(raw);
  }

  // ── Validation re-exports ────────────────────────────────────────────────

  bool isValidName(String name) => v.isValidName(name);
  bool isValidUnifiedAddress(String address) =>
      v.isValidUnifiedAddress(address);
  bool isValidTransparentAddress(String address) =>
      v.isValidTransparentAddress(address);

  /// Validate a signing payload string against the ZNS memo format spec.
  /// See [payload_validation.validatePayload] for details.
  PayloadValidationResult validatePayload(String payload) =>
      payload_validation.validatePayload(payload);

  // ── Signature verification ───────────────────────────────────────────────

  /// Verify a listing's signature. Uses [Listing.pubkey] if set, otherwise
  /// falls back to [adminPubkey] (from [Status.adminPubkey]).
  Future<bool> verifyListing(Listing listing, String adminPubkey) {
    final pubkey = listing.pubkey ?? adminPubkey;
    final payload =
        'LIST:${listing.name}:${listing.price}:${listing.payTaddr}:${listing.nonce}';
    return crypto.verifyEd25519(payload, listing.signature, pubkey);
  }

  /// Verify a registration's signature.
  Future<bool> verifyRegistration(
      Registration reg, String adminPubkey) async {
    final sig = reg.signature;
    if (sig == null) return false;
    final payload = _registrationPayload(reg);
    if (payload == null) return false;
    final pubkey = reg.pubkey ?? adminPubkey;
    return crypto.verifyEd25519(payload, sig, pubkey);
  }

  /// Verify a sovereign-key signature before submitting a transaction.
  /// Returns `false` on any decode error or mismatch; never throws.
  Future<bool> verifySovereignSignature(
    String payload,
    String signatureBase64,
    String pubkeyBase64,
  ) =>
      crypto.verifyEd25519(payload, signatureBase64, pubkeyBase64);

  // ── Pricing helpers ──────────────────────────────────────────────────────

  /// Cost in zatoshis to claim a name of [nameLength]. Returns `null` when
  /// [pricing.tiers] is empty.
  int? claimCost(int nameLength, Pricing pricing) {
    if (pricing.tiers.isEmpty) return null;
    final idx = (nameLength - 1).clamp(0, pricing.tiers.length - 1);
    return pricing.tiers[idx];
  }

  /// Listing commission in zatoshis (10% of the minimum pricing tier).
  /// Uses integer division to keep the result in [int].
  int? listCommissionFor(Pricing pricing) {
    if (pricing.tiers.isEmpty) return null;
    return pricing.tiers.reduce(math.min) ~/ 10;
  }

  // ── ZIP-321 helper ───────────────────────────────────────────────────────

  zip321.Zip321Parts parseZip321Uri(String uri) => zip321.parseZip321Uri(uri);

  // ── Prepared actions ─────────────────────────────────────────────────────

  PreparedClaim prepareClaim(String name, String address, int cost) {
    _requireValidName(name);
    if (!v.isValidUnifiedAddress(address)) {
      throw InvalidAddressException(address, ZcashAddressKind.unified);
    }
    return PreparedClaim(
      name: name,
      address: address,
      cost: cost,
      registryAddress: registryAddress,
    );
  }

  PreparedList prepareList(
      String name, int price, String payTaddr, int nonce) {
    _requireValidName(name);
    if (!v.isValidTransparentAddress(payTaddr)) {
      throw InvalidAddressException(payTaddr, ZcashAddressKind.transparent);
    }
    return PreparedList(
      name: name,
      price: price,
      payTaddr: payTaddr,
      nonce: nonce,
      registryAddress: registryAddress,
    );
  }

  PreparedDelist prepareDelist(String name, int nonce) {
    _requireValidName(name);
    return PreparedDelist(
      name: name,
      nonce: nonce,
      registryAddress: registryAddress,
    );
  }

  PreparedUpdate prepareUpdate(String name, String newAddress, int nonce) {
    _requireValidName(name);
    if (!v.isValidUnifiedAddress(newAddress)) {
      throw InvalidAddressException(newAddress, ZcashAddressKind.unified);
    }
    return PreparedUpdate(
      name: name,
      newAddress: newAddress,
      nonce: nonce,
      registryAddress: registryAddress,
    );
  }

  PreparedBuy prepareBuy(String name, String buyerAddress, int price) {
    _requireValidName(name);
    if (!v.isValidUnifiedAddress(buyerAddress)) {
      throw InvalidAddressException(buyerAddress, ZcashAddressKind.unified);
    }
    return PreparedBuy(
      name: name,
      buyerAddress: buyerAddress,
      price: price,
      registryAddress: registryAddress,
    );
  }

  PreparedRelease prepareRelease(String name, int nonce) {
    _requireValidName(name);
    return PreparedRelease(
      name: name,
      nonce: nonce,
      registryAddress: registryAddress,
    );
  }

  PreparedSetPrice prepareSetPrice(List<int> prices, int nonce) {
    return PreparedSetPrice(
      prices: prices,
      nonce: nonce,
      registryAddress: registryAddress,
    );
  }

  // ── Private ──────────────────────────────────────────────────────────────

  void _requireValidName(String name) {
    if (!v.isValidName(name)) {
      throw InvalidNameException(name);
    }
  }

  String? _registrationPayload(Registration reg) {
    switch (reg.lastAction) {
      case ZnsAction.claim:
        return 'CLAIM:${reg.name}:${reg.address}';
      case ZnsAction.buy:
        return 'BUY:${reg.name}:${reg.address}';
      case ZnsAction.update:
        return 'UPDATE:${reg.name}:${reg.address}:${reg.nonce}';
      case ZnsAction.delist:
        return 'DELIST:${reg.name}:${reg.nonce}';
      case ZnsAction.release:
        return 'RELEASE:${reg.name}:${reg.nonce}';
      case ZnsAction.list:
      case ZnsAction.setprice:
        // Not ownership-changing; can't appear as lastAction. Unreachable
        // given the assert in Registration's constructor.
        return null;
    }
  }
}
