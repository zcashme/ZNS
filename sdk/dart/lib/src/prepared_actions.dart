/// Sealed [PreparedAction] hierarchy: each concrete subtype represents a
/// signable ZNS action. Consumers can `switch` on the sealed base type and
/// have exhaustiveness checked by the compiler.
library;

import 'package:meta/meta.dart';

import 'actions.dart';
import 'models.dart';
import 'zip321.dart' as zip321;

/// Commission sent with a BUY claim memo (0.0001 ZEC = 10,000 zats).
const int buyCommission = 10000;

/// Listing commission sent with a LIST memo (0.01 ZEC = 1,000,000 zats).
/// Mirrors the indexer's formula: `min_tier × 1000`.
const int listCommission = 1000000;

/// Sealed base type for all signable ZNS actions.
///
/// To produce a transaction-ready memo + URI:
/// 1. read [payload]
/// 2. sign it with Ed25519
/// 3. call [complete] with the base64-encoded signature
sealed class PreparedAction {
  /// The signing payload string. UTF-8 encode this to feed Ed25519.
  String get payload;

  /// The action this represents.
  ZnsAction get action;

  /// Build the memo + URI from [signatureBase64].
  CompletedAction complete(String signatureBase64);
}

/// Internal helper — builds the `ZNS:` memo and the ZIP-321 URI.
CompletedAction _build({
  required String memoBody,
  required String registryAddress,
  int? amountZats,
}) {
  final memo = 'ZNS:$memoBody';
  return CompletedAction(
    memo: memo,
    uri: zip321.buildZcashUri(
      registryAddress,
      amountZats: amountZats,
      memo: memo,
    ),
  );
}

@immutable
final class PreparedClaim extends PreparedAction {
  final String name;
  final String address;
  final int cost;
  final String _registryAddress;

  PreparedClaim({
    required this.name,
    required this.address,
    required this.cost,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.claim;

  @override
  String get payload => 'CLAIM:$name:$address';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'CLAIM:$name:$address:$signatureBase64',
        registryAddress: _registryAddress,
        amountZats: cost,
      );
}

@immutable
final class PreparedList extends PreparedAction {
  final String name;
  final int price;
  final String payTaddr;
  final int nonce;
  final String _registryAddress;

  PreparedList({
    required this.name,
    required this.price,
    required this.payTaddr,
    required this.nonce,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.list;

  @override
  String get payload => 'LIST:$name:$price:$payTaddr:$nonce';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'LIST:$name:$price:$payTaddr:$nonce:$signatureBase64',
        registryAddress: _registryAddress,
        amountZats: listCommission,
      );
}

@immutable
final class PreparedDelist extends PreparedAction {
  final String name;
  final int nonce;
  final String _registryAddress;

  PreparedDelist({
    required this.name,
    required this.nonce,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.delist;

  @override
  String get payload => 'DELIST:$name:$nonce';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'DELIST:$name:$nonce:$signatureBase64',
        registryAddress: _registryAddress,
      );
}

@immutable
final class PreparedUpdate extends PreparedAction {
  final String name;
  final String newAddress;
  final int nonce;
  final String _registryAddress;

  PreparedUpdate({
    required this.name,
    required this.newAddress,
    required this.nonce,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.update;

  @override
  String get payload => 'UPDATE:$name:$newAddress:$nonce';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'UPDATE:$name:$newAddress:$nonce:$signatureBase64',
        registryAddress: _registryAddress,
      );
}

@immutable
final class PreparedBuy extends PreparedAction {
  final String name;
  final String buyerAddress;
  final int price;
  final String _registryAddress;

  PreparedBuy({
    required this.name,
    required this.buyerAddress,
    required this.price,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.buy;

  @override
  String get payload => 'BUY:$name:$buyerAddress';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'BUY:$name:$buyerAddress:$price:$signatureBase64',
        registryAddress: _registryAddress,
        amountZats: buyCommission,
      );
}

@immutable
final class PreparedRelease extends PreparedAction {
  final String name;
  final int nonce;
  final String _registryAddress;

  PreparedRelease({
    required this.name,
    required this.nonce,
    required String registryAddress,
  }) : _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.release;

  @override
  String get payload => 'RELEASE:$name:$nonce';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody: 'RELEASE:$name:$nonce:$signatureBase64',
        registryAddress: _registryAddress,
      );
}

/// Admin-only. SETPRICE is signed only by the registry admin key.
@immutable
final class PreparedSetPrice extends PreparedAction {
  final List<int> prices;
  final int nonce;
  final String _registryAddress;

  PreparedSetPrice({
    required List<int> prices,
    required this.nonce,
    required String registryAddress,
  })  : prices = List<int>.unmodifiable(prices),
        _registryAddress = registryAddress;

  @override
  ZnsAction get action => ZnsAction.setprice;

  @override
  String get payload => 'SETPRICE:${prices.length}:${prices.join(':')}:$nonce';

  @override
  CompletedAction complete(String signatureBase64) =>
      _build(
        memoBody:
            'SETPRICE:${prices.length}:${prices.join(':')}:$nonce:$signatureBase64',
        registryAddress: _registryAddress,
      );
}
