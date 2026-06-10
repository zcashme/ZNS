/// Domain models for ZNS. Hand-rolled `fromJson` per the spec, mirroring
/// the snake_case shape returned by the Rust indexer.
library;

import 'package:meta/meta.dart';

import 'actions.dart';

/// Pending purchase for a listed name.
@immutable
class PendingBuy {
  final String buyer;
  final int price;
  final int claimHeight;
  final int expiresAt;
  final String txid;

  const PendingBuy({
    required this.buyer,
    required this.price,
    required this.claimHeight,
    required this.expiresAt,
    required this.txid,
  });

  factory PendingBuy.fromJson(Map<String, dynamic> json) => PendingBuy(
        buyer: json['buyer'] as String,
        price: json['price'] as int,
        claimHeight: json['claim_height'] as int,
        expiresAt: json['expires_at'] as int,
        txid: json['txid'] as String,
      );

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PendingBuy &&
          other.buyer == buyer &&
          other.price == price &&
          other.claimHeight == claimHeight &&
          other.expiresAt == expiresAt &&
          other.txid == txid;

  @override
  int get hashCode => Object.hash(buyer, price, claimHeight, expiresAt, txid);

  @override
  String toString() =>
      'PendingBuy(buyer: $buyer, price: $price, claimHeight: $claimHeight, '
      'expiresAt: $expiresAt, txid: $txid)';
}

/// A name listing in the marketplace.
@immutable
class Listing {
  final String name;
  final int price;
  final String payTaddr;
  final int nonce;
  final String txid;
  final int height;
  final String signature;
  final PendingBuy? pendingBuy;

  const Listing({
    required this.name,
    required this.price,
    required this.payTaddr,
    required this.nonce,
    required this.txid,
    required this.height,
    required this.signature,
    this.pendingBuy,
  });

  factory Listing.fromJson(Map<String, dynamic> json) {
    final pb = json['pending_buy'];
    return Listing(
      name: json['name'] as String,
      price: json['price'] as int,
      payTaddr: json['pay_taddr'] as String,
      nonce: json['nonce'] as int,
      txid: json['txid'] as String,
      height: json['height'] as int,
      signature: json['signature'] as String,
      pendingBuy:
          pb != null ? PendingBuy.fromJson(pb as Map<String, dynamic>) : null,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Listing &&
          other.name == name &&
          other.price == price &&
          other.payTaddr == payTaddr &&
          other.nonce == nonce &&
          other.txid == txid &&
          other.height == height &&
          other.signature == signature &&
          other.pendingBuy == pendingBuy;

  @override
  int get hashCode => Object.hash(
      name, price, payTaddr, nonce, txid, height, signature, pendingBuy);

  @override
  String toString() =>
      'Listing(name: $name, price: $price, payTaddr: $payTaddr, nonce: $nonce)';
}

/// A registered ZNS name.
@immutable
class Registration {
  final String name;
  final String address;
  final String txid;
  final int height;
  final int nonce;
  final String? signature;

  /// The most recent ownership-affecting action. Restricted to the
  /// ownership-changing subset of [ZnsAction] (see
  /// [ZnsAction.isOwnershipChanging]).
  final ZnsAction lastAction;
  final Listing? listing;

  Registration({
    required this.name,
    required this.address,
    required this.txid,
    required this.height,
    required this.nonce,
    required this.lastAction,
    this.signature,
    this.listing,
  }) : assert(lastAction.isOwnershipChanging,
            'lastAction must be ownership-changing, got $lastAction');

  factory Registration.fromJson(Map<String, dynamic> json) {
    final l = json['listing'];
    final actionStr = json['last_action'] as String;
    final action = ZnsAction.fromWire(actionStr);
    if (action == null || !action.isOwnershipChanging) {
      throw FormatException(
          'Unknown or non-ownership last_action from indexer: "$actionStr"');
    }
    return Registration(
      name: json['name'] as String,
      address: json['address'] as String,
      txid: json['txid'] as String,
      height: json['height'] as int,
      nonce: json['nonce'] as int,
      signature: json['signature'] as String?,
      lastAction: action,
      listing: l != null ? Listing.fromJson(l as Map<String, dynamic>) : null,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Registration &&
          other.name == name &&
          other.address == address &&
          other.txid == txid &&
          other.height == height &&
          other.nonce == nonce &&
          other.signature == signature &&
          other.lastAction == lastAction &&
          other.listing == listing;

  @override
  int get hashCode => Object.hash(
      name, address, txid, height, nonce, signature, lastAction, listing);

  @override
  String toString() =>
      'Registration(name: $name, address: $address, lastAction: $lastAction)';
}

/// Merkle inclusion proof binding a [Registration] to a state root.
/// Sibling hashes are hex-encoded, ordered bottom-up (leaf → root).
@immutable
class MerkleProof {
  final int index;
  final List<String> path;
  final String root;
  final int height;
  final int leafCount;

  const MerkleProof({
    required this.index,
    required this.path,
    required this.root,
    required this.height,
    required this.leafCount,
  });

  factory MerkleProof.fromJson(Map<String, dynamic> json) => MerkleProof(
        index: json['index'] as int,
        path: List<String>.unmodifiable(
            (json['path'] as List).cast<String>()),
        root: json['root'] as String,
        height: json['height'] as int,
        leafCount: json['leaf_count'] as int,
      );

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! MerkleProof) return false;
    if (other.index != index ||
        other.root != root ||
        other.height != height ||
        other.leafCount != leafCount) return false;
    if (other.path.length != path.length) return false;
    for (var i = 0; i < path.length; i++) {
      if (other.path[i] != path[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode =>
      Object.hash(index, Object.hashAll(path), root, height, leafCount);

  @override
  String toString() =>
      'MerkleProof(index: $index, height: $height, root: $root)';
}

/// A [Registration] with an accompanying Merkle proof against the indexer's
/// state root at `proof.height`. Returned by `ZNS.resolveNameWithProof`.
@immutable
class RegistrationWithProof {
  final Registration registration;
  final MerkleProof proof;

  const RegistrationWithProof({
    required this.registration,
    required this.proof,
  });

  // Convenience accessors to the inner Registration's fields, matching the
  // TypeScript SDK's flattened shape and avoiding `reg.registration.name`.
  String get name => registration.name;
  String get address => registration.address;
  String get txid => registration.txid;
  int get height => registration.height;
  int get nonce => registration.nonce;
  String? get signature => registration.signature;
  ZnsAction get lastAction => registration.lastAction;
  Listing? get listing => registration.listing;

  /// Parse from the indexer's wire format. The proof must be present;
  /// callers should have requested `with_proof: true`.
  factory RegistrationWithProof.fromJson(Map<String, dynamic> json) {
    final proofJson = json['proof'];
    if (proofJson == null) {
      throw FormatException(
          'Indexer response missing "proof" field — was with_proof=true sent?');
    }
    return RegistrationWithProof(
      registration: Registration.fromJson(json),
      proof: MerkleProof.fromJson(proofJson as Map<String, dynamic>),
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RegistrationWithProof &&
          other.registration == registration &&
          other.proof == proof;

  @override
  int get hashCode => Object.hash(registration, proof);

  @override
  String toString() =>
      'RegistrationWithProof(name: $name, address: $address, '
      'proof.root: ${proof.root.substring(0, 16)}...)';
}

/// Pricing tiers for name registration.
@immutable
class Pricing {
  final int nonce;
  final int height;
  final List<int> tiers;

  const Pricing({
    required this.nonce,
    required this.height,
    required this.tiers,
  });

  factory Pricing.fromJson(Map<String, dynamic> json) => Pricing(
        nonce: json['nonce'] as int,
        height: json['height'] as int,
        tiers: List<int>.unmodifiable((json['tiers'] as List).cast<int>()),
      );

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Pricing) return false;
    if (other.nonce != nonce || other.height != height) return false;
    if (other.tiers.length != tiers.length) return false;
    for (var i = 0; i < tiers.length; i++) {
      if (other.tiers[i] != tiers[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(nonce, height, Object.hashAll(tiers));

  @override
  String toString() =>
      'Pricing(nonce: $nonce, height: $height, tiers: $tiers)';
}

/// Current indexer status.
@immutable
class Status {
  final int syncedHeight;
  final String adminPubkey;
  final String uivk;
  final String address;
  final int registered;
  final int listed;
  final Pricing? pricing;

  const Status({
    required this.syncedHeight,
    required this.adminPubkey,
    required this.uivk,
    required this.address,
    required this.registered,
    required this.listed,
    this.pricing,
  });

  factory Status.fromJson(Map<String, dynamic> json) {
    final p = json['pricing'];
    return Status(
      syncedHeight: json['synced_height'] as int,
      adminPubkey: json['admin_pubkey'] as String,
      uivk: json['uivk'] as String,
      address: json['address'] as String,
      registered: json['registered'] as int,
      listed: json['listed'] as int,
      pricing: p != null ? Pricing.fromJson(p as Map<String, dynamic>) : null,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Status &&
          other.syncedHeight == syncedHeight &&
          other.adminPubkey == adminPubkey &&
          other.uivk == uivk &&
          other.address == address &&
          other.registered == registered &&
          other.listed == listed &&
          other.pricing == pricing;

  @override
  int get hashCode => Object.hash(
      syncedHeight, adminPubkey, uivk, address, registered, listed, pricing);

  @override
  String toString() =>
      'Status(syncedHeight: $syncedHeight, registered: $registered, '
      'listed: $listed)';
}

/// A single event in the ZNS event log.
@immutable
class Event {
  final int id;
  final String name;

  /// The full set of actions can appear in the event log, including
  /// admin `SETPRICE`.
  final ZnsAction action;
  final String txid;
  final int height;
  final String? ua;
  final int? price;
  final int? nonce;
  final String? signature;

  const Event({
    required this.id,
    required this.name,
    required this.action,
    required this.txid,
    required this.height,
    this.ua,
    this.price,
    this.nonce,
    this.signature,
  });

  factory Event.fromJson(Map<String, dynamic> json) {
    final actionStr = json['action'] as String;
    final action = ZnsAction.fromWire(actionStr);
    if (action == null) {
      throw FormatException('Unknown event action from indexer: "$actionStr"');
    }
    return Event(
      id: json['id'] as int,
      name: json['name'] as String,
      action: action,
      txid: json['txid'] as String,
      height: json['height'] as int,
      ua: json['ua'] as String?,
      price: json['price'] as int?,
      nonce: json['nonce'] as int?,
      signature: json['signature'] as String?,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Event &&
          other.id == id &&
          other.name == name &&
          other.action == action &&
          other.txid == txid &&
          other.height == height &&
          other.ua == ua &&
          other.price == price &&
          other.nonce == nonce &&
          other.signature == signature;

  @override
  int get hashCode => Object.hash(
      id, name, action, txid, height, ua, price, nonce, signature);

  @override
  String toString() =>
      'Event(id: $id, name: $name, action: $action, height: $height)';
}

/// Filter options for querying events.
@immutable
class EventsFilter {
  final String? name;
  final ZnsAction? action;
  final int? sinceHeight;
  final int? limit;
  final int? offset;

  const EventsFilter({
    this.name,
    this.action,
    this.sinceHeight,
    this.limit,
    this.offset,
  });

  /// Convert to a snake_case JSON-RPC params map, omitting null fields.
  Map<String, dynamic> toJson() {
    final out = <String, dynamic>{};
    if (name != null) out['name'] = name;
    if (action != null) out['action'] = action!.wire;
    if (sinceHeight != null) out['since_height'] = sinceHeight;
    if (limit != null) out['limit'] = limit;
    if (offset != null) out['offset'] = offset;
    return out;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is EventsFilter &&
          other.name == name &&
          other.action == action &&
          other.sinceHeight == sinceHeight &&
          other.limit == limit &&
          other.offset == offset;

  @override
  int get hashCode => Object.hash(name, action, sinceHeight, limit, offset);
}

/// Paginated events result.
@immutable
class EventsResult {
  final List<Event> events;
  final int total;

  const EventsResult({required this.events, required this.total});

  factory EventsResult.fromJson(Map<String, dynamic> json) => EventsResult(
        events: (json['events'] as List)
            .map((e) => Event.fromJson(e as Map<String, dynamic>))
            .toList(growable: false),
        total: json['total'] as int,
      );

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! EventsResult) return false;
    if (other.total != total || other.events.length != events.length) {
      return false;
    }
    for (var i = 0; i < events.length; i++) {
      if (other.events[i] != events[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(total, Object.hashAll(events));
}

/// Paginated listings result.
@immutable
class ListingsResult {
  final List<Listing> listings;
  final int total;

  const ListingsResult({required this.listings, required this.total});

  factory ListingsResult.fromJson(Map<String, dynamic> json) => ListingsResult(
        listings: (json['listings'] as List)
            .map((l) => Listing.fromJson(l as Map<String, dynamic>))
            .toList(growable: false),
        total: json['total'] as int,
      );

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! ListingsResult) return false;
    if (other.total != total || other.listings.length != listings.length) {
      return false;
    }
    for (var i = 0; i < listings.length; i++) {
      if (other.listings[i] != listings[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(total, Object.hashAll(listings));
}

/// A completed action ready to be embedded in a Zcash transaction.
@immutable
class CompletedAction {
  final String memo;
  final String uri;

  const CompletedAction({required this.memo, required this.uri});

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CompletedAction && other.memo == memo && other.uri == uri;

  @override
  int get hashCode => Object.hash(memo, uri);

  @override
  String toString() => 'CompletedAction(memo: $memo, uri: $uri)';
}

/// Validation result for a signing payload.
enum PayloadValidationLevel { valid, invalid, unrecognized }

@immutable
class PayloadValidationResult {
  final bool valid;
  final String action;
  final String message;
  final PayloadValidationLevel level;

  const PayloadValidationResult({
    required this.valid,
    required this.action,
    required this.message,
    required this.level,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PayloadValidationResult &&
          other.valid == valid &&
          other.action == action &&
          other.message == message &&
          other.level == level;

  @override
  int get hashCode => Object.hash(valid, action, message, level);

  @override
  String toString() =>
      'PayloadValidationResult(level: $level, action: $action, message: $message)';
}
