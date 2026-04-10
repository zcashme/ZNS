/// A registered ZNS name.
class Registration {
  final String name;
  final String address;
  final String txid;
  final int height;
  final int nonce;
  final String? signature;
  final String lastAction;
  final String? pubkey;

  Registration({
    required this.name,
    required this.address,
    required this.txid,
    required this.height,
    required this.nonce,
    this.signature,
    required this.lastAction,
    this.pubkey,
  });

  factory Registration.fromJson(Map<String, dynamic> json) {
    return Registration(
      name: json['name'] as String,
      address: json['address'] as String,
      txid: json['txid'] as String,
      height: json['height'] as int,
      nonce: json['nonce'] as int,
      signature: json['signature'] as String?,
      lastAction: json['last_action'] as String,
      pubkey: json['pubkey'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'address': address,
        'txid': txid,
        'height': height,
        'nonce': nonce,
        if (signature != null) 'signature': signature,
        'last_action': lastAction,
        if (pubkey != null) 'pubkey': pubkey,
      };
}

/// A name listed for sale on the ZNS marketplace.
class Listing {
  final String name;

  /// Price in zatoshis.
  final int price;
  final int nonce;
  final String txid;
  final int height;
  final String signature;

  Listing({
    required this.name,
    required this.price,
    required this.nonce,
    required this.txid,
    required this.height,
    required this.signature,
  });

  factory Listing.fromJson(Map<String, dynamic> json) {
    return Listing(
      name: json['name'] as String,
      price: json['price'] as int,
      nonce: json['nonce'] as int,
      txid: json['txid'] as String,
      height: json['height'] as int,
      signature: json['signature'] as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'price': price,
        'nonce': nonce,
        'txid': txid,
        'height': height,
        'signature': signature,
      };
}

/// Result of resolving a ZNS name or address.
class ResolveResult {
  final String name;
  final String address;
  final String txid;
  final int height;
  final int nonce;
  final String? signature;
  final String lastAction;
  final String? pubkey;
  final Listing? listing;

  ResolveResult({
    required this.name,
    required this.address,
    required this.txid,
    required this.height,
    required this.nonce,
    this.signature,
    required this.lastAction,
    this.pubkey,
    this.listing,
  });

  factory ResolveResult.fromJson(Map<String, dynamic> json) {
    final listingData = json['listing'];
    return ResolveResult(
      name: json['name'] as String,
      address: json['address'] as String,
      txid: json['txid'] as String,
      height: json['height'] as int,
      nonce: json['nonce'] as int,
      signature: json['signature'] as String?,
      lastAction: json['last_action'] as String,
      pubkey: json['pubkey'] as String?,
      listing: listingData != null
          ? Listing.fromJson(listingData as Map<String, dynamic>)
          : null,
    );
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'address': address,
        'txid': txid,
        'height': height,
        'nonce': nonce,
        if (signature != null) 'signature': signature,
        'last_action': lastAction,
        if (pubkey != null) 'pubkey': pubkey,
        'listing': listing?.toJson(),
      };
}

/// Pricing tiers and nonce for name claims.
class Pricing {
  final int nonce;
  final int height;
  final List<int> tiers;

  Pricing({
    required this.nonce,
    required this.height,
    required this.tiers,
  });

  factory Pricing.fromJson(Map<String, dynamic> json) {
    return Pricing(
      nonce: json['nonce'] as int,
      height: json['height'] as int,
      tiers: (json['tiers'] as List<dynamic>).cast<int>(),
    );
  }

  Map<String, dynamic> toJson() => {
        'nonce': nonce,
        'height': height,
        'tiers': tiers,
      };
}

/// Status of the ZNS indexer.
class StatusResult {
  final int syncedHeight;
  final String adminPubkey;
  final String uivk;
  final String address;
  final int registered;
  final int listed;
  final Pricing? pricing;

  StatusResult({
    required this.syncedHeight,
    required this.adminPubkey,
    required this.uivk,
    required this.address,
    required this.registered,
    required this.listed,
    this.pricing,
  });

  factory StatusResult.fromJson(Map<String, dynamic> json) {
    final pricingData = json['pricing'];
    return StatusResult(
      syncedHeight: json['synced_height'] as int,
      adminPubkey: json['admin_pubkey'] as String,
      uivk: json['uivk'] as String,
      address: json['address'] as String,
      registered: json['registered'] as int,
      listed: json['listed'] as int,
      pricing: pricingData != null
          ? Pricing.fromJson(pricingData as Map<String, dynamic>)
          : null,
    );
  }

  Map<String, dynamic> toJson() => {
        'synced_height': syncedHeight,
        'admin_pubkey': adminPubkey,
        'uivk': uivk,
        'address': address,
        'registered': registered,
        'listed': listed,
        if (pricing != null) 'pricing': pricing!.toJson(),
      };
}

/// A single event from the ZNS event log.
class ZnsEvent {
  final int id;
  final String name;

  /// One of: CLAIM, LIST, DELIST, RELEASE, UPDATE, BUY, SETPRICE.
  final String action;
  final String txid;
  final int height;
  final String? ua;
  final int? price;
  final int? nonce;
  final String? signature;
  final String? pubkey;

  ZnsEvent({
    required this.id,
    required this.name,
    required this.action,
    required this.txid,
    required this.height,
    this.ua,
    this.price,
    this.nonce,
    this.signature,
    this.pubkey,
  });

  factory ZnsEvent.fromJson(Map<String, dynamic> json) {
    return ZnsEvent(
      id: json['id'] as int,
      name: json['name'] as String,
      action: json['action'] as String,
      txid: json['txid'] as String,
      height: json['height'] as int,
      ua: json['ua'] as String?,
      price: json['price'] as int?,
      nonce: json['nonce'] as int?,
      signature: json['signature'] as String?,
      pubkey: json['pubkey'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'action': action,
        'txid': txid,
        'height': height,
        if (ua != null) 'ua': ua,
        if (price != null) 'price': price,
        if (nonce != null) 'nonce': nonce,
        if (signature != null) 'signature': signature,
        if (pubkey != null) 'pubkey': pubkey,
      };
}

/// Optional filters for querying the event log.
class EventsFilter {
  final String? name;
  final String? action;
  final int? sinceHeight;
  final int? limit;
  final int? offset;

  EventsFilter({
    this.name,
    this.action,
    this.sinceHeight,
    this.limit,
    this.offset,
  });

  /// Converts to a JSON map, omitting null fields.
  /// Uses snake_case keys to match the API.
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    if (name != null) map['name'] = name;
    if (action != null) map['action'] = action;
    if (sinceHeight != null) map['since_height'] = sinceHeight;
    if (limit != null) map['limit'] = limit;
    if (offset != null) map['offset'] = offset;
    return map;
  }
}

/// A page of events with total count.
class EventsResult {
  final List<ZnsEvent> events;
  final int total;

  EventsResult({
    required this.events,
    required this.total,
  });

  factory EventsResult.fromJson(Map<String, dynamic> json) {
    return EventsResult(
      events: (json['events'] as List<dynamic>)
          .map((e) => ZnsEvent.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as int,
    );
  }

  Map<String, dynamic> toJson() => {
        'events': events.map((e) => e.toJson()).toList(),
        'total': total,
      };
}
