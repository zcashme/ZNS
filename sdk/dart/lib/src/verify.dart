import 'dart:convert';
import 'dart:typed_data';

import 'types.dart';

typedef SignatureVerifier = Future<bool> Function(
    String payload, String signatureB64, String pubkeyB64);

String registrationPayload(Registration reg) {
  switch (reg.lastAction) {
    case 'CLAIM':
      return 'CLAIM:${reg.name}:${reg.address}';
    case 'BUY':
      return 'BUY:${reg.name}:${reg.address}';
    case 'UPDATE':
      return 'UPDATE:${reg.name}:${reg.address}:${reg.nonce}';
    case 'DELIST':
      return 'DELIST:${reg.name}:${reg.nonce}';
    case 'RELEASE':
      return 'RELEASE:${reg.name}:${reg.nonce}';
    default:
      return '';
  }
}

String listingPayload(Listing listing) =>
    'LIST:${listing.name}:${listing.price}:${listing.nonce}';

String eventActionPayload(ZnsEvent event) {
  switch (event.action) {
    case 'CLAIM':
      return event.ua != null ? 'CLAIM:${event.name}:${event.ua}' : '';
    case 'BUY':
      return event.ua != null ? 'BUY:${event.name}:${event.ua}' : '';
    case 'LIST':
      return event.price != null && event.nonce != null
          ? 'LIST:${event.name}:${event.price}:${event.nonce}'
          : '';
    case 'DELIST':
      return event.nonce != null ? 'DELIST:${event.name}:${event.nonce}' : '';
    case 'RELEASE':
      return event.nonce != null ? 'RELEASE:${event.name}:${event.nonce}' : '';
    case 'UPDATE':
      return event.ua != null && event.nonce != null
          ? 'UPDATE:${event.name}:${event.ua}:${event.nonce}'
          : '';
    default:
      return '';
  }
}

Future<bool> verifyRegistration(
    Registration reg, String adminPubkey, SignatureVerifier verifier) async {
  final sig = reg.signature;
  if (sig == null) return false;
  final payload = registrationPayload(reg);
  if (payload.isEmpty) return false;
  final pubkey = reg.pubkey ?? adminPubkey;
  return verifier(payload, sig, pubkey);
}

Future<bool> verifyListing(
    Listing listing, String adminPubkey, SignatureVerifier verifier) async {
  final payload = listingPayload(listing);
  return verifier(payload, listing.signature, adminPubkey);
}

Future<bool> verifyEvent(
    ZnsEvent event, String adminPubkey, SignatureVerifier verifier) async {
  final sig = event.signature;
  if (sig == null) return false;
  final payload = eventActionPayload(event);
  if (payload.isEmpty) return false;
  final pubkey = event.pubkey ?? adminPubkey;
  return verifier(payload, sig, pubkey);
}
