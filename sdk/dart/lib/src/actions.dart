/// User-signable and admin actions in the ZNS protocol.
///
/// Each value carries the canonical wire string (`CLAIM`, `BUY`, …) that
/// appears in memos and JSON-RPC responses. Use [fromWire] to parse strings
/// from the indexer; use [wire] to serialise back.
enum ZnsAction {
  claim('CLAIM'),
  buy('BUY'),
  update('UPDATE'),
  list('LIST'),
  delist('DELIST'),
  release('RELEASE'),
  setprice('SETPRICE');

  const ZnsAction(this.wire);

  /// Canonical uppercase action name as it appears in memos.
  final String wire;

  /// Parse a wire string (case-insensitive) into a [ZnsAction]. Returns
  /// `null` for unknown actions.
  static ZnsAction? fromWire(String s) {
    final upper = s.toUpperCase();
    for (final a in values) {
      if (a.wire == upper) return a;
    }
    return null;
  }

  /// True for actions a regular user signs. `SETPRICE` is admin-only.
  bool get isUserSignable => this != ZnsAction.setprice;

  /// True for actions that can appear as [Registration.lastAction] — the
  /// ownership-affecting set: `CLAIM`, `BUY`, `UPDATE`, `DELIST`, `RELEASE`.
  /// `LIST` does not change ownership; `SETPRICE` is global.
  bool get isOwnershipChanging =>
      this != ZnsAction.list && this != ZnsAction.setprice;

  @override
  String toString() => wire;
}
