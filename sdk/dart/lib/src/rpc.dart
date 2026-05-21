import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

/// Thrown when an RPC call fails — either a non-2xx HTTP status, or a
/// JSON-RPC envelope `error`.
class ZnsRpcException implements Exception {
  /// JSON-RPC error code when [isHttp] is false; the raw HTTP status code
  /// (e.g. 404, 500) when [isHttp] is true.
  final int code;
  final String message;
  final bool isHttp;

  ZnsRpcException(this.code, this.message, {this.isHttp = false});

  @override
  String toString() => isHttp
      ? 'ZnsRpcException: ZNS HTTP $code: $message'
      : 'ZnsRpcException: ZNS RPC error $code: $message';
}

/// Internal JSON-RPC 2.0 client. Not exported in the public surface.
class RpcClient {
  final Uri url;
  final http.Client httpClient;
  final Duration timeout;
  int _id = 0;

  /// Whether [httpClient] is owned (and therefore closed by [close]).
  final bool _ownsClient;

  RpcClient(this.url, {http.Client? httpClient, Duration? timeout})
      : httpClient = httpClient ?? http.Client(),
        _ownsClient = httpClient == null,
        timeout = timeout ?? const Duration(seconds: 10);

  Future<T> call<T>(String method, [Map<String, dynamic>? params]) async {
    final id = ++_id;
    final body = jsonEncode({
      'jsonrpc': '2.0',
      'id': id,
      'method': method,
      'params': params ?? <String, dynamic>{},
    });

    final response = await httpClient.post(
      url,
      headers: const {'Content-Type': 'application/json'},
      body: body,
    ).timeout(timeout);

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ZnsRpcException(
        response.statusCode,
        response.reasonPhrase ?? 'HTTP error',
        isHttp: true,
      );
    }

    final decoded = jsonDecode(response.body) as Map<String, dynamic>;
    final error = decoded['error'];
    if (error != null) {
      final m = error as Map<String, dynamic>;
      throw ZnsRpcException(
        (m['code'] as int?) ?? -32603,
        (m['message'] as String?) ?? 'Unknown error',
      );
    }
    return decoded['result'] as T;
  }

  void close() {
    if (_ownsClient) httpClient.close();
  }
}
