import 'dart:convert';

import 'package:http/http.dart' as http;

import 'errors.dart';

/// Send a JSON-RPC 2.0 request and return the result.
Future<dynamic> rpc(
  http.Client httpClient,
  String url,
  String method, {
  Map<String, dynamic>? params,
  int id = 1,
}) async {
  final payload = jsonEncode({
    'jsonrpc': '2.0',
    'id': id,
    'method': method,
    'params': params ?? <String, dynamic>{},
  });

  final http.Response response;
  try {
    response = await httpClient.post(
      Uri.parse(url),
      headers: {'Content-Type': 'application/json'},
      body: payload,
    );
  } on Exception catch (e) {
    throw ZnsError(ZnsErrorType.httpError, e.toString());
  }

  if (response.statusCode != 200) {
    throw ZnsError(
      ZnsErrorType.httpError,
      'HTTP ${response.statusCode}: ${response.reasonPhrase}',
    );
  }

  final body = jsonDecode(response.body) as Map<String, dynamic>;

  final error = body['error'];
  if (error != null) {
    final code = error['code'] as int? ?? ZnsErrorType.internalError.code;
    final errorType = ZnsErrorType.fromCode(code);
    final message = error['message'] as String? ?? 'Unknown error';
    throw ZnsError(errorType, message);
  }

  return body['result'];
}
