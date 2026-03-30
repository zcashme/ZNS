export enum ErrorType {
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,
  HttpError = -1,
  UivkMismatch = -2,
}

export class ZNSError extends Error {
  type: ErrorType;

  constructor(type: ErrorType, message?: string) {
    super(message ?? ErrorType[type]);
    this.name = "ZNSError";
    this.type = type;
  }
}
