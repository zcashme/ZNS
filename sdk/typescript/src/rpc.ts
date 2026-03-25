import { ZNSError, ErrorType } from "./errors.js";

export async function rpc<T>(
  url: string,
  method: string,
  params: Record<string, unknown> = {},
  id: number = 1,
): Promise<T> {
  const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  if (!res.ok) {
    throw new ZNSError(ErrorType.HttpError, `HTTP ${res.status}: ${res.statusText}`);
  }

  const json = (await res.json()) as {
    result?: T;
    error?: { code: number; message: string };
  };

  if (json.error) {
    const type = Object.values(ErrorType).includes(json.error.code as ErrorType)
      ? (json.error.code as ErrorType)
      : ErrorType.InternalError;
    throw new ZNSError(type, json.error.message);
  }

  return json.result as T;
}
