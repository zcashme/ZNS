export function toBase64Url(text: string): string {
  try {
    return btoa(unescape(encodeURIComponent(text)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  } catch {
    return "";
  }
}

export function decodeBase64Url(value: string): string {
  try {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const paddingLength =
      normalized.length % 4 === 0 ? 0 : 4 - (normalized.length % 4);
    const padded = normalized + "=".repeat(paddingLength);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

export interface Zip321Parts {
  address: string;
  amount: string;
  memoRaw: string;
  memoDecoded: string;
}

export function buildZcashUri(
  address: string,
  amount?: string | number,
  memo?: string,
): string {
  if (!address) return "";
  const base = `zcash:${address}`;
  const params: string[] = [];
  if (amount !== undefined && Number(amount) > 0) params.push(`amount=${amount}`);
  if (memo) params.push(`memo=${toBase64Url(memo)}`);
  return params.length ? `${base}?${params.join("&")}` : base;
}

export function parseZip321Uri(uri: string): Zip321Parts {
  const withoutScheme = String(uri ?? "").replace(/^zcash:/i, "");
  const [addressPart, queryPart = ""] = withoutScheme.split("?");
  const address = addressPart.trim();
  const params = new URLSearchParams(queryPart);
  const amount = String(params.get("amount") ?? "").trim();
  const memoRaw = String(params.get("memo") ?? "").trim();
  const memoDecoded = memoRaw ? decodeBase64Url(memoRaw) : "";
  return { address, amount, memoRaw, memoDecoded };
}
