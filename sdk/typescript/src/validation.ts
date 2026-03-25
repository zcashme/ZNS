export function isValidName(name: string): boolean {
  return (
    /^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/.test(name) &&
    !name.includes("--")
  );
}
