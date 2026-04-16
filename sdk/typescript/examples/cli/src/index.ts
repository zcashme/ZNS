import { ZNS } from "zcashname-sdk";
import * as ed25519 from "@noble/ed25519";
import * as fs from "fs";
import * as path from "path";

const command = process.argv[2];
const args = process.argv.slice(3);

function help() {
  console.log(`zns <command> [args] [options]

Commands:
  resolve <name|address>       Resolve a ZNS name or address
  available <name>               Check if a name is available
  listings                       Show all names for sale
  status                         Show indexer status
  events [name]                  Show recent events
  cost <name>                    Show claim cost for a name
  
  prepare-claim <name> <addr>    Build claim payload + URI (manual signing)
  sign-claim <name> <addr>       Sign and complete claim with private key
                                 Options: --key-file <path> or --key <hex>
  
  sign-list <name> <price> <nonce>
                                 Sign a list action
                                 Options: --key-file <path> or --key <hex>
                                 
  sign-delist <name> <nonce>     Sign a delist action
                                 Options: --key-file <path> or --key <hex>
                                 
  sign-update <name> <newAddr> <nonce>
                                 Sign an update action
                                 Options: --key-file <path> or --key <hex>
                                 
  sign-release <name> <nonce>    Sign a release action
                                 Options: --key-file <path> or --key <hex>

Options:
  --key-file <path>              Path to file containing hex-encoded private key
  --key <hex>                    Hex-encoded private key (64 chars)
  --url <url>                    ZNS indexer URL
  --help                         Show this help

Environment:
  ZNS_URL                        Default indexer URL (default: https://light.zcash.me/zns-testnet)

Examples:
  zns resolve alice
  zns available bob
  zns sign-claim myname u1qqlzrf9... --key-file ./key.txt
  zns sign-list myname 1000000 1 --key $(cat key.txt)`);
}

function parseArgs(args: string[]): { flags: Record<string, string>; positional: string[] } {
  const flags: Record<string, string> = {};
  const positional: string[] = [];
  
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const value = args[i + 1] ?? "";
      if (!value.startsWith("--")) {
        flags[key] = value;
        i++;
      } else {
        flags[key] = "true";
      }
    } else {
      positional.push(args[i]);
    }
  }
  
  return { flags, positional };
}

async function loadPrivateKey(flags: Record<string, string>): Promise<Uint8Array> {
  let hexKey: string;
  
  if (flags["key-file"]) {
    const keyPath = path.resolve(flags["key-file"]);
    if (!fs.existsSync(keyPath)) {
      throw new Error(`Key file not found: ${keyPath}`);
    }
    hexKey = fs.readFileSync(keyPath, "utf-8").trim();
  } else if (flags["key"]) {
    hexKey = flags["key"].trim();
  } else {
    throw new Error("Private key required. Use --key-file <path> or --key <hex>");
  }
  
  // Remove 0x prefix if present
  hexKey = hexKey.replace(/^0x/, "");
  
  if (hexKey.length !== 64) {
    throw new Error(`Invalid private key length: ${hexKey.length} chars (expected 64)`);
  }
  
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hexKey.slice(i * 2, i * 2 + 2), 16);
  }
  
  return bytes;
}

async function signAndComplete(
  payload: string,
  complete: (sig: string, pubkey?: string) => { memo: string; uri: string },
  privateKey: Uint8Array
): Promise<{ memo: string; uri: string; pubkey: string }> {
  const message = new TextEncoder().encode(payload);
  const signature = await ed25519.signAsync(message, privateKey);
  const pubkey = ed25519.getPublicKey(privateKey);
  
  const sigB64 = Buffer.from(signature).toString("base64");
  const pubkeyB64 = Buffer.from(pubkey).toString("base64");
  
  const result = complete(sigB64, pubkeyB64);
  return { ...result, pubkey: pubkeyB64 };
}

async function main() {
  const { flags, positional } = parseArgs(args);
  const url = flags["url"] || process.env.ZNS_URL;
  
  const zns = new ZNS({ url });

  switch (command) {
    case "resolve": {
      const query = positional[0];
      if (!query) {
        console.error("Usage: zns resolve <name-or-address>");
        process.exit(1);
      }
      const result = query.startsWith("u") 
        ? await zns.resolveAddress(query)
        : await zns.resolveName(query);
        
      if (!result || (Array.isArray(result) && result.length === 0)) {
        console.log("Not found");
        break;
      }
      const results = Array.isArray(result) ? result : [result];
      for (const r of results) {
        console.log(`${r.name} → ${r.address}`);
        console.log(`  sovereign: ${r.pubkey ? "yes" : "no (admin)"}`);
        console.log(`  txid: ${r.txid}  height: ${r.height}  nonce: ${r.nonce}`);
        console.log(`  last_action: ${r.last_action}`);
        if (r.listing) {
          console.log(`  listed for: ${r.listing.price / 1e8} ZEC`);
        }
      }
      break;
    }

    case "available": {
      const name = positional[0];
      if (!name) {
        console.error("Usage: zns available <name>");
        process.exit(1);
      }
      const valid = zns.isValidName(name);
      if (!valid) {
        console.log("Invalid name (must be lowercase alphanumeric, 1-62 chars)");
        break;
      }
      const available = await zns.isAvailable(name);
      console.log(available ? "Available" : "Taken");
      break;
    }

    case "listings": {
      const listings = await zns.listings();
      if (listings.length === 0) {
        console.log("No listings");
        break;
      }
      const status = await zns.status();
      for (const l of listings) {
        const verified = await zns.verifyListing(l, status.admin_pubkey);
        console.log(`${l.name} – ${l.price / 1e8} ZEC  (verified: ${verified})`);
      }
      break;
    }

    case "status": {
      const status = await zns.status();
      console.log(`Synced:     ${status.synced_height}`);
      console.log(`UIVK:       ${status.uivk.slice(0, 30)}...`);
      console.log(`Admin:      ${status.admin_pubkey.slice(0, 30)}...`);
      console.log(`Registry:   ${zns.registryAddress}`);
      console.log(`Registered: ${status.registered}`);
      console.log(`Listed:     ${status.listed}`);
      if (status.pricing) {
        console.log(`Pricing:    ${status.pricing.tiers.map((t, i) => `${i + 1}ch=${t / 1e8}ZEC`).join(" ")}`);
      }
      break;
    }

    case "events": {
      const filter: Record<string, string | number> = {};
      if (positional[0]) filter.name = positional[0];
      const result = await zns.events(filter);
      for (const e of result.events) {
        const parts = [`${e.action}`, e.name];
        if (e.price != null) parts.push(`${e.price / 1e8} ZEC`);
        parts.push(`h=${e.height}`);
        console.log(parts.join("  "));
      }
      console.log(`(${result.total} total)`);
      break;
    }

    case "cost": {
      const name = positional[0];
      if (!name) {
        console.error("Usage: zns cost <name>");
        process.exit(1);
      }
      const valid = zns.isValidName(name);
      if (!valid) {
        console.log("Invalid name");
        break;
      }
      const status = await zns.status();
      if (!status.pricing) {
        console.log("No pricing available");
        break;
      }
      const cost = zns.claimCost(name.length, status.pricing);
      if (cost == null) {
        console.log("No pricing available");
      } else {
        console.log(`${name} (${name.length} chars): ${cost / 1e8} ZEC (${cost} zats)`);
      }
      break;
    }

    case "prepare-claim": {
      const [name, address] = positional;
      if (!name || !address) {
        console.error("Usage: zns prepare-claim <name> <address>");
        process.exit(1);
      }
      const status = await zns.status();
      if (!status.pricing) {
        console.error("No pricing available from server");
        process.exit(1);
      }
      const cost = zns.claimCost(name.length, status.pricing);
      if (cost === null) {
        console.error("Could not calculate claim cost");
        process.exit(1);
      }
      const result = zns.prepareClaim(name, address, cost);
      console.log(`Name:    ${result.name}`);
      console.log(`Address: ${result.address}`);
      console.log(`Cost:    ${result.cost / 1e8} ZEC (${result.cost} zats)`);
      console.log(`Registry: ${zns.registryAddress}`);
      console.log(`Payload: ${result.payload}`);
      console.log("");
      console.log("Sign this payload with your Ed25519 private key, then:");
      console.log(`  zns complete-claim ${name} ${address} ${zns.registryAddress} ${cost} <signature> [pubkey]`);
      break;
    }

    case "sign-claim": {
      const [name, address] = positional;
      if (!name || !address) {
        console.error("Usage: zns sign-claim <name> <address> --key-file <path>");
        process.exit(1);
      }
      
      const status = await zns.status();
      if (!status.pricing) {
        console.error("No pricing available from server");
        process.exit(1);
      }
      const cost = zns.claimCost(name.length, status.pricing);
      if (cost === null) {
        console.error("Could not calculate claim cost");
        process.exit(1);
      }
      
      const privateKey = await loadPrivateKey(flags);
      const action = zns.prepareClaim(name, address, cost);
      
      const { memo, uri, pubkey } = await signAndComplete(
        action.payload,
        action.complete.bind(action),
        privateKey
      );
      
      console.log(`Name:      ${name}`);
      console.log(`Address:   ${address}`);
      console.log(`Cost:      ${action.cost / 1e8} ZEC`);
      console.log(`Registry:  ${zns.registryAddress}`);
      console.log(`Public Key: ${pubkey}`);
      console.log("");
      console.log("Memo:");
      console.log(memo);
      console.log("");
      console.log("ZIP-321 URI (send this to your wallet):");
      console.log(uri);
      break;
    }

    case "sign-list": {
      const [name, priceStr, nonceStr] = positional;
      if (!name || !priceStr || !nonceStr) {
        console.error("Usage: zns sign-list <name> <price-zats> <nonce> --key-file <path>");
        process.exit(1);
      }
      
      const status = await zns.status();
      const price = parseInt(priceStr, 10);
      const nonce = parseInt(nonceStr, 10);
      const privateKey = await loadPrivateKey(flags);
      const action = zns.prepareList(name, price, nonce);
      
      const { memo, uri, pubkey } = await signAndComplete(
        action.payload,
        action.complete.bind(action),
        privateKey
      );
      
      console.log(`Name:       ${name}`);
      console.log(`Price:      ${price / 1e8} ZEC (${price} zats)`);
      console.log(`Public Key: ${pubkey}`);
      console.log("");
      console.log("Memo:");
      console.log(memo);
      console.log("");
      console.log("ZIP-321 URI:");
      console.log(uri);
      break;
    }

    case "sign-delist": {
      const [name, nonceStr] = positional;
      if (!name || !nonceStr) {
        console.error("Usage: zns sign-delist <name> <nonce> --key-file <path>");
        process.exit(1);
      }
      
      const status = await zns.status();
      const nonce = parseInt(nonceStr, 10);
      const privateKey = await loadPrivateKey(flags);
      const action = zns.prepareDelist(name, nonce);
      
      const { memo, uri } = await signAndComplete(
        action.payload,
        action.complete.bind(action),
        privateKey
      );
      
      console.log(`Name: ${name}`);
      console.log("Memo:");
      console.log(memo);
      console.log("");
      console.log("ZIP-321 URI:");
      console.log(uri);
      break;
    }

    case "sign-update": {
      const [name, newAddress, nonceStr] = positional;
      if (!name || !newAddress || !nonceStr) {
        console.error("Usage: zns sign-update <name> <new-address> <nonce> --key-file <path>");
        process.exit(1);
      }
      
      const status = await zns.status();
      const nonce = parseInt(nonceStr, 10);
      const privateKey = await loadPrivateKey(flags);
      const action = zns.prepareUpdate(name, newAddress, nonce);
      
      const { memo, uri } = await signAndComplete(
        action.payload,
        action.complete.bind(action),
        privateKey
      );
      
      console.log(`Name:        ${name}`);
      console.log(`New Address: ${newAddress}`);
      console.log("Memo:");
      console.log(memo);
      console.log("");
      console.log("ZIP-321 URI:");
      console.log(uri);
      break;
    }

    case "sign-release": {
      const [name, nonceStr] = positional;
      if (!name || !nonceStr) {
        console.error("Usage: zns sign-release <name> <nonce> --key-file <path>");
        process.exit(1);
      }
      
      const status = await zns.status();
      const nonce = parseInt(nonceStr, 10);
      const privateKey = await loadPrivateKey(flags);
      const action = zns.prepareRelease(name, nonce);
      
      const { memo, uri } = await signAndComplete(
        action.payload,
        action.complete.bind(action),
        privateKey
      );
      
      console.log(`Name: ${name}`);
      console.log("Memo:");
      console.log(memo);
      console.log("");
      console.log("ZIP-321 URI:");
      console.log(uri);
      break;
    }

    case "help":
    case "--help":
    case "-h":
    default: {
      help();
    }
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
