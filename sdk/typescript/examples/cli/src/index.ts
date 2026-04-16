import { ZNS } from "zcashname-sdk";

const command = process.argv[2];
const arg = process.argv[3];

async function main() {
  const zns = await ZNS.create({ url: process.env.ZNS_URL });

  switch (command) {
    case "resolve": {
      if (!arg) {
        console.error("Usage: zns resolve <name-or-address>");
        process.exit(1);
      }
      const result = await zns.resolve(arg);
      if (!result) {
        console.log("Not found");
        break;
      }
      const results = Array.isArray(result) ? result : [result];
      for (const r of results) {
        console.log(`${r.name} → ${r.address}`);
        console.log(`  verified: ${r.verified}  sovereign: ${r.sovereign}`);
        console.log(`  txid: ${r.txid}  height: ${r.height}  nonce: ${r.nonce}`);
        console.log(`  last_action: ${r.last_action}`);
        if (r.listing) {
          console.log(`  listed for: ${r.listing.price / 1e8} ZEC`);
        }
      }
      break;
    }

    case "available": {
      if (!arg) {
        console.error("Usage: zns available <name>");
        process.exit(1);
      }
      console.log(await zns.isAvailable(arg) ? "Available" : "Taken");
      break;
    }

    case "listings": {
      const listings = await zns.listings();
      if (listings.length === 0) {
        console.log("No listings");
        break;
      }
      for (const l of listings) {
        console.log(`${l.name} – ${l.price / 1e8} ZEC  (verified: ${l.verified})`);
      }
      break;
    }

    case "status": {
      const status = await zns.status();
      console.log(`Synced:    ${status.synced_height}`);
      console.log(`Registered:${status.registered}`);
      console.log(`Listed:    ${status.listed}`);
      if (status.pricing) {
        console.log(`Pricing:   ${status.pricing.tiers.map((t, i) => `${i + 1}ch=${t / 1e8}ZEC`).join(" ")}`);
      }
      break;
    }

    case "events": {
      const filter: Record<string, string | number> = {};
      if (arg) filter.name = arg;
      const result = await zns.events(filter);
      for (const e of result.events) {
        const parts = [`${e.action}`, e.name];
        if (e.price != null) parts.push(`${e.price / 1e8} ZEC`);
        parts.push(`h=${e.height}`);
        if (e.verified) parts.push("✓");
        console.log(parts.join("  "));
      }
      console.log(`(${result.total} total)`);
      break;
    }

    case "cost": {
      if (!arg) {
        console.error("Usage: zns cost <name>");
        process.exit(1);
      }
      const cost = zns.claimCost(arg.length);
      if (cost == null) {
        console.log("No pricing available");
      } else {
        console.log(`${arg} (${arg.length} chars): ${cost / 1e8} ZEC (${cost} zats)`);
      }
      break;
    }

    case "prepare-claim": {
      if (!arg) {
        console.error("Usage: zns prepare-claim <name> <address>");
        process.exit(1);
      }
      const address = process.argv[4];
      if (!address) {
        console.error("Usage: zns prepare-claim <name> <address>");
        process.exit(1);
      }
      const result = zns.prepareClaim(arg, address);
      console.log(`Payload: ${result.payload}`);
      if (result.cost) console.log(`Cost:    ${result.cost / 1e8} ZEC (${result.cost} zats)`);
      if (result.uri) console.log(`URI:     ${result.uri}`);
      break;
    }

    case "help":
    default: {
      console.log(`zns <command> [arg]

Commands:
  resolve <name|address>    Resolve a ZNS name or address
  available <name>          Check if a name is available
  listings                  Show all names for sale
  status                    Show indexer status
  events [name]             Show recent events
  cost <name>               Show claim cost for a name
  prepare-claim <name> <addr>  Build claim payload + URI

Environment:
  ZNS_URL  Indexer URL (default: https://light.zcash.me/zns-testnet)`);
    }
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});