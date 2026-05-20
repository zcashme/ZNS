/// Target network for ZNS operations.
enum Network { testnet, mainnet }

/// Network-specific configuration for a ZNS indexer.
class NetworkConfig {
  final Uri url;
  final String registryAddress;
  final String uivk;

  const NetworkConfig({
    required this.url,
    required this.registryAddress,
    required this.uivk,
  });
}

final Map<Network, NetworkConfig> networks = {
  Network.testnet: NetworkConfig(
    url: Uri.parse('https://light.zcash.me/zns-testnet'),
    registryAddress:
        'utest1f32kn6c4zvn54xr8wfsnxmj9hzpu2mwgtxzpzwcw34906tdccdvzs0z2dx38lly7tpan77x6udt8pjczqm22ymsdhlz9j0tk5yq664nl',
    uivk:
        'uivktest1hzw7wyadutvzfgpna80yftsk5l7jeyu2p5me5quvp28tytxueta00cx4068wnlzcv7tx9n3t3gfhsy83pe4y6jrhxtzaq0hj6xtg5zrk2dn7zen3vns2a5pgs4fxdjlletmqrhfa42',
  ),
  Network.mainnet: NetworkConfig(
    url: Uri.parse('https://light.zcash.me/zns-mainnet'),
    registryAddress:
        'u1k0evt0ahj5qdt6y9ftsxndl8lrkm4ff6rp00u04cjpmqj6hxl9t8hfsxftmn3ht34e03lljh89czn2h8qn67rwrs8x0hm3lsxsucp9q9',
    uivk:
        'uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6',
  ),
};
