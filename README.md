# st-core

The command-line core for swarm-tools. It provides local HTTP/HTTPS gateways, a policy DNS server, HTTP and SOCKS5 proxies, CA management, startup IP selection, and an on-demand origin speed test.

Build with `go build -o st-core ./cmd/st-core`. Commands use `config.yaml` in the current directory by default. Pass `-config /path/to/config.yaml` before the command to use another file.

```text
st-core help
st-core check
st-core ca generate
st-core ca install
st-core ca remove
st-core start all
st-core start proxy
st-core start dns
st-core start https
st-core start http
st-core speedtest 1.1.1.1:443 1.0.0.1:443
st-core speedtest 1.0.0.0/24
st-core speedtest
```

Running `st-core` without a command displays help and starts no server. Each `start` command stays in the foreground until interrupted; `serve` is an alias. `start proxy` starts the configured HTTP and SOCKS5 proxy listeners. `start all` starts every configured listener. HTTPS requires an existing CA certificate and key: run `ca generate` first. CA generation refuses to overwrite either file. On macOS and Windows, `ca install` and `ca remove` change trust for the current user and use the certificate configured in `ca.cert`. Linux trust-store management is not implemented.

Origin TLS omits SNI but verifies the certificate chain and the configured
`upstream.host` by default. An origin that cannot present a valid certificate
without SNI will fail closed. Only when you explicitly accept that risk, set
`origin.insecure_skip_verify: true` to allow unverified origin connections.

`origin.domains` can map an exact domain or `*.example.com` to a named IP list,
a single domain name, or an array of IP addresses and domain names. Domain targets are resolved
through the configured DoH server when a connection is made. For example:

```yaml
origin:
  domains:
    example.com: origin.example.net
```

Named lists can contain individual IPs or CIDRs. For CIDRs, the Core uses only
the domain's current DoH answers that fall within a listed range. Keep the
release archive's `iplist/` directory beside the executable when running
startup selection.

With no addresses, `speedtest` resolves the host of each configured and built-in provider download URL, then tests each returned IP against that provider's URL. Add provider URLs with `speedtest.profiles` in `config.yaml`, for example:

```yaml
speedtest:
  profiles:
    - name: example
      url: https://download.example.com/test.bin
      min_bytes: 65536
```

For explicit IPs or IPv4 CIDR ranges, the command checks whether each IP matches a resolved provider URL. Other IPs are tried against the provider URLs and labeled with the endpoint that accepts the download. This label identifies the successful test endpoint; it does not prove ownership of a shared CDN IP. CIDR ranges use port 443 and include the first and last address. Inputs can be mixed and duplicates are tested once. At most 1,024 distinct addresses are accepted, with eight tested concurrently. The test never runs when a client connects to a server. It downloads a limited amount of data and may consume bandwidth.

On each `start`, the Core also checks one randomly chosen website per provider category in the built-in catalog. It resolves the website through the configured DoH resolver, keeps only addresses inside the bundled provider CIDRs where a range list is available, then makes an HTTPS request pinned to each candidate IP. Normal certificate and hostname verification is required. The fastest address above `speedtest.min_mbps` (default 1 Mbps) is logged. Startup selection runs in the background and does not block listeners or alter routing. A failed check produces no selected IP. No IPs are uploaded; the desktop app only displays local results until a community API is supplied.

The bundled `iplist/*.txt` files contain CIDRs from [Cloudflare's IP API](https://api.cloudflare.com/client/v4/ips), [Fastly's public IP API](https://api.fastly.com/public-ip-list), [CloudFront's global edge list](https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips), and [Akamai's published Origin IP ACL](https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server). Akamai's public ACL describes origin-facing addresses; its client-facing edge ranges are provided through account-specific Client Access Control. The Akamai startup probe therefore tests only the current DoH answer for its predefined URL if that answer is in the published ACL. The lists are snapshots and need refreshing when providers change their ranges.

## Android and iOS embedding

The `mobilecore` package is a Go Mobile binding for an in-app HTTP and SOCKS5
proxy. Build an Android AAR or iOS XCFramework with:

```sh
./scripts/build-mobile.sh android
./scripts/build-mobile.sh ios org.example.yourapp
```

Android builds require the Android SDK and NDK. iOS builds require macOS and
Xcode. The generated files are `dist/st-core.aar` and
`dist/STCore.xcframework`. See the [Go Mobile documentation](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile)
for SDK setup and binding integration.

The generated API exposes `NewCore()`, `Core.Start(httpPort, socksPort)`,
`Core.HTTPAddress()`, `Core.SOCKS5Address()`, `Core.LastError()`, and
`Core.Stop()`. Use port `0` to select a free port and `-1` to disable a proxy.
For example, `Start(0, 0)` starts both proxies, and the address methods return
the loopback endpoints to configure in the host app. Call `Stop()` when the app
no longer uses them; the same instance can then be restarted. Listeners bind
only to `127.0.0.1` and the mobile proxies make direct outbound connections.

To route traffic from other apps or the whole device, the host app must provide
Android `VpnService` or an iOS Network Extension and feed its traffic to this
core. The CLI policy DNS and HTTPS gateway are not part of the mobile binding;
their privileged ports, certificate trust, and background operation require
platform-specific integration.
