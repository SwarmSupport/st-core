# st-core

The command-line core for swarm-tools. It provides local HTTP/HTTPS gateways, a policy DNS server, HTTP and SOCKS5 proxies, CA management, and an on-demand origin speed test.

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
```

Running `st-core` without a command displays help and starts no server. Each `start` command stays in the foreground until interrupted; `serve` is an alias. `start proxy` starts the configured HTTP and SOCKS5 proxy listeners. `start all` starts every configured listener. HTTPS requires an existing CA certificate and key: run `ca generate` first. CA generation refuses to overwrite either file. On macOS and Windows, `ca install` and `ca remove` change trust for the current user and use the certificate configured in `ca.cert`. Linux trust-store management is not implemented.

Origin TLS omits SNI but verifies the certificate chain and the configured
`upstream.host` by default. An origin that cannot present a valid certificate
without SNI will fail closed. Only when you explicitly accept that risk, set
`origin.insecure_skip_verify: true` to allow unverified origin connections.

The speed test downloads a limited amount of data from the configured profiles and built-in provider endpoints using only the addresses passed to the command. IPv4 CIDR ranges expand to every address in the range on port 443, including the first and last address. Inputs can be mixed and duplicate addresses are tested once. At most 1,024 distinct addresses are accepted, with eight tested concurrently. It never runs when a client connects to a server. The command reports measured speeds and exits with an error if none of the addresses could be measured. It may contact external services and consume bandwidth.

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
