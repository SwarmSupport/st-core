# Startup website provider mapping

Checked on 2026-10-05 with Cloudflare DNS over HTTPS (`https://cloudflare-dns.com/dns-query`) and IPinfo. DNS answers change; the Core resolves the names again on each start and checks the current CDN answers against the bundled CIDRs before testing.

| Website | DoH sample address | IPinfo network | Startup category |
| --- | --- | --- | --- |
| `github.com` | `172.182.252.133` | [AS8075 Microsoft](https://ipinfo.io/ips/172.182.0.0/16) | `microsoft` (current DoH IPs; no CDN list) |
| `huggingface.co` | `108.138.246.67` | [AS16509 Amazon / CloudFront](https://ipinfo.io/ips/108.138.246.0/24) | `cloudfront` |
| `archiveofourown.org` (AO3) | `104.20.8.2` | [AS13335 Cloudflare](https://ipinfo.io/104.20.8.2) | `cloudflare` |

The other predefined test hosts were checked with DoH against the bundled provider ranges: `www.amazon.com` (CloudFront), `www.cloudflare.com` (Cloudflare), `www.fastly.com` and `www.python.org` (Fastly), and `dash.akamaized.net` (Akamai). The DNS match establishes a candidate range, while the pinned HTTPS request verifies that the selected address actually serves the site with a valid certificate.

The Akamai file is an [origin-facing ACL](https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server), not a complete client-facing edge list. Akamai provides the latter through [Client Access Control](https://techdocs.akamai.com/client-access-control/docs/about-client-access-control) for a customer's content. The startup check only tries DoH answers that happen to fall within the public ACL.
