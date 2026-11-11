# Peer UDP relay: `CallMeMaybeVia` has no `ClientDisco`/`AddrPorts` validation — attacker-directed UDP reflection + client-side handshake DoS

**Component:** `wgengine/magicsock` (peer UDP-relay client) — `magicsock.go`,
`relaymanager.go`
**Affected version:** Tailscale v1.104.1 (confirmed; present on current `main`)
**Reporter:** (your name / HackerOne handle)
**Severity:** High (DoS). A hostile tailnet peer makes a victim emit UDP packets
to arbitrary attacker-chosen addresses (reflection with the node as source) and
can exhaust the victim's CPU/goroutines/memory. Preconditions are effectively
default-on. CVSS:3.1 ~ `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`.

## Summary

When a node receives a `disco.CallMeMaybeVia` over DERP from a relay-capable
peer, it builds a relay `ServerEndpoint` directly from the message's
attacker-controlled fields (`ServerDisco`, `VNI`, `AddrPorts`, `LamportID`,
`BindLifetime`) and starts a handshake that sends a UDP "Bind" disco packet to
**every** address in `AddrPorts`. There is **no** check that the message's
`ClientDisco` contains this node's (or the sender's) disco key, and **no** cap
on the number of `AddrPorts`. So a single DERP message makes the victim send a
UDP packet to each of up to ~thousands of attacker-specified IP:ports, and
repeated messages with distinct `ServerDisco`/`VNI` spawn unbounded concurrent
handshake goroutines.

That the omission is a bug (not intent) is shown by the sibling *allocation*
path, which **does** enforce authorization: `AllocateUDPRelayEndpointRequest`
requires `peercap.Relay` and that the sender be one of the `ClientDisco`
(`magicsock.go:2482-2504`). The `CallMeMaybeVia` receive path simply lacks the
equivalent checks.

## Affected code

Dispatch (`wgengine/magicsock/magicsock.go`, `handleDiscoMessage`
`CallMeMaybe{Via}` case): gates only on `HasNATTraversal`, DERP origin, known
`derpNodeSrc`, `relayClientEnabled`, `relayCapable`, and that the sender's disco
key matches its endpoint — then:
```go
c.relayManager.handleCallMeMaybeVia(ep, lastBest, lastBestIsTrusted, via)
```
No validation of `via.ClientDisco` membership or `via.AddrPorts`.

Build + send (`wgengine/magicsock/relaymanager.go`):
```go
func (r *relayManager) handleCallMeMaybeVia(... dm *disco.CallMeMaybeVia) {
	se := udprelay.ServerEndpoint{
		ServerDisco: dm.ServerDisco, ClientDisco: dm.ClientDisco,
		LamportID: dm.LamportID, AddrPorts: dm.AddrPorts, VNI: dm.VNI,
	} ...                                   // all attacker-controlled
}
func (r *relayManager) handshakeServerEndpoint(work *relayHandshakeWork) {
	...
	for _, addrPort := range work.se.AddrPorts {
		if addrPort.IsValid() {
			go ep.c.sendDiscoMessage(epAddr{ap: addrPort, vni: vni}, key.NodePublic{},
				work.se.ServerDisco, bind, discoVerboseLog)   // one UDP packet per AddrPort
		}
	}
	...
}
```
`AddrPorts` is decoded bounded only by the DERP frame size (`MaxPacketSize =
64<<10`), i.e. up to ~thousands of entries per message. Handshake work is deduped
only by `{ServerDisco, VNI}` — both attacker-chosen — so distinct values create
distinct concurrent handshake goroutines (each with an ECDH).

## Preconditions (effectively default-on)

- Attacker is any peer known to the victim over DERP (same tailnet, or a
  shared-in node) advertising capability version ≥ 121 — any modern Tailscale
  node. `relayCapable` derives from that self-reported capver, not an ACL grant.
- Victim has `relayClientEnabled`, which is **true by default** (false only with
  the `disable-relay-client` node attr or `OnlyTCP443`).
- No `peercap` capability is required (unlike the allocation path).

## Impact

- **Reflection / source-spoofed fan-out:** one `CallMeMaybeVia` over DERP →
  the victim emits a UDP Bind packet to each attacker-chosen `AddrPort`,
  including arbitrary off-tailnet public IP:ports, with the **victim node** as
  the apparent source. Packet-count fan-out up to ~1:thousands.
- **Client resource exhaustion:** sustained messages with fresh
  `ServerDisco`/`VNI` accrue concurrent handshake goroutines + ECDH operations
  and map state on the victim → CPU/goroutine/memory DoS.

## Verification

Confirmed by complete source analysis of the receive→send path (dispatch →
`handleCallMeMaybeVia` → `handshakeServerEndpoint`); no `ClientDisco`/`AddrPorts`
validation exists between message receipt and the per-`AddrPort` send. No
runtime two-peer PoC was built (it requires a full magicsock + DERP + a
relay-capable peer); the issue is a verifiable absence of validation, and
contrasts with the authorized allocation path in the same file.

### Suggested confirming test
Feed a `CallMeMaybeVia` with a large `AddrPorts` list (and varied
`ServerDisco`/`VNI`) to `handleCallMeMaybeVia` and count outbound
`sendDiscoMessage` calls / live goroutines.

## Remediation
Before handshaking: require that `via.ClientDisco` includes this node's disco
key (mirroring the allocation path's sender∈`ClientDisco` check); cap
`len(AddrPorts)`; and cap concurrent handshake works per peer.

## References
- `wgengine/magicsock/magicsock.go` — `CallMeMaybe{Via}` dispatch; authorized
  sibling `AllocateUDPRelayEndpointRequest` path (`:2482-2504`)
- `wgengine/magicsock/relaymanager.go` — `handleCallMeMaybeVia`,
  `handshakeServerEndpoint`

## Disclosure
Reported privately to Tailscale (security@tailscale.com). No public disclosure
until a fix ships / per program policy.
