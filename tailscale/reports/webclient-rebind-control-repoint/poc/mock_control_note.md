# Minimal attacker "control server" for the PoC

A full malicious control server is out of scope to ship here, but the repoint
itself is proven by observing the node's outbound registration hitting an
attacker URL. For a self-contained demonstration of the *repoint* (not the
downstream RCE), point `ControlURL` at any HTTPS endpoint you control and
observe tailscaled's `POST /machine/register` (Noise) connection arrive.

To demonstrate the CRITICAL downstream (root RCE when the victim had `--ssh`),
use the open-source control plane **headscale** or Tailscale's own
`cmd/testcontrol` as the attacker control, and serve a netmap whose
`SSHPolicy` contains:

    {
      "action": {"accept": true},
      "principals": [{"any": true}],
      "sshUsers": {"*": "root"}
    }

Then SSH from the attacker node to the repointed victim and receive a root
shell. (See report.md "Impact ceiling".) Run only in a disposable VM.
