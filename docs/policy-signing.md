# Policy bundle signing (C2)

The agent hot-swaps policy bundles from the console into the kernel. Signing makes that bundle
**authentic**: a stolen control-plane token (present on every node) or a compromised console cannot
push a bundle that strips `kill` actions or whitelists an attacker's chain. ed25519 (asymmetric) — the
signing pusher holds the **private** key; agents carry only the **public** key and verify.

## Keys
```
ariguard-ctl keygen --out ariguard-policy    # writes ariguard-policy.key (private) + .pub (public)
```
Keep `.key` secret (the signing host / CI only). The `.pub` is safe to distribute.

## Agent (verify)
Give agents the public key via Helm; they then verify every control-plane bundle before loading it:
```
helm upgrade ... --set-file agent.policySigning.publicKey=ariguard-policy.pub   # or paste the base64
```
This mounts the key and adds `--policy-pubkey=/etc/ariguard/policy.pub`. Verification is **fail-closed**:
a bad or missing signature on a control-plane push is rejected and the agent keeps its last-good policy.
The baked `--bundle` file is verified only if a `<bundle>.sig` sidecar is present (it ships inside the
trusted immutable image); a present-but-invalid sidecar is fatal.

Empty `publicKey` = no verification (backward-compatible).

## Signing pusher (sign + push)
Build the bundle, then sign and push it with the private key instead of an unsigned push:
```
ariguard-ctl policy push --url http://console:8080 --token "$ARIGUARD_TOKEN" \
  --key ariguard-policy.key bundle.bin
```
`policy push` signs the bundle and PUTs it with the detached signature in the `X-Policy-Signature`
header; the console stores it and serves it back to agents. To sign only (e.g. for a baked bundle's
`.sig` sidecar): `ariguard-ctl policy sign --key ariguard-policy.key bundle.bin > bundle.bin.sig`.

## Rotation
Generate a new keypair, roll the agents to the new `.pub` first (they accept only the new key), then
switch the pusher to the new `.key`. (A dual-key grace window is a future enhancement.)

## Not yet (follow-ups)
- The rulegen CronJob still pushes unsigned (the Python loop has no ed25519); to sign automatically it
  needs `ariguard-ctl` in the rulegen image and a build→sign→push step. Until then, sign/push from CI
  or an operator step with `ariguard-ctl`.
- **Anti-rollback**: a valid but *old* signed bundle can still be replayed. A monotonic, signed version
  (rejecting a bundle with version ≤ the last applied) is the planned mitigation.
