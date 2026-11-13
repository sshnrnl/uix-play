# iPhone-side capture via USB pcapd (13 Nov 2026)

Instrument: `pymobiledevice3 pcap --out x.pcapng` on Windows, iPhone on USB, Continuity session
triggered on the Mac. Captures all iPhone interfaces with per-packet **process attribution** —
no Mac root, no AWDL stack on the PC. 15 s session, ~5,389 frames. Parsed with scapy.

## What the iPhone sends/receives during a session

| Flow | Pkts | What |
|---|---|---|
| `fd21:…::d`.58238 → `fd36:…::22`.61056 | 3079 | **Video**, RTP v2, **PT 100**, 1 SSRC, sizes 399/1347-1368, **entropy 7.997 → SRTP-encrypted** |
| `fd36:…::22`.61056 → `fd21:…::d`.58238 | 847 | **RTCP** feedback (first bytes `81 c9` = RR/PT201, PT204) |
| awdl0 fe80…:**320** ↔ fe80…:320 | 319 | **PTP** (IEEE-1588) general msgs — media clock, cleartext (`1b 02…`) |
| awdl0 fe80…:**319** ↔ fe80…:319 | 142 | **PTP** event msgs (`10 02…`), cleartext |
| TCP (continuitycapture/rapportd) | 758 | control, high-entropy, **NOT TLS record framing** (no `16 03`/`17 03`) |
| 17.248.x.x:443 (QUIC) | ~60 | incidental iCloud/APNs |

Processes (pcapd attribution): `mediaserverd`/media stack (video), `clocksyncd` (PTP),
`rapportd` + `continuitycapture` (control), `cloudd`/`apsd`/`mDNSResponder` (incidental).

## Conclusions

- **Video confirmed SRTP from both ends.** PT 100, encrypted (entropy ~8.0). Same on the Mac's
  llw0 receive side and the iPhone's send side. Codec invisible without the key.
- **The clock is standard PTP** over AWDL (ports 319/320), in cleartext. A reimplementation can
  speak PTP directly; this is not the hard part.
- **Rapport control is custom-encrypted, not TLS.** So its key schedule comes from Rapport
  pair-verify, and the AVC/SRTP keys are derived inside it. This is the one true blocker.
- **Per-session ephemeral ULA IPv6** addresses (differ every session).
- pcapd captures the video on the iPhone **send** side (BPF sees it here), unlike Mac-side where
  the sender's sockets were invisible to lsof — useful asymmetry for future work.

## Rapport transport framing (handshake capture, 13 Nov 2026)

Reassembled the control TCP streams (en0 persistent `rapportd` :56431<->:49155, and awdl0
`continuitycapture` :49447<->:65136). Frame format is confirmed:

```
  frame = type(1) | length(3, big-endian) | body
  type 0x08 = encrypted application frame
```

Streams walk cleanly as sequences of 0x08 frames, e.g. en0 rapportd one direction =
`(8,98)(8,147)(8,98)(8,121)(8,317)`, other = `(8,329)(8,117)(8,56)(8,385)`; awdl0
`(8,471)(8,631)(8,634)(8,631)`. Bodies are high-entropy (encrypted) from the **first** frame.
One large awdl0 frame `(8,665)` is followed by a non-0x08 region (a different sub-stream /
bulk payload) — to be split out later.

**Why no cleartext keys:** the iPhone and Mac already hold a persistent Rapport pairing (set up
once via iCloud), so each session runs only **pair-verify**, and its messages are inside the
0x08 encrypted framing from byte 0. A cleartext **pair-setup** (ephemeral curve25519 keys, SRP)
only happens on a device's first-ever trust. Capturing that would require breaking the existing
pairing (sign out of iCloud / unpair both ends) — disruptive, and the resulting keys are still
bound to Apple-ID device identity (Secure Enclave). That is the wall.

## Net: the only missing piece is the Rapport pair-verify key schedule

Everything else (discovery surface, RTP/RTCP framing, PTP clock, Windows trust) is mapped. To
decrypt the video we need the SRTP keys, which live behind Rapport pair-verify (Apple-ID device
identity). That handshake is the remaining research frontier.
