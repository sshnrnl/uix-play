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

## Net: the only missing piece is the Rapport pair-verify key schedule

Everything else (discovery surface, RTP/RTCP framing, PTP clock, Windows trust) is mapped. To
decrypt the video we need the SRTP keys, which live behind Rapport pair-verify (Apple-ID device
identity). That handshake is the remaining research frontier.
