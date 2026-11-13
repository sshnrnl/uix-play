# Continuity Camera interoperability research

Goal: understand Apple Continuity Camera (iPhone as webcam) well enough to receive it on a
non-Apple desktop. Interop research on hardware we own (one iPhone, one MacBook Air, one Windows
PC). All findings and raw captures live here; narrative notes are in the repo-root `CLAUDE.md`.

## The stack (what we know as of 13 Nov 2026)

```
  iPhone  <--- Rapport (control, ENCRYPTED) --->  Mac
          <--- AVConference SRTP (video)     --->
  discovery: BLE + iCloud device list (NOT _companion-link bonjour)
```

- **Discovery:** the iPhone does not advertise `_companion-link._tcp`. On Wi-Fi it advertises
  `_apple-mobdev2._tcp`, `_remotepairing._tcp` (iOS17+ RemoteXPC), `_asquic._udp`. The Mac finds
  the phone for Continuity via Bluetooth LE + the iCloud device list, then connects.
- **Control plane = Rapport.** Per session, `ContinuityCaptureAgent` opens 3 TCP conns and
  `rapportd` 1, over `awdl0` to the phone (ports ~49159-49174). A persistent `rapportd` conn also
  runs over `en0` (normal Wi-Fi), port 56431<->49155. Rapport carries the AVC negotiation
  (`handleAVCNegotiation`, `createAVCVideoStream`) that sets up the video and its keys.
- **Video plane = SRTP.** RTP/UDP/IPv6, payload type 100, one SSRC, header-extension on every
  packet, ~424 KB/s for 720p. **Payload entropy 8.0 bits/byte => encrypted (SRTP).** RTCP
  (PT 201/204) flows back. Codec is invisible until decrypted. Keys come from the Rapport AVC
  negotiation. See `captures/` + `scripts/rtp_analyze.py`.

## The blocker (be honest)

To receive the video we must: (1) complete **Rapport pair-verify** (Apple-ID-backed device
identity; private keys in the Secure Enclave), then (2) recover the **SRTP keys** from the
encrypted AVC negotiation. No open-source implementation of either exists. `pymobiledevice3`
reaches lockdown/developer services, NOT Rapport. Signing into an Apple ID on the PC does not
provide the Rapport identity. This is a hard, possibly-infeasible RE project — that is the point
of doing it as research.

## Tracks

1. **Wire capture of the control plane** (ground truth for any reimplementation).
   - Capture `awdl0` + `en0` at a *fresh* session start to frame the AVC negotiation.
   - Needs root tcpdump on the Mac. Broaden the sudoers rule to `/usr/sbin/tcpdump` (any args).
   - `scripts/mac_capture.sh` orchestrates it (run on the Mac).
2. **Windows reachability** via `pymobiledevice3` over **USB**.
   - A stale RemotePairing record for the phone already exists on the PC; re-pair over USB:
     `pymobiledevice3 lockdown pair`, then `remote start-tunnel`, then `remote rsd-info`.
   - Enumerate services to confirm (as expected) that Continuity is not among them.
3. **Protocol reference.** Rapport pair-setup/verify is HAP-adjacent (SRP + Ed25519/Curve25519 +
   ChaC20-Poly1305, OPACK-encoded). pyatv implements the HAP variant for Companion/AirPlay; it is
   a structural reference, not a drop-in.

## Tooling
- `scripts/mdns_unicast_probe.py <ip>` — unicast mDNS service probe (gets past multicast-blocking routers).
- `scripts/rtp_analyze.py <pcap>` — RTP/RTCP flow + entropy analysis of a capture.
- `scripts/mac_capture.sh` — session-start multi-interface capture (run on the Mac).

## Legal / ethical
Interoperability research on our own devices. No DRM-for-piracy, no third-party devices, no
credential theft. If this ever moves toward redistribution, mind Apple-ID terms and DMCA §1201
interop provisions.
