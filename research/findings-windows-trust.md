# Windows → iPhone trust: what the developer tunnel reaches (13 Nov 2026)

Setup: native Python 3.12 + pymobiledevice3 11.54 on the Windows PC, iPhone 17 Pro Max
(iPhone18,2, iOS 27.2) over USB. Apple Mobile Device Service must be restarted after plug-in
or usbmux shows no device; the iPhone exposes only its PTP/camera (WPD) interface until it is
**unlocked and the "Trust This Computer" prompt is accepted** — then the usbmux data interface
appears.

## Result: lockdown pairing works, Continuity is not in reach

- `pymobiledevice3 lockdown pair` → Trust prompt → paired. `lockdown info` returns full data, so
  this PC is now a trusted host.
- `pymobiledevice3 remote rsd-info` builds a RemoteXPC tunnel over USB (no root needed) and
  enumerates **62 services**. All are developer / diagnostic / management:
  afc, installation_proxy, mobilebackup2, mobilesync, crashreport*, diagnostics_relay,
  os_trace_relay, syslog_relay, webinspector, GPUTools, debugserver-adjacent, notification_proxy,
  springboardservices, house_arrest, etc.
- **None is Continuity Camera / Rapport / AVConference / any camera or media-streaming service.**
  (`com.apple.corecaptured.remoteservice` is Wi-Fi/BT firmware packet logging, not a camera.)

**Conclusion (definitive):** Continuity Camera is gated behind **Rapport**, a trust domain
entirely separate from lockdown/RemoteXPC. Pairing/trusting from Windows — even with an Apple ID —
does not place us in the Rapport domain and does not expose the camera. The "reach Continuity by
pairing from Windows" hypothesis is answered: **no.**

## Useful byproducts for the research

- `com.apple.pcapd` is reachable → **iPhone-side packet capture over USB from Windows**
  (`pymobiledevice3 pcap`), all phone interfaces incl. awdl0/llw0, no Mac root needed. This is a
  better instrument for Track 1 (wire capture of the Rapport/AVC handshake) than Mac-side tcpdump.
- The iPhone's USB **PTP/UVC camera interface** (the WPD device seen on plug-in) is the practical
  wired-webcam path that apps like Camo/EpocCam use. Not Continuity, but it works today.

## Remaining avenues (honest)

1. **Rapport RE** (hard, maybe infeasible): reverse pair-verify (Apple-ID/Secure-Enclave identity)
   + the AVC SRTP key exchange. No open-source base exists.
2. **iPhone-side capture via pcapd** to study the handshake framing from the phone's view.
3. **Pragmatic pivot**: USB PTP/UVC interface for an actual working webcam.
