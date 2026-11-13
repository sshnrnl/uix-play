# uix-play

Shan's fork of [FDH2/UxPlay](https://github.com/FDH2/UxPlay) (`origin` = sshnrnl/uix-play,
`upstream` = FDH2/UxPlay). UxPlay itself is an AirPlay mirror/audio receiver. The goal of this
fork is extra: get **iPhone Continuity Camera** (iPhone as a webcam) working on a non-Mac
desktop. Personal project, not Kyou work.

## Tools in this fork

- `tools/companion_browse.c`: lists Apple Rapport (`_companion-link._tcp`) devices on the LAN
  and prints host, port and TXT fields. Uses the system `dns_sd` API, because UxPlay's
  internal `lib/mdnsd` can only advertise, not browse.
  - Quick build: `cc -o companion-browse tools/companion_browse.c && ./companion-browse 10`
    (macOS; on Linux add `-I/usr/include/avahi-compat-libdns_sd -ldns_sd`; on Windows/MSYS2
    it needs the Bonjour SDK's `dns_sd.h` + `dnssd.lib`, plus `-lws2_32`, and the Bonjour service running).
  - Compile-checked 13 Nov 2026: MinGW gcc 16 (Apple `dns_sd.h`) and GCC 14 + Avahi, both clean with `-Wall -Wextra`.
  - CMake target `companion-browse` is defined in `lib/dns_sd/CMakeLists.txt`, so it only
    exists in dns_sd builds. Untested: the full configure needs pkg-config, GStreamer,
    OpenSSL and libplist.

## Continuity Camera notes (measured 13 Nov 2026, macOS 26.2, iPhone18,2)

How a session starts
- Opening the Camera app on the iPhone does nothing. A session starts only when an app on
  the Mac opens the "iPhone Camera" device.
- Easiest trigger from the terminal:
  `ffmpeg -f avfoundation -framerate 30 -video_size 1280x720 -pixel_format nv12 -i "iPhone Camera" -t 8 out.mp4`

What is on the network during a session
- Control: `ContinuityCaptureAgent` opens 3 TCP connections and `rapportd` opens 1, all over
  AWDL (`awdl0`, link-local IPv6) to the phone, on ports around 49157 to 49166. They close
  when the camera is released. Check with `lsof -nP -i | grep 'fe80:d::'`.
- Video: flows on `llw0` (low-latency WLAN). It reads 0 KB/s with the camera off and about
  68 KB/s for a still 720p scene. `awdl0` carries only about 1 KB/s.
- `en0` (normal Wi-Fi) is not used; its traffic is the same with the camera on or off.
- Measure per interface with `netstat -ibn` before and during a capture.
- The iPhone does not advertise `_companion-link._tcp` on Bonjour. The Mac finds it through
  Bluetooth LE and the iCloud device list. The Mac does advertise; its TXT has `rpVr`
  (Rapport version, 715.2), `rpFl` (flags), `rpBA` (rotating Bluetooth address) and the
  6-byte hashes `rpHI` `rpHA` `rpAD` `rpHN`, which are probably the Apple ID check.

What the system binaries show (strings, not traffic)
- `/usr/libexec/ContinuityCaptureAgent` is a CMIO camera extension
  (`com.apple.cmio.ContinuityCaptureAgent`) and links `Rapport.framework` and the private
  `CMContinuityCaptureCore.framework`.
- Video is carried by the AVConference stack (the FaceTime media engine, RTP), set up through
  a negotiation blob sent over Rapport (`handleAVCNegotiation`, `createAVCVideoStream`).
- Two transports: `CMContinuityCaptureTransportRapportDevice` (wireless) and
  `CMContinuityCaptureTransportSidecarDevice` (the Sidecar path, likely USB).

### Session 2 (13 Nov 2026, run from Windows over SSH; MacBook Air Mac16,12, macOS 26.2)

- SSH sessions are blocked from the camera by TCC (ffmpeg hangs with no frames). Workaround:
  run the capture inside the GUI session with
  `osascript -e 'tell application "Terminal" to do script "<script>; exit"'`.
- `ffmpeg ... -framerate 30 -video_size 1280x720 -i "iPhone Camera"` produced H.264 1280x720
  at about 59 fps (ffprobe `591/10`), so the phone delivered more than the requested 30 fps.
- Interface scopes: `fe80:b` = en0, `fe80:d` = awdl0, `fe80:e` = llw0 (same link-local address as
  awdl0), `fe80:14` = utun5.
- Byte counters over a 14 s window with a 10 s capture: llw0 in +1.6 MB (about 115 KB/s, the
  video), awdl0 out +680 KB and in +48 KB. en0 was noisy because of other traffic.
- Control channel: ContinuityCaptureAgent opens 3 TCP connections and rapportd opens 1 over awdl0
  to iPhone ports in the 49159 to 49174 range. Port numbers change each session.
- **New:** rapportd also keeps a TCP connection over **en0 (normal Wi-Fi)** from its listen port
  56431 to the iPhone's port 49155. It was already up before the session started, so Rapport
  does run over infrastructure Wi-Fi. Other rapportd listeners: TCP 55007, 55008; UDP 3722.
- `identityservicesd` (IDS, Apple ID identity) has TCP connections over utun5 during the session.
- `avconferenced` runs as the user but has **no BSD sockets** (lsof shows nothing, either before
  or during the session). The llw0 media path probably uses Skywalk/Network.framework channels,
  which lsof cannot see, so it has to be captured with tcpdump on llw0, which needs root.

### llw0 packet capture (13 Nov 2026, Discord using "iPhone Camera", 3.6 s / 1435 packets)

Captured with `sudo tcpdump -i llw0 -c 20000 -w /tmp/llw0.pcap` (link type EN10MB).
- **Transport: RTP over UDP over IPv6 ULA**, not link-local: phone `fdab:d035:db32::a` port
  60851 to Mac `fd40:c510:64dc::1f` port 61129. It is one UDP flow in each direction.
- Phone to Mac: about 1260 packets at about 424 KB/s; every packet is RTP v2, dynamic payload
  type 100, one SSRC, and **every packet has an RTP header extension** (`0x90` first byte).
  Packets are 1322 to 1330 bytes with many small ones. The timestamp steps by 800 per frame:
  60 fps if the clock is 48 kHz, 112.5 fps if it is 90 kHz (ffprobe saw about 59 fps, so 48 kHz?).
- Mac to phone: about 170 packets at about 2 KB/s. These are **RTCP**: first bytes `0x81 0xc9` (RR,
  PT 201) and PT 204 (APP), probably feedback and keyframe requests.
- **The payload is encrypted**: the RTP payload entropy is 8.000 bits/byte over 1.5 MB, and the
  first payload bytes are random rather than the H.264/HEVC NAL/FU headers that would repeat
  in cleartext. RTCP bodies look encrypted too. So this is SRTP/SRTCP or similar, and the keys
  must come from the Rapport/AVC negotiation (`handleAVCNegotiation`). The codec cannot be
  read from the wire.
- An analyzer script was used (pcap to RTP/RTCP stats plus entropy); it is easy to rewrite.

### Pairing attempt from Windows (13 Nov 2026, this PC)

Tooling: native Python 3.12 + `pyatv` and `pymobiledevice3` 11.54 (MSYS2 python can't build
`cryptography` without Rust; use the Windows python).

- **pyatv is the wrong tool.** It pairs with `_companion-link._tcp`, which Apple TV / HomePod
  expose but the **iPhone does not**. `atvremote --scan-hosts <iphone>` finds nothing.
- iPhone's advertised services (unicast mDNS, 13 Nov): `_apple-mobdev2._tcp` (:32498),
  `_remotepairing._tcp` (:49152, ver=26 minVer=8), `_asquic._udp` (:58879). The trust channel
  is **`_remotepairing._tcp`** = Apple's iOS 17+ RemoteXPC pairing = `pymobiledevice3` territory.
- `pymobiledevice3 remote browse` reports a **stale RemotePairing record already exists** for
  iPhone UDID `00008120-...` (`~/.pymobiledevice3/remote_*.plist`): so this PC was USB-paired to
  the phone before. It "predates altIRK recording", so it can't match over Wi-Fi bonjour; must
  re-pair over **USB** (`pymobiledevice3 lockdown remotepairing --pair`). No device on USB now.
- **Network RemoteXPC tunnel to the iPhone requires a current USB pairing record first.** So the
  next real step is a USB cable + Trust prompt, then `remote start-tunnel` and `remote rsd-info`
  to enumerate services.

### Honest blocker assessment

Even a full pymobiledevice3 tunnel (USB trust + Apple ID) yields **lockdown / developer (DVT)
services only** — it is NOT the Rapport channel Continuity Camera uses. The webcam path needs:
(1) Rapport **pair-verify** (Apple-ID-backed device identity, keys in the Secure Enclave), then
(2) the AVConference **SRTP key exchange** carried inside that encrypted negotiation. Neither has
an open-source implementation, and (1) is gated by Apple-ID identity that does not leave Apple's
OS. **Signing into an Apple ID on Windows does not bridge this** — the missing piece is the
Rapport auth stack, not an account login. Reimplementing it is a large RE effort with no
guarantee, and may run into Apple-ID / DMCA-interop concerns. Keep that in view before investing.

## Not known yet

- ~~Whether the RTP on `llw0` is encrypted~~: yes (see above). The codec on the wire is still
  unknown; it can only be seen after decryption.
- Where the SRTP keys come from: probably the AVC negotiation blob sent over Rapport, which
  is itself encrypted after pair-verify.
- What `llw0` is exactly and whether Linux can reproduce it.
- How to pass Rapport pairing without a device signed into the same Apple ID.

## Next steps

1. Capture the `llw0` traffic during a session (`tcpdump -i llw0`) and look at the packets.
2. Try Rapport pairing from Linux with pyatv's Companion protocol code.
3. Bring up AWDL on Linux with OWL (`seemoo-lab/owl`) and see if the iPhone answers.
