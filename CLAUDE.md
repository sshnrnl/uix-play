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

## Not known yet

- Whether the RTP on `llw0` is encrypted, and its codec on the wire (H.264 or HEVC).
- What `llw0` is exactly and whether Linux can reproduce it.
- How to pass Rapport pairing without a device signed into the same Apple ID.

## Next steps

1. Capture the `llw0` traffic during a session (`tcpdump -i llw0`) and look at the packets.
2. Try Rapport pairing from Linux with pyatv's Companion protocol code.
3. Bring up AWDL on Linux with OWL (`seemoo-lab/owl`) and see if the iPhone answers.
