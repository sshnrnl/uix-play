#!/bin/bash
# Capture the Continuity Camera CONTROL plane at a fresh session start.
# Run ON THE MAC. Needs: broadened sudoers (NOPASSWD: /usr/sbin/tcpdump), homebrew ffmpeg.
# The video plane is SRTP-encrypted; the point here is the awdl0/en0 negotiation framing.
#
# Usage: mac_capture.sh [seconds]   (default 25)
set -u
SECS=${1:-25}
PHONE_V4=192.168.100.140
D=~/uixplay-research; mkdir -p "$D"; cd "$D" || exit 1
export PATH=/opt/homebrew/bin:$PATH

command -v ffmpeg >/dev/null || { echo "need homebrew ffmpeg"; exit 1; }
sudo -n /usr/sbin/tcpdump --version >/dev/null 2>&1 || {
  echo "sudoers not broadened. Add to /etc/sudoers.d/uixplay-research:"
  echo "  $(whoami) ALL=(root) NOPASSWD: /usr/sbin/tcpdump"; exit 1; }

STAMP=$(date +%Y%m%d_%H%M%S)
echo "capturing awdl0 + en0 for ${SECS}s, stamp=$STAMP"
sudo -n /usr/sbin/tcpdump -i awdl0 -s0 -G "$SECS" -W1 -w "$D/awdl0_$STAMP.pcap" >/dev/null 2>&1 &
sudo -n /usr/sbin/tcpdump -i en0   -s0 -G "$SECS" -W1 -w "$D/en0_$STAMP.pcap" \
     "host $PHONE_V4" >/dev/null 2>&1 &
sleep 2
# trigger a fresh session from the GUI login session (SSH can't open the camera: TCC)
osascript -e "tell application \"Terminal\" to do script \"/opt/homebrew/bin/ffmpeg -hide_banner -loglevel error -f avfoundation -framerate 30 -video_size 1280x720 -pixel_format nv12 -i 'iPhone Camera' -t $((SECS-4)) -y ~/uixplay-research/sess_$STAMP.mp4; exit\"" >/dev/null
wait
echo "done:"; ls -la "$D"/*_"$STAMP".pcap "$D/sess_$STAMP.mp4" 2>/dev/null
