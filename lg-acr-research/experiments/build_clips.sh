#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
: "${1:?Usage: bash build_clips.sh PRIVATE_CLIPS_DIRECTORY}"
cd -- "$1"
test -s source.mp4
# Both experimental files retain a video stream and an audio stream.
ffmpeg -hide_banner -loglevel error -nostdin -y -i source.mp4 -t 37 \
 -map 0:v:0 -map 0:a:0 -vf 'scale=1280:720,setsar=1,fps=25' \
 -c:v libx264 -preset fast -crf 20 -pix_fmt yuv420p -threads 2 \
 -c:a aac -b:a 160k -ar 48000 -ac 2 -movflags +faststart av.mp4
ffmpeg -hide_banner -loglevel error -nostdin -y -i av.mp4 \
 -f lavfi -i 'anullsrc=r=48000:cl=stereo' -t 37 \
 -map 0:v:0 -map 1:a:0 -c:v copy -c:a aac -b:a 160k \
 -movflags +faststart v_only.mp4
ffmpeg -hide_banner -loglevel error -nostdin -y \
 -f lavfi -i 'color=c=black:s=1280x720:r=25' -i av.mp4 -t 37 \
 -map 0:v:0 -map 1:a:0 -c:v libx264 -preset fast -crf 20 \
 -pix_fmt yuv420p -threads 2 -c:a copy -movflags +faststart a_only.mp4
sha256sum source.mp4 av.mp4 v_only.mp4 a_only.mp4 > clips-sha256.txt
printf 'Prepared 37-second looping clips: AV, silent picture, and sound with black picture.\n'
