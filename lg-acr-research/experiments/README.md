# Local stimulus tools

`build_clips.sh` converts a supplied private source into matched AV, silent-picture and black-picture-with-sound files. `play_hdmi.py` controls local mpv through a temporary Unix socket and records acknowledged switches. It does not prove each frame reached the TV or that its audio came from HDMI; physical verification is required.

No TV/router capture launcher or root exploit is included. The protocol and reasons for the controls are in docs/02-methods.md. The experiment was completed; these files do not start a new trial automatically.
