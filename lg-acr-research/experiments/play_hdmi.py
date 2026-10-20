#!/usr/bin/env python3
"""Local HDMI stimulus playback. No remote control or network access."""
import datetime as dt
import json
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = None
CLIPS = {'av': 'av.mp4', 'v': 'v_only.mp4', 'a': 'a_only.mp4'}


def player_command(ipc, command):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect(str(ipc))
        client.sendall((json.dumps({'command': command, 'request_id': 1}) + '\n').encode())
        with client.makefile('r') as replies:
            for line in replies:
                reply = json.loads(line)
                if reply.get('request_id') == 1:
                    if reply.get('error') != 'success':
                        raise RuntimeError('Player rejected the command.')
                    return reply.get('data')
    raise RuntimeError('No player acknowledgement.')


def wait_ready(player, ipc):
    for _ in range(100):
        if player.poll() is not None:
            raise RuntimeError('Player exited. Check the display/audio setup.')
        try:
            player_command(ipc, ['get_property', 'idle-active'])
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Player control did not become ready.')


def main():
    global ROOT
    parser=argparse.ArgumentParser(description='Local HDMI stimulus player. No TV/router connection.')
    parser.add_argument('--clips-dir', type=Path, required=True)
    parser.add_argument('--log-dir', type=Path, required=True)
    args=parser.parse_args()
    ROOT=args.clips_dir.resolve()
    os.umask(0o077)
    args.log_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not all((ROOT / name).is_file() for name in CLIPS.values()):
        raise SystemExit('Build the clips first.')
    log = args.log_dir / ('playback-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.jsonl')
    with tempfile.TemporaryDirectory(prefix='acr-e2-player-') as folder:
        ipc = Path(folder) / 'player.sock'
        bindings = Path(folder) / 'input.conf'
        bindings.write_text('q ignore\nQ ignore\nESC ignore\n')
        player = subprocess.Popen([
            'mpv', '--no-config', '--fullscreen', '--loop-file=inf', '--keep-open=yes',
            '--no-osc', '--osd-level=0', '--volume=100', '--resume-playback=no',
            '--input-terminal=no', '--input-conf=' + str(bindings),
            '--input-ipc-server=' + str(ipc), str(ROOT / CLIPS['av']),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_ready(player, ipc)
            with log.open('x') as record:
                log.chmod(0o600)
                record.write(json.dumps({'utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                                         'event': 'player_started', 'clip': 'av.mp4'}) + '\n')
                record.flush()
                print('Normal picture and sound are playing in a separate window.')
                print('Verify the TV shows the player and sound comes from the TV over HDMI.')
                print('At each router prompt, enter av, v, or a here, then confirm on the router.')
                print('av = normal; v = picture and silence; a = black picture and sound; q = quit.')
                print('Leave the video window open. Alt+Tab to THIS terminal to change clips.')
                print('Video-window q/Escape are disabled. Terminal q ends the whole playback session.')
                while True:
                    choice = input('Clip [av/v/a/q]: ').strip().lower()
                    if choice == 'q':
                        break
                    if choice not in CLIPS:
                        continue
                    try:
                        if player.poll() is not None:
                            raise RuntimeError('Player window was closed.')
                        player_command(ipc, ['loadfile', str(ROOT / CLIPS[choice]), 'replace'])
                    except (OSError, RuntimeError, ValueError):
                        record.write(json.dumps({'utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                                                 'event': 'playback_interrupted'}) + '\n')
                        record.flush()
                        print('Player closed or its control connection failed. Playback has stopped.')
                        print('Rerun this command, then verify HDMI picture and sound again.')
                        print('If a capture measurement was underway, mark that phase interrupted.')
                        break
                    record.write(json.dumps({'utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                                             'event': 'loadfile_acknowledged', 'clip': CLIPS[choice]}) + '\n')
                    record.flush()
                    print('Loaded ' + CLIPS[choice] + '. Visually/audibly verify before router confirmation.')
        except (KeyboardInterrupt, EOFError):
            pass
        except (OSError, RuntimeError) as error:
            print('Playback could not start: ' + str(error))
        finally:
            player.terminate()
            try:
                player.wait(timeout=5)
            except subprocess.TimeoutExpired:
                player.kill()
                player.wait()
    print('Playback ended. Local switch log: ' + log.name)


if __name__ == '__main__':
    main()
