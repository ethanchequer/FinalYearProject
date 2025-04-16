# traffic_simulator.py

import subprocess
import time
import os

class TrafficSimulator:
    def simulate(self, application):
        if application == "Video Streaming":
            subprocess.Popen([
                "ffmpeg", "-re", "-i", "media/sample_video.mp4", "-f", "mpegts",
                "udp://127.0.0.1:1234"
            ])
            time.sleep(2)
        elif application == "File Transfer":
            subprocess.Popen(["python3", "-m", "http.server", "8080"])
            subprocess.Popen(["curl", "http://localhost:8080"])
            time.sleep(2)
        elif application == "Web Browsing":
            for _ in range(3):
                subprocess.Popen(["curl", "http://example.com"])
                time.sleep(1)
        elif application == "VoIP":
            subprocess.Popen(["bash", "-c", "while true; do echo 'test' | nc -u -w1 127.0.0.1 5060; sleep 1; done"])
            time.sleep(2)