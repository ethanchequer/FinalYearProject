```markdown
# PQC Benchmarking Web App

This Flask-based web application allows users to benchmark Post-Quantum Cryptographic (PQC) algorithms against real-time application simulations. It evaluates algorithm performance using metrics like execution time, CPU and memory usage, latency, and throughput.

## Features
- Real-time traffic simulation for Web Browsing, VoIP, Video Streaming, and File Transfer
- Encryption/signing using Kyber512, Dilithium2, SPHINCS+-SHA2-128s
- Live packet capture and performance logging
- AI-powered algorithm recommendation based on test results
- Dynamic Chart.js visualizations for latency and resource usage

## Getting Started

### Prerequisites
- Python 3.12+
- pip
- Raspberry Pi (if deploying)

### Installation
```bash
git clone https://github.com/YOUR_USERNAME/your-repo-name.git
cd your-repo-name
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running the App (Locally)
```bash
sudo gunicorn -w 1 -b 0.0.0.0:8000 app:app
```

### Running the App (Raspberry Pi)
Make sure you're in the project directory and your dependencies are installed:
```bash
git pull origin main
source .venv/bin/activate
sudo gunicorn -w 1 -b 0.0.0.0:8000 app:app
```

### Recommended Setup for Raspberry Pi
- Use a virtual environment
- Run on localhost, port 8000
- Ensure `ffmpeg`, `netcat`, `curl`, and `lsof` are installed for traffic simulation

### Useful Routes
- `/` - Homepage
- `/benchmark` - Start a single test
- `/run_tests/<algorithm>` - Run all tests for one algorithm
- `/run_all_algorithms_for_application` - Test all algorithms for one application
- `/report` - View test results and graphs


## License
MIT
```
```
