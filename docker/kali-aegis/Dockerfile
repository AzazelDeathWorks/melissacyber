# melissacyber attack sandbox image — Kali + the ~120-tool surface.
# Build: docker build -t melissacyber/kali-aegis:latest docker/kali-aegis
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    kali-linux-headless \
    tmux curl wget netcat-traditional socat \
    nmap masscan dnsutils whois \
    nikto gobuster dirb ffuf whatweb wapiti \
    sqlmap hydra john hashcat \
    metasploit-framework \
    exploitdb searchsploit \
    gdb gdb-peda \
    python3 python3-pip python3-venv \
    git jq ripgrep \
    openssl ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Agents run as an unprivileged user inside the box.
RUN useradd -m -s /bin/bash aegis
USER aegis
WORKDIR /home/aegis
CMD ["sleep", "infinity"]
