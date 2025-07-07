#!/bin/bash
# SecurityForge Linux - Instalação de Ferramentas de Segurança

set -euo pipefail

# Este script será executado dentro do chroot
export DEBIAN_FRONTEND=noninteractive

log() { echo "[$(date +'%H:%M:%S')] $1"; }

log "Instalando ferramentas de reconhecimento..."
apt install -y nmap masscan zmap rustscan unicornscan hping3 dmitry

log "Instalando ferramentas de web testing..."
apt install -y nikto sqlmap dirb gobuster wfuzz whatweb wafw00f

log "Instalando ferramentas de network..."
apt install -y wireshark tshark tcpdump netcat socat netdiscover arp-scan

log "Instalando ferramentas de passwords..."
apt install -y john hashcat hydra medusa ncrack aircrack-ng

log "Instalando ferramentas de exploitation..."
apt install -y metasploit-framework searchsploit exploitdb

log "Instalando ferramentas de forense..."
apt install -y autopsy sleuthkit foremost scalpel binwalk

log "Instalando linguagens e frameworks..."
apt install -y python3-full python3-pip ruby-full golang-go nodejs npm

log "Instalando ferramentas Python..."
pip3 install --break-system-packages requests beautifulsoup4 scapy pwntools volatility3

log "Instalando Docker..."
apt install -y docker.io docker-compose
systemctl enable docker

log "Ferramentas de segurança instaladas com sucesso!"