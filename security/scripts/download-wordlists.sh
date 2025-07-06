#!/bin/bash
# SecurityForge Linux - Download de Wordlists Famosas

set -euo pipefail

WORDLIST_DIR="/opt/securityforge/wordlists"
LOG_FILE="/var/log/securityforge/wordlist-download.log"

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}✅ $1${NC}" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}❌ $1${NC}" | tee -a "$LOG_FILE"; }

echo "📚 SecurityForge Wordlist Downloader"
echo "===================================="

# Criar diretório e configurar permissões
mkdir -p "$WORDLIST_DIR"
mkdir -p "$(dirname "$LOG_FILE")"
cd "$WORDLIST_DIR"

# Verificar conectividade
if ! ping -c 1 google.com &> /dev/null; then
    error "Sem conectividade com internet"
    exit 1
fi

# RockYou
if [ ! -f "rockyou.txt" ]; then
    log "Baixando RockYou wordlist..."
    if curl -L -o rockyou.txt.gz "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>/dev/null; then
        success "RockYou baixado"
    else
        warning "Falha ao baixar RockYou, criando versão básica..."
        head -1000 common-passwords.txt > rockyou.txt
    fi
else
    success "RockYou já existe"
fi

# SecLists
if [ ! -d "seclists" ]; then
    log "Clonando SecLists..."
    if git clone https://github.com/danielmiessler/SecLists.git seclists 2>/dev/null; then
        success "SecLists clonado"
    else
        warning "Falha ao clonar SecLists"
    fi
else
    success "SecLists já existe"
fi

# PayloadsAllTheThings
if [ ! -d "payloadsallthethings" ]; then
    log "Clonando PayloadsAllTheThings..."
    if git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git payloadsallthethings 2>/dev/null; then
        success "PayloadsAllTheThings clonado"
    else
        warning "Falha ao clonar PayloadsAllTheThings"
    fi
else
    success "PayloadsAllTheThings já existe"
fi

# FuzzDB
if [ ! -d "fuzzdb" ]; then
    log "Clonando FuzzDB..."
    if git clone https://github.com/fuzzdb-project/fuzzdb.git fuzzdb 2>/dev/null; then
        success "FuzzDB clonado"
    else
        warning "Falha ao clonar FuzzDB"
    fi
else
    success "FuzzDB já existe"
fi

# Criar links simbólicos úteis
log "Criando links simbólicos..."
[ -f "seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt" ] && ln -sf "seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt" "top-1million-passwords.txt"
[ -f "seclists/Discovery/Web-Content/common.txt" ] && ln -sf "seclists/Discovery/Web-Content/common.txt" "common-directories.txt"
[ -f "seclists/Usernames/top-usernames-shortlist.txt" ] && ln -sf "seclists/Usernames/top-usernames-shortlist.txt" "common-usernames.txt"

# Configurar permissões
chown -R secforge:secforge "$WORDLIST_DIR" 2>/dev/null || warning "Erro ao configurar proprietário"
chmod -R 644 "$WORDLIST_DIR"/*.txt 2>/dev/null || true

success "Download de wordlists concluído!"
echo ""
echo "📁 Wordlists disponíveis em: $WORDLIST_DIR"
echo "📊 Total de arquivos: $(find "$WORDLIST_DIR" -type f | wc -l)"
echo "💾 Espaço usado: $(du -sh "$WORDLIST_DIR" | cut -f1)"
