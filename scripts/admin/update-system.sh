#!/bin/bash
# SecurityForge Linux - Atualização Ultra-Completa do Sistema

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
header() { echo -e "${PURPLE}$1${NC}"; }

header "🔄 SECURITYFORGE LINUX - ATUALIZAÇÃO COMPLETA"
header "=============================================="

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Backup de configurações críticas
BACKUP_DIR="/var/backups/securityforge-$(date +%Y%m%d_%H%M%S)"
log "Criando backup em: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp -r /etc/apt/ "$BACKUP_DIR/" 2>/dev/null || warning "Erro no backup do APT"
cp -r /opt/securityforge/configs/ "$BACKUP_DIR/" 2>/dev/null || warning "Erro no backup das configurações"

# Atualizar repositórios
log "Atualizando repositórios..."
apt update

# Verificar e corrigir pacotes quebrados
log "Verificando integridade dos pacotes..."
apt --fix-broken install -y
dpkg --configure -a

# Atualizar sistema base
log "Atualizando sistema base..."
apt upgrade -y
apt full-upgrade -y

# Remover pacotes órfãos
log "Removendo pacotes desnecessários..."
apt autoremove -y
apt autoclean

# Atualizar ferramentas Python
log "Atualizando ferramentas Python..."
pip3 install --upgrade pip setuptools wheel
pip3 list --outdated --format=freeze | grep -v '^-e' | cut -d = -f 1 | xargs -n1 pip3 install -U 2>/dev/null || warning "Alguns pacotes Python falharam"

# Atualizar ferramentas Ruby
log "Atualizando gems Ruby..."
gem update --system
gem update

# Atualizar ferramentas Node.js
log "Atualizando packages Node.js..."
npm update -g

# Atualizar ferramentas Go
log "Atualizando ferramentas Go..."
if [ -d "/opt/go" ]; then
    export GOPATH="/opt/go"
    export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"
    go clean -modcache
    
    # Atualizar ferramentas Go específicas
    go install -a github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -a github.com/tomnomnom/assetfinder@latest
    go install -a github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -a github.com/ffuf/ffuf@latest
    go install -a github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
fi

# Atualizar repositórios Git
log "Atualizando repositórios Git..."
find /opt/securityforge/tools -name ".git" -type d | while read git_dir; do
    repo_dir="$(dirname "$git_dir")"
    cd "$repo_dir"
    repo_name="$(basename "$repo_dir")"
    log "Atualizando $repo_name..."
    git pull origin master 2>/dev/null || git pull origin main 2>/dev/null || warning "Falha ao atualizar $repo_name"
done

# Atualizar wordlists
log "Atualizando wordlists..."
if [ -f "/opt/securityforge/scripts/download-wordlists.sh" ]; then
    bash "/opt/securityforge/scripts/download-wordlists.sh"
fi

# Atualizar kernels e módulos
log "Verificando atualizações de kernel..."
if [ $(apt list --upgradable 2>/dev/null | grep -c linux-image) -gt 0 ]; then
    warning "Nova versão do kernel disponível. Considere reiniciar após a atualização."
fi

# Verificar serviços críticos
log "Verificando serviços críticos..."
for service in ssh ufw fail2ban docker; do
    if systemctl is-active --quiet "$service"; then
        success "Serviço $service: Ativo"
    else
        warning "Serviço $service: Inativo"
    fi
done

# Limpar cache
log "Limpando cache do sistema..."
apt autoclean
apt autoremove -y
journalctl --vacuum-time=7d

# Atualizar banco de dados de arquivos
log "Atualizando banco de dados de arquivos..."
updatedb

success "Atualização completa finalizada!"
echo ""
header "📊 RESUMO DA ATUALIZAÇÃO"
echo "Backup criado em: $BACKUP_DIR"
echo "Pacotes atualizados: $(apt list --upgradable 2>/dev/null | wc -l) disponíveis"
echo "Espaço liberado: $(du -sh /var/cache/apt/archives/ | cut -f1) em cache"
echo ""
header "💡 RECOMENDAÇÕES PÓS-ATUALIZAÇÃO"
echo "1. Reiniciar o sistema se houver atualizações de kernel"
echo "2. Verificar logs: journalctl -xe"
echo "3. Testar ferramentas críticas"
echo "4. Executar auditoria de segurança: secforge-audit"
