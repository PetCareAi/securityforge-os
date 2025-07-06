#!/bin/bash
# SecurityForge Linux - Sistema de Backup Completo

set -euo pipefail

# Configurações
BACKUP_BASE_DIR="/var/backups/securityforge"
DATE_FORMAT="%Y%m%d_%H%M%S"
CURRENT_DATE=$(date +"$DATE_FORMAT")
BACKUP_DIR="$BACKUP_BASE_DIR/backup_$CURRENT_DATE"
LOG_FILE="/var/log/securityforge/backup.log"
RETENTION_DAYS=30

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

echo "💾 SecurityForge Linux - Sistema de Backup"
echo "=========================================="

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Criar diretórios
mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")"

log "Iniciando backup completo em: $BACKUP_DIR"

# Backup das configurações do sistema
log "Fazendo backup das configurações do sistema..."
mkdir -p "$BACKUP_DIR/system"
tar -czf "$BACKUP_DIR/system/etc.tar.gz" /etc/ 2>/dev/null || warning "Erro parcial no backup do /etc"
tar -czf "$BACKUP_DIR/system/var-log.tar.gz" /var/log/ 2>/dev/null || warning "Erro parcial no backup dos logs"

# Backup do SecurityForge
log "Fazendo backup do SecurityForge..."
if [ -d "/opt/securityforge" ]; then
    mkdir -p "$BACKUP_DIR/securityforge"
    tar -czf "$BACKUP_DIR/securityforge/opt-securityforge.tar.gz" /opt/securityforge/ 2>/dev/null || warning "Erro no backup do SecurityForge"
fi

# Backup dos dados do usuário
log "Fazendo backup dos dados do usuário..."
mkdir -p "$BACKUP_DIR/users"
if [ -d "/home/secforge" ]; then
    tar -czf "$BACKUP_DIR/users/secforge-home.tar.gz" /home/secforge/ 2>/dev/null || warning "Erro no backup do home do usuário"
fi

# Backup da lista de pacotes instalados
log "Fazendo backup da lista de pacotes..."
mkdir -p "$BACKUP_DIR/packages"
dpkg --get-selections > "$BACKUP_DIR/packages/installed-packages.txt"
apt-mark showmanual > "$BACKUP_DIR/packages/manual-packages.txt"

# Backup das chaves SSH
log "Fazendo backup das chaves SSH..."
mkdir -p "$BACKUP_DIR/ssh"
if [ -d "/etc/ssh" ]; then
    cp -r /etc/ssh/ "$BACKUP_DIR/ssh/" 2>/dev/null || warning "Erro no backup das chaves SSH"
fi

# Criar manifesto do backup
log "Criando manifesto do backup..."
cat > "$BACKUP_DIR/MANIFEST.txt" << MANIFEST_EOF
SecurityForge Linux - Manifesto de Backup
========================================
Data: $(date)
Host: $(hostname)
Versão SecurityForge: 3.1.0
Sistema: $(lsb_release -d | cut -f2)
Usuário: $(whoami)

Conteúdo do Backup:
- Configurações do sistema (/etc)
- Logs do sistema (/var/log)
- SecurityForge completo (/opt/securityforge)
- Dados do usuário (/home/secforge)
- Lista de pacotes instalados
- Chaves SSH

Tamanho total: $(du -sh "$BACKUP_DIR" | cut -f1)
Arquivos: $(find "$BACKUP_DIR" -type f | wc -l)
MANIFEST_EOF

# Gerar checksums
log "Gerando checksums..."
cd "$BACKUP_DIR"
find . -type f -exec md5sum {} ; > checksums.md5

# Remover backups antigos
log "Removendo backups antigos (mais de $RETENTION_DAYS dias)..."
find "$BACKUP_BASE_DIR" -type d -name "backup_*" -mtime +$RETENTION_DAYS -exec rm -rf {} ; 2>/dev/null || true

# Compactar backup completo
log "Compactando backup..."
cd "$BACKUP_BASE_DIR"
tar -czf "SecurityForge-Backup-$CURRENT_DATE.tar.gz" "backup_$CURRENT_DATE/"
rm -rf "backup_$CURRENT_DATE/"

success "Backup concluído!"
echo ""
echo "📁 Arquivo de backup: $BACKUP_BASE_DIR/SecurityForge-Backup-$CURRENT_DATE.tar.gz"
echo "📊 Tamanho: $(du -sh "$BACKUP_BASE_DIR/SecurityForge-Backup-$CURRENT_DATE.tar.gz" | cut -f1)"
echo "🔍 Checksums: incluídos no backup"
echo ""
echo "Para restaurar:"
echo "  tar -xzf SecurityForge-Backup-$CURRENT_DATE.tar.gz"
echo "  ./restore-backup.sh"
