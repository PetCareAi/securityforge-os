#!/bin/bash
# SecurityForge Linux - Auditoria de Segurança Avançada

set -euo pipefail

# Configurações
REPORT_DIR="/opt/securityforge/reports"
REPORT_FILE="$REPORT_DIR/security-audit-$(date +%Y%m%d_%H%M%S).txt"
TEMP_DIR="/tmp/securityforge-audit"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$REPORT_FILE"; }
success() { echo -e "${GREEN}✅ $1${NC}" | tee -a "$REPORT_FILE"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}" | tee -a "$REPORT_FILE"; }
error() { echo -e "${RED}❌ $1${NC}" | tee -a "$REPORT_FILE"; }
header() { echo -e "${PURPLE}$1${NC}" | tee -a "$REPORT_FILE"; }
info() { echo -e "${CYAN}$1${NC}" | tee -a "$REPORT_FILE"; }

# Preparar ambiente
mkdir -p "$REPORT_DIR" "$TEMP_DIR"

# Banner do relatório
cat > "$REPORT_FILE" << 'AUDIT_HEADER'
╔═══════════════════════════════════════════════════════════════════════════════╗
║                🛡️  SECURITYFORGE LINUX - AUDITORIA DE SEGURANÇA              ║
╚═══════════════════════════════════════════════════════════════════════════════╝
AUDIT_HEADER

echo "Data: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "Usuário: $(whoami)" >> "$REPORT_FILE"
echo "Sistema: $(lsb_release -d | cut -f2)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

header "🔍 SECURITYFORGE LINUX - AUDITORIA DE SEGURANÇA AVANÇADA"
header "========================================================"

# 1. INFORMAÇÕES DO SISTEMA
header "📊 1. INFORMAÇÕES DO SISTEMA"
info "Sistema Operacional: $(lsb_release -d | cut -f2)"
info "Kernel: $(uname -r)"
info "Arquitetura: $(uname -m)"
info "Uptime: $(uptime -p)"
info "Carga do sistema: $(uptime | awk -F'load average:' '{print $2}')"
info "Memória total: $(free -h | awk 'NR==2{print $2}')"
info "Memória disponível: $(free -h | awk 'NR==2{print $7}')"
info "Espaço em disco (/): $(df -h / | awk 'NR==2{print $4}') disponível"
echo ""

# 2. VERIFICAÇÕES DE REDE
header "🌐 2. ANÁLISE DE REDE"
log "Verificando interfaces de rede..."
ip addr show | grep -E "(inet|inet6)" | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando portas abertas..."
echo "Portas TCP em escuta:" >> "$REPORT_FILE"
ss -tulnp | grep LISTEN | head -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando conexões ativas..."
echo "Conexões estabelecidas:" >> "$REPORT_FILE"
ss -tuln | grep ESTAB | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 3. VERIFICAÇÕES DE USUÁRIOS E AUTENTICAÇÃO
header "👥 3. USUÁRIOS E AUTENTICAÇÃO"
log "Verificando usuários do sistema..."
echo "Usuários com shell válido:" >> "$REPORT_FILE"
grep -E "(bash|sh|zsh)" /etc/passwd >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando últimos logins..."
echo "Últimos 10 logins:" >> "$REPORT_FILE"
last -n 10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando tentativas de login falharam..."
echo "Falhas de autenticação recentes:" >> "$REPORT_FILE"
grep "authentication failure" /var/log/auth.log | tail -5 >> "$REPORT_FILE" 2>/dev/null || echo "Nenhuma falha de autenticação encontrada" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 4. VERIFICAÇÕES DE PROCESSOS
header "⚙️ 4. ANÁLISE DE PROCESSOS"
log "Verificando processos em execução..."
echo "Top 10 processos por uso de CPU:" >> "$REPORT_FILE"
ps aux --sort=-%cpu | head -11 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Top 10 processos por uso de memória:" >> "$REPORT_FILE"
ps aux --sort=-%mem | head -11 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando processos suspeitos..."
SUSPICIOUS_PROCESSES=(nc netcat socat ncat telnet)
for proc in "${SUSPICIOUS_PROCESSES[@]}"; do
    if pgrep "$proc" > /dev/null; then
        warning "Processo suspeito encontrado: $proc"
    fi
done

# 5. VERIFICAÇÕES DE SEGURANÇA
header "🔒 5. CONFIGURAÇÕES DE SEGURANÇA"

# Firewall
log "Verificando status do firewall..."
if command -v ufw &> /dev/null; then
    echo "Status do UFW:" >> "$REPORT_FILE"
    ufw status verbose >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if ufw status | grep -q "Status: active"; then
        success "Firewall UFW: Ativo"
    else
        warning "Firewall UFW: Inativo"
    fi
else
    warning "UFW não está instalado"
fi

# Fail2Ban
log "Verificando Fail2Ban..."
if systemctl is-active --quiet fail2ban; then
    success "Fail2Ban: Ativo"
    echo "Status do Fail2Ban:" >> "$REPORT_FILE"
    fail2ban-client status >> "$REPORT_FILE" 2>/dev/null || echo "Erro ao obter status do Fail2Ban" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
else
    warning "Fail2Ban: Inativo"
fi

# SSH
log "Verificando configuração SSH..."
if [ -f "/etc/ssh/sshd_config" ]; then
    echo "Configurações críticas do SSH:" >> "$REPORT_FILE"
    grep -E "(PermitRootLogin|PasswordAuthentication|Port|Protocol)" /etc/ssh/sshd_config | grep -v "^#" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
        warning "SSH: Login root habilitado"
    else
        success "SSH: Login root desabilitado"
    fi
    
    if grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
        warning "SSH: Autenticação por senha habilitada"
    else
        success "SSH: Autenticação por senha desabilitada"
    fi
fi

# 6. VERIFICAÇÕES DE ARQUIVOS
header "📁 6. INTEGRIDADE DE ARQUIVOS"
log "Verificando arquivos com SUID/SGID..."
echo "Arquivos com bit SUID:" >> "$REPORT_FILE"
find / -type f -perm -4000 2>/dev/null | head -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Arquivos com bit SGID:" >> "$REPORT_FILE"
find / -type f -perm -2000 2>/dev/null | head -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

log "Verificando arquivos world-writable..."
echo "Arquivos world-writable:" >> "$REPORT_FILE"
find / -type f -perm -002 2>/dev/null | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 7. VERIFICAÇÕES DE LOGS
header "📋 7. ANÁLISE DE LOGS"
log "Verificando logs críticos..."

echo "Últimas entradas do syslog:" >> "$REPORT_FILE"
tail -10 /var/log/syslog >> "$REPORT_FILE" 2>/dev/null || echo "Syslog não acessível" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Últimas entradas de autenticação:" >> "$REPORT_FILE"
tail -10 /var/log/auth.log >> "$REPORT_FILE" 2>/dev/null || echo "Auth.log não acessível" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 8. VERIFICAÇÕES DE MALWARE
header "🦠 8. VERIFICAÇÃO DE MALWARE"
log "Executando verificações básicas de malware..."

# Verificar rootkits com rkhunter (se instalado)
if command -v rkhunter &> /dev/null; then
    log "Executando rkhunter..."
    rkhunter --check --sk --nocolors > "$TEMP_DIR/rkhunter.log" 2>&1 || true
    echo "Resultado do rkhunter:" >> "$REPORT_FILE"
    tail -20 "$TEMP_DIR/rkhunter.log" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
else
    warning "rkhunter não está instalado"
fi

# Verificar com chkrootkit (se instalado)
if command -v chkrootkit &> /dev/null; then
    log "Executando chkrootkit..."
    chkrootkit > "$TEMP_DIR/chkrootkit.log" 2>&1 || true
    echo "Resultado do chkrootkit:" >> "$REPORT_FILE"
    grep -v "nothing found" "$TEMP_DIR/chkrootkit.log" | tail -10 >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
else
    warning "chkrootkit não está instalado"
fi

# 9. VERIFICAÇÕES DE CONFIGURAÇÃO DO SECURITYFORGE
header "🛡️ 9. CONFIGURAÇÕES DO SECURITYFORGE"
log "Verificando instalação do SecurityForge..."

if [ -d "/opt/securityforge" ]; then
    success "SecurityForge: Instalado"
    info "Versão: 3.1.0"
    info "Ferramentas: $(find /opt/securityforge/tools -type d -maxdepth 1 | wc -l) categorias"
    info "Wordlists: $(find /opt/securityforge/wordlists -type f | wc -l) arquivos"
    info "Scripts: $(find /opt/securityforge/scripts -name "*.sh" | wc -l) scripts"
else
    warning "SecurityForge: Não encontrado"
fi

# 10. RECOMENDAÇÕES DE SEGURANÇA
header "💡 10. RECOMENDAÇÕES DE SEGURANÇA"

RECOMMENDATIONS=()

# Verificar se existem atualizações pendentes
if [ $(apt list --upgradable 2>/dev/null | wc -l) -gt 1 ]; then
    RECOMMENDATIONS+=("Atualizar pacotes do sistema (apt update && apt upgrade)")
fi

# Verificar se o firewall está ativo
if ! ufw status | grep -q "Status: active"; then
    RECOMMENDATIONS+=("Ativar e configurar firewall UFW")
fi

# Verificar se fail2ban está ativo
if ! systemctl is-active --quiet fail2ban; then
    RECOMMENDATIONS+=("Instalar e configurar Fail2Ban")
fi

# Verificar configuração SSH
if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    RECOMMENDATIONS+=("Desabilitar login SSH como root")
fi

# Verificar se existe backup recente
if [ ! -d "/var/backups" ] || [ $(find /var/backups -type f -mtime -7 | wc -l) -eq 0 ]; then
    RECOMMENDATIONS+=("Configurar sistema de backup automático")
fi

# Mostrar recomendações
if [ ${#RECOMMENDATIONS[@]} -gt 0 ]; then
    echo "Recomendações de segurança:" >> "$REPORT_FILE"
    for i in "${!RECOMMENDATIONS[@]}"; do
        echo "$((i+1)). ${RECOMMENDATIONS[i]}" >> "$REPORT_FILE"
    done
else
    echo "✅ Nenhuma recomendação crítica de segurança encontrada" >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"

# FINALIZAÇÃO
header "📊 RESUMO DA AUDITORIA"
success "Auditoria de segurança concluída"
info "Relatório salvo em: $REPORT_FILE"
info "Tamanho do relatório: $(du -h "$REPORT_FILE" | cut -f1)"
info "Total de recomendações: ${#RECOMMENDATIONS[@]}"

echo ""
header "🎯 PRÓXIMOS PASSOS"
echo "1. Revisar o relatório completo: cat $REPORT_FILE"
echo "2. Implementar as recomendações de segurança"
echo "3. Agendar auditorias regulares"
echo "4. Monitorar logs continuamente"

# Limpar arquivos temporários
rm -rf "$TEMP_DIR"

header "============================================"
info "Auditoria concluída em: $(date)"
