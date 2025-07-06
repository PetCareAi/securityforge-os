#!/bin/bash
# SecurityForge Linux - Configuração Ultra-Avançada de Firewall

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
header() { echo -e "${PURPLE}$1${NC}"; }

header "═══════════════════════════════════════════════════════════════════════════════"
header "               🛡️  SECURITYFORGE FIREWALL ULTRA-CONFIGURATION                "
header "═══════════════════════════════════════════════════════════════════════════════"

log "Iniciando configuração ultra-avançada de firewall..."

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Backup de configurações existentes
BACKUP_DIR="/var/backups/firewall-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -f /etc/ufw/ufw.conf ]; then
    cp -r /etc/ufw/ "$BACKUP_DIR/"
    log "Backup criado em: $BACKUP_DIR"
fi

# Reset completo do firewall
log "Resetando configurações do firewall..."
ufw --force reset > /dev/null 2>&1

# Configurar logging detalhado
log "Configurando logging avançado..."
ufw logging full

# Políticas padrão ultra-restritivas
log "Aplicando políticas ultra-restritivas..."
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward
ufw default deny routed

# Permitir loopback (essencial para funcionamento básico)
log "Configurando interface loopback..."
ufw allow in on lo
ufw allow out on lo

# Bloquear acesso de fora para loopback
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

# SSH personalizado e seguro
SSH_PORT=${SSH_PORT:-2222}
log "Configurando SSH seguro na porta $SSH_PORT..."
ufw allow "$SSH_PORT"/tcp comment 'SSH Custom Port - Secure'
ufw limit "$SSH_PORT"/tcp

# Saídas essenciais controladas
log "Configurando saídas essenciais..."
# DNS (necessário para resolução de nomes)
ufw allow out 53 comment 'DNS queries'
ufw allow out 853/tcp comment 'DNS over TLS'

# HTTP/HTTPS (para downloads e atualizações)
ufw allow out 80/tcp comment 'HTTP outbound'
ufw allow out 443/tcp comment 'HTTPS outbound'

# NTP (sincronização de tempo)
ufw allow out 123/udp comment 'NTP time sync'

# DHCP client (se necessário)
ufw allow out 67/udp comment 'DHCP client'
ufw allow out 68/udp comment 'DHCP client'

# Ferramentas de pentesting controladas
log "Configurando portas para ferramentas de segurança..."
# Burp Suite / OWASP ZAP
ufw allow in 8080/tcp comment 'Burp Suite / ZAP proxy'
ufw allow in 8443/tcp comment 'HTTPS proxy testing'

# Metasploit Framework
ufw allow in 4444/tcp comment 'Metasploit default listener'
ufw allow in 4445/tcp comment 'Metasploit SSL listener'
ufw allow in 4446/tcp comment 'Metasploit additional'

# Web application testing
ufw allow in 3000/tcp comment 'Development server'
ufw allow in 8000/tcp comment 'Alternative web server'
ufw allow in 8888/tcp comment 'Jupyter/Alternative proxy'

# Database testing (local only)
ufw allow in on lo to any port 3306 comment 'MySQL local'
ufw allow in on lo to any port 5432 comment 'PostgreSQL local'
ufw allow in on lo to any port 27017 comment 'MongoDB local'

# Redis/Memcached (local only)
ufw allow in on lo to any port 6379 comment 'Redis local'
ufw allow in on lo to any port 11211 comment 'Memcached local'

# ICMP controlado (ping)
log "Configurando ICMP..."
ufw allow out on any to any proto icmp comment 'ICMP outbound'
ufw allow in proto icmp from any to any icmp-type echo-request comment 'ICMP ping inbound'

# IPv6 ICMP
ufw allow out on any to any proto ipv6-icmp comment 'ICMPv6 outbound'

# Rate limiting avançado
log "Aplicando rate limiting avançado..."
# SSH com rate limiting agressivo
ufw limit 22/tcp comment 'SSH default rate limit'
ufw limit "$SSH_PORT"/tcp comment 'SSH custom rate limit'

# HTTP services
ufw limit 80/tcp comment 'HTTP rate limit'
ufw limit 443/tcp comment 'HTTPS rate limit'

# Configurações iptables avançadas para DDoS protection
log "Configurando proteção anti-DDoS..."

# Proteção SYN flood
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Proteção contra port scanning
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Proteção contra ataques de força bruta
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh_attack
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --rcheck --seconds 60 --hitcount 3 --name ssh_attack -j DROP
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -m recent --set --name ssh_attack
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -m recent --rcheck --seconds 60 --hitcount 3 --name ssh_attack -j DROP

# Limitar conexões simultâneas
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 50 -j REJECT
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 50 -j REJECT

# Bloquear ranges problemáticos conhecidos
log "Configurando bloqueios geográficos e ranges problemáticos..."
# Bloquear ranges privados de fora (spoof protection)
ufw deny in from 10.0.0.0/8 to any comment 'Block private range 10.x from outside'
ufw deny in from 172.16.0.0/12 to any comment 'Block private range 172.16.x from outside'
ufw deny in from 192.168.0.0/16 to any comment 'Block private range 192.168.x from outside'

# Bloquear multicast/broadcast
ufw deny in from 224.0.0.0/4 comment 'Block multicast'
ufw deny in from 240.0.0.0/5 comment 'Block reserved addresses'

# Logging personalizado para análise
log "Configurando logging personalizado..."
# Log de tentativas de conexão SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j LOG --log-prefix "[UFW SSH-22] " --log-level 4
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -j LOG --log-prefix "[UFW SSH-$SSH_PORT] " --log-level 4

# Log de tentativas em portas web
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j LOG --log-prefix "[UFW HTTP] " --log-level 4
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j LOG --log-prefix "[UFW HTTPS] " --log-level 4

# Log de pacotes descartados
iptables -A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "[UFW BLOCK] " --log-level 4

# Configurações específicas para laboratório de penetration testing
log "Configurando regras específicas para laboratório..."
# Permitir comunicação com VMs locais (ajustar conforme necessário)
# ufw allow in from 192.168.122.0/24 comment 'KVM/libvirt VMs'
# ufw allow in from 172.17.0.0/16 comment 'Docker containers'

# Ativar IP forwarding para laboratórios (se necessário)
# echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Configuração do fail2ban
log "Instalando e configurando Fail2Ban..."
if ! command -v fail2ban-server &> /dev/null; then
    apt-get update
    apt-get install -y fail2ban
fi

systemctl enable fail2ban
systemctl start fail2ban

# Ativar firewall
log "Ativando firewall..."
ufw --force enable

# Verificar status detalhado
log "Verificando configuração final..."
echo ""
header "═══════════════════════════════════════════════════════════════════════════════"
header "                           FIREWALL STATUS REPORT                             "
header "═══════════════════════════════════════════════════════════════════════════════"
ufw status verbose
echo ""

# Criar script de monitoramento
cat > /opt/securityforge/scripts/firewall-monitor.sh << 'MONITOR_EOF'
#!/bin/bash
# SecurityForge Firewall Monitor

echo "🔥 SecurityForge Firewall Monitor"
echo "=================================="
echo "Data: $(date)"
echo ""

echo "📊 Status UFW:"
ufw status numbered
echo ""

echo "📈 Top 10 IPs bloqueados:"
grep "UFW BLOCK" /var/log/ufw.log | awk '{print $14}' | cut -d= -f2 | sort | uniq -c | sort -nr | head -10
echo ""

echo "🚨 Tentativas SSH recentes:"
grep "UFW SSH" /var/log/ufw.log | tail -5
echo ""

echo "🌐 Conexões ativas:"
ss -tulnp | grep LISTEN
MONITOR_EOF

chmod +x /opt/securityforge/scripts/firewall-monitor.sh

success "Firewall ultra-avançado configurado com sucesso!"
echo ""
echo -e "${CYAN}🔒 CONFIGURAÇÕES APLICADAS:${NC}"
echo "   • Políticas ultra-restritivas por padrão"
echo "   • SSH seguro na porta $SSH_PORT com rate limiting"
echo "   • Proteção anti-DDoS e anti-scanning"
echo "   • Logging detalhado para análise forense"
echo "   • Fail2Ban ativo para proteção automática"
echo "   • Regras específicas para ferramentas de pentest"
echo "   • Bloqueio de ranges problemáticos"
echo "   • Monitor de firewall disponível"
echo ""
warning "IMPORTANTE: SSH agora está na porta $SSH_PORT!"
warning "Para monitorar: /opt/securityforge/scripts/firewall-monitor.sh"
echo ""
header "═══════════════════════════════════════════════════════════════════════════════"
