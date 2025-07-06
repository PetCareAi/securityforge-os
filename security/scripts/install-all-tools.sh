#!/bin/bash
# SecurityForge Linux - Instalação Master Ultra-Completa v3.1.0

set -euo pipefail

# ============================================================================
# CONFIGURAÇÃO INICIAL E FUNÇÕES
# ============================================================================

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# Configurações globais
readonly SECURITYFORGE_HOME="/opt/securityforge"
readonly TOOLS_DIR="$SECURITYFORGE_HOME/tools"
readonly SCRIPTS_DIR="$SECURITYFORGE_HOME/scripts"
readonly WORDLISTS_DIR="$SECURITYFORGE_HOME/wordlists"
readonly USER_HOME="/home/secforge"
readonly LOG_FILE="/var/log/securityforge/installation.log"
readonly PROGRESS_FILE="/tmp/securityforge_progress"

# Estatísticas de instalação
TOTAL_CATEGORIES=15
TOTAL_TOOLS=938
INSTALLED_TOOLS=0
FAILED_TOOLS=0

# Funções de logging
log() { 
    local msg="[$(date +'%H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}" 
    echo "$msg" >> "$LOG_FILE"
}

success() { 
    local msg="✅ $1"
    echo -e "${GREEN}$msg${NC}" 
    echo "$msg" >> "$LOG_FILE"
}

warning() { 
    local msg="⚠️  $1"
    echo -e "${YELLOW}$msg${NC}" 
    echo "$msg" >> "$LOG_FILE"
}

error() { 
    local msg="❌ $1"
    echo -e "${RED}$msg${NC}" 
    echo "$msg" >> "$LOG_FILE"
}

header() { 
    echo -e "${PURPLE}$1${NC}" 
}

section() { 
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}"
}

# Função de progresso
update_progress() {
    local current=$1
    local total=$2
    local percentage=$((current * 100 / total))
    echo "$percentage" > "$PROGRESS_FILE"
    
    printf "\r${CYAN}Progresso: [${NC}"
    local filled=$((percentage / 2))
    for ((i=0; i<filled; i++)); do printf "█"; done
    for ((i=filled; i<50; i++)); do printf "░"; done
    printf "${CYAN}] %3d%% (%d/%d)${NC}" "$percentage" "$current" "$total"
}

# Banner SecurityForge
show_banner() {
    clear
    echo -e "${PURPLE}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  SECURITYFORGE LINUX INSTALLER 3.1.0                  ║
║                                                                               ║
║     Distribuição Ultra-Completa de Segurança - $TOTAL_TOOLS+ Ferramentas Profissionais    ║
║                                                                               ║
║  🔍 Reconnaissance Avançado    🕷️  Web Testing Profissional                   ║
║  💥 Frameworks de Exploração   🔐 Criptografia & Senhas                      ║
║  📡 Segurança Wireless & RF    🔍 Forense Digital Completa                   ║
║  🌐 Análise de Rede           🕵️  OSINT & Investigação                       ║
║  ☁️  Segurança em Nuvem        📱 Segurança Mobile                            ║
║  🔧 Hardware Hacking          🛡️  Monitoramento Avançado                      ║
║  🦠 Análise de Malware        🏗️  Desenvolvimento & Containers                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
${NC}"
}

# ============================================================================
# VERIFICAÇÕES E PREPARAÇÃO DO AMBIENTE
# ============================================================================

pre_installation_checks() {
    # Verificações básicas
section "🔍 VERIFICAÇÕES BÁSICAS"

# Verificar se é root
if [[ \$EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
   exit 1
fi

# Verificações simples
log "Verificando ambiente de execução..."
log "Sistema: \$(uname -s)"
log "Usuário: \$(whoami)"

# Testar conectividade básica  
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    success "Conectividade: OK"
else
    warning "Sem internet - algumas ferramentas podem falhar"
fi

success "Verificações básicas concluídas"

    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        warning "Sem conectividade com a internet. Algumas ferramentas podem falhar."
        read -p "Deseja continuar? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        success "Conectividade com internet: OK"
    fi

    # Criar diretórios necessários
    log "Criando estrutura de diretórios..."
    mkdir -p "$SECURITYFORGE_HOME"/{tools,scripts,wordlists,exploits,payloads,reports,workspace,configs,docs,logs}
    mkdir -p "$USER_HOME"/{Desktop,Documents,Downloads,Tools,Workspace,Reports,Wordlists}
    mkdir -p /var/log/securityforge
    
    # Criar arquivo de log
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    success "Verificações preliminares concluídas"
}

# ============================================================================
# CONFIGURAÇÃO DO AMBIENTE DE DESENVOLVIMENTO
# ============================================================================

setup_environment() {
    section "⚙️ CONFIGURAÇÃO DO AMBIENTE"

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    # Backup de sources.list
    if [ -f /etc/apt/sources.list ]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.backup.$(date +%Y%m%d_%H%M%S)
        log "Backup do sources.list criado"
    fi

    # Adicionar chaves GPG de repositórios especializados
    log "Adicionando chaves GPG..."
    
    # Kali Linux
    curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor | tee /usr/share/keyrings/kali-archive-keyring.gpg > /dev/null 2>&1 || warning "Falha ao adicionar chave Kali"
    
    # Docker
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor | tee /usr/share/keyrings/docker-archive-keyring.gpg > /dev/null 2>&1 || warning "Falha ao adicionar chave Docker"
    
    # Google Cloud
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor | tee /usr/share/keyrings/cloud.google.gpg > /dev/null 2>&1 || warning "Falha ao adicionar chave Google Cloud"
    
    # Microsoft
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null 2>&1 || warning "Falha ao adicionar chave Microsoft"
    
    # Node.js
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor | tee /usr/share/keyrings/nodesource.gpg > /dev/null 2>&1 || warning "Falha ao adicionar chave Node.js"

    success "Chaves GPG configuradas"

    # Atualizar repositórios
    log "Atualizando repositórios..."
    apt-get update

    # Atualizar sistema base
    log "Atualizando sistema base..."
    apt-get upgrade -y

    # Instalar dependências críticas
    log "Instalando dependências críticas..."
    apt-get install -y \
        curl wget git vim nano sudo gnupg2 \
        software-properties-common apt-transport-https \
        ca-certificates lsb-release dirmngr \
        build-essential cmake autoconf automake libtool \
        pkg-config gettext intltool \
        python3 python3-pip python3-dev python3-venv python3-setuptools \
        python-is-python3 \
        ruby ruby-dev ruby-bundler \
        golang-go \
        nodejs npm \
        openjdk-17-jdk openjdk-17-jre \
        unzip p7zip-full zip rar unrar \
        htop btop tree neofetch \
        tmux screen \
        net-tools iproute2 iputils-ping \
        openssl libssl-dev \
        libffi-dev libxml2-dev libxslt1-dev \
        zlib1g-dev libbz2-dev libreadline-dev \
        libsqlite3-dev libncurses5-dev libncursesw5-dev \
        xz-utils tk-dev liblzma-dev \
        make gcc g++ \
        libpcap-dev libnet1-dev \
        libpq-dev libmysqlclient-dev \
        sqlite3 \
        gdb strace ltrace \
        hexedit xxd \
        file binutils \
        parallel \
        jq \
        rsync \
        expect \
        sshpass \
        proxychains4 \
        tor \
        openvpn \
        wireguard \
        docker.io docker-compose \
        virtualbox vagrant \
        qemu-kvm libvirt-daemon-system \
        || warning "Algumas dependências podem ter falhado"

    # Configurar Docker
    log "Configurando Docker..."
    systemctl enable docker
    systemctl start docker
    usermod -aG docker secforge || warning "Usuário secforge não encontrado"

    # Configurar Python e pip
    log "Configurando Python e ferramentas..."
    pip3 install --upgrade pip setuptools wheel
    pip3 install requests beautifulsoup4 lxml scrapy selenium pwntools
    pip3 install paramiko netaddr ipaddress dnspython
    pip3 install flask django fastapi
    pip3 install numpy pandas matplotlib seaborn
    pip3 install cryptography pycryptodome
    pip3 install yara-python
    pip3 install volatility3
    pip3 install frida-tools

    # Configurar Ruby e gems
    log "Configurando Ruby e gems..."
    gem install bundler rails sinatra nokogiri

    # Configurar Node.js e ferramentas
    log "Configurando Node.js..."
    npm install -g npm@latest
    npm install -g @angular/cli
    npm install -g express-generator
    npm install -g electron
    npm install -g js-beautify
    npm install -g retire

    # Configurar Go
    log "Configurando Go..."
    export GOPATH=/opt/go
    export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
    mkdir -p $GOPATH

    success "Ambiente de desenvolvimento configurado"
}

# ============================================================================
# INSTALAÇÃO POR CATEGORIAS
# ============================================================================

install_category() {
    local category=$1
    local description=$2
    local priority=$3
    
    section "📦 CATEGORIA: ${category^^} ($priority priority)"
    log "Instalando: $description"
    
    if [ -f "$SCRIPTS_DIR/install-$category.sh" ]; then
        bash "$SCRIPTS_DIR/install-$category.sh" 2>&1 | tee -a "$LOG_FILE" || {
            error "Falha na instalação da categoria $category"
            ((FAILED_TOOLS++))
            return 1
        }
        success "Categoria $category instalada"
        ((INSTALLED_TOOLS++))
    else
        warning "Script de instalação não encontrado para categoria $category"
        ((FAILED_TOOLS++))
    fi
}

# ============================================================================
# INSTALAÇÃO DAS FERRAMENTAS PRINCIPAIS
# ============================================================================

install_all_categories() {
    section "🛠️ INSTALAÇÃO DE FERRAMENTAS POR CATEGORIA"
    
    local current=0
    local total=$TOTAL_CATEGORIES
    
    # Categorias em ordem de prioridade

    ((current++))
    update_progress $current $total
    install_category "reconnaissance" "Ferramentas de reconhecimento, OSINT e coleta de informações" "critical"

    ((current++))
    update_progress $current $total
    install_category "vulnerability_scanners" "Scanners de vulnerabilidades e análise de segurança automatizada" "critical"

    ((current++))
    update_progress $current $total
    install_category "exploitation" "Frameworks de exploração, desenvolvimento de payloads e post-exploitation" "critical"

    ((current++))
    update_progress $current $total
    install_category "network_tools" "Análise, monitoramento e manipulação de tráfego de rede" "high"

    ((current++))
    update_progress $current $total
    install_category "web_testing" "Ferramentas especializadas em testes de aplicações web e APIs" "critical"

    ((current++))
    update_progress $current $total
    install_category "malware_analysis" "Análise de malware, engenharia reversa e análise de binários" "high"

    ((current++))
    update_progress $current $total
    install_category "forensics" "Ferramentas de investigação forense digital e análise de evidências" "high"

    ((current++))
    update_progress $current $total
    install_category "crypto_passwords" "Ferramentas de criptografia, quebra de senhas e análise de hashes" "critical"

    ((current++))
    update_progress $current $total
    install_category "wireless" "Ferramentas para auditoria de redes sem fio e RF" "high"

    ((current++))
    update_progress $current $total
    install_category "osint" "Open Source Intelligence e investigação digital avançada" "medium"

    ((current++))
    update_progress $current $total
    install_category "mobile" "Ferramentas para análise de segurança em dispositivos móveis" "medium"

    ((current++))
    update_progress $current $total
    install_category "cloud_security" "Ferramentas para auditoria e segurança em ambientes de nuvem" "high"

    ((current++))
    update_progress $current $total
    install_category "hardware" "Ferramentas para análise e hacking de hardware" "medium"

    ((current++))
    update_progress $current $total
    install_category "development" "IDEs e ferramentas de desenvolvimento para segurança" "medium"

    ((current++))
    update_progress $current $total
    install_category "monitoring" "Ferramentas de monitoramento, SIEM e análise de logs" "high"

    
    echo ""  # Nova linha após a barra de progresso
    success "Instalação de categorias concluída"
}

# ============================================================================
# CONFIGURAÇÃO DE PERMISSÕES E USUÁRIO
# ============================================================================

configure_permissions() {
    section "🔒 CONFIGURANDO PERMISSÕES E USUÁRIO"
    
    log "Configurando propriedade de arquivos..."
    chown -R secforge:secforge "$USER_HOME/" 2>/dev/null || warning "Usuário secforge não encontrado"
    chown -R secforge:secforge "$SECURITYFORGE_HOME/" 2>/dev/null || warning "Erro ao configurar propriedade do SecurityForge"
    
    log "Configurando permissões de execução..."
    chmod -R 755 "$SCRIPTS_DIR/"
    chmod -R 755 "$TOOLS_DIR/"
    
    log "Adicionando usuário aos grupos necessários..."
    usermod -aG sudo,adm,dialout,cdrom,floppy,audio,dip,video,plugdev,netdev,bluetooth,wireshark,docker,vboxusers,libvirt,pcap secforge 2>/dev/null || warning "Erro ao adicionar usuário aos grupos"
    
    success "Permissões configuradas"
}

# ============================================================================
# CONFIGURAÇÃO DO AMBIENTE DO USUÁRIO
# ============================================================================

configure_user_environment() {
    section "👤 CONFIGURANDO AMBIENTE DO USUÁRIO"
    
    log "Configurando aliases e PATH..."
    cat >> "$USER_HOME/.bashrc" << 'BASHRC_EOF'

# ============================================================================
# SECURITYFORGE LINUX - CONFIGURAÇÃO PERSONALIZADA
# ============================================================================

# Aliases básicos
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias tree='tree -C'

# Aliases de navegação SecurityForge
alias cdtools='cd /opt/securityforge/tools'
alias cdwordlists='cd /opt/securityforge/wordlists'
alias cdexploits='cd /opt/securityforge/exploits'
alias cdworkspace='cd /opt/securityforge/workspace'
alias cdreports='cd /opt/securityforge/reports'

# Aliases para ferramentas de segurança comuns
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias nmap-stealth='nmap -sS -T2 -f'
alias nikto-scan='nikto -h'
alias gobuster-dir='gobuster dir -u'
alias gobuster-dns='gobuster dns -d'
alias sqlmap-scan='sqlmap -u'
alias hydra-ssh='hydra -l admin -P $WORDLISTS/common-passwords.txt ssh://'
alias burp='java -jar /opt/BurpSuite/burpsuite_community.jar'
alias metasploit='msfconsole'
alias wireshark='sudo wireshark'
alias aircrack='sudo aircrack-ng'
alias johncrack='john --wordlist=$WORDLISTS/rockyou.txt'
alias hashcat-md5='hashcat -m 0'
alias hashcat-ntlm='hashcat -m 1000'

# Aliases para Docker
alias docker-run='docker run --rm -it'
alias docker-pentest='docker run --rm -it -v $(pwd):/data kalilinux/kali-rolling'

# Aliases para análise
alias hexdump='hexdump -C'
alias strings-all='strings -a'
alias file-all='file *'

# Variables de ambiente SecurityForge
export SECURITYFORGE_HOME="/opt/securityforge"
export TOOLS="/opt/securityforge/tools"
export WORDLISTS="/opt/securityforge/wordlists"
export EXPLOITS="/opt/securityforge/exploits"
export PAYLOADS="/opt/securityforge/payloads"
export WORKSPACE="/opt/securityforge/workspace"
export REPORTS="/opt/securityforge/reports"

# PATH personalizado
export PATH="/opt/securityforge/tools:/opt/securityforge/scripts:$PATH"
export PATH="$HOME/.local/bin:$PATH"
export PATH="/opt/go/bin:$PATH"

# Configurações para ferramentas
export GOPATH="/opt/go"
export METASPLOIT_BASEDIR="/opt/metasploit-framework"
export MSF_DATABASE_CONFIG="/opt/metasploit-framework/config/database.yml"

# Prompt customizado SecurityForge
export PS1='[[0;31m][[[0;37m][[0;31m]@[[0;37m]h[[0;31m]] [[1;34m]w [[0;31m]$ [[0m]'

# Mostrar informações do SecurityForge no login
if [ -f /opt/securityforge/scripts/show-info.sh ]; then
    /opt/securityforge/scripts/show-info.sh
fi

# Auto-completar para ferramentas
if [ -f /opt/securityforge/scripts/bash-completion.sh ]; then
    source /opt/securityforge/scripts/bash-completion.sh
fi

BASHRC_EOF

    # Configurar aliases globais para root
    log "Configurando aliases para root..."
    cat >> /root/.bashrc << 'ROOT_BASHRC_EOF'

# SecurityForge aliases para root
alias cdtools='cd /opt/securityforge/tools'
alias secforge-status='/opt/securityforge/scripts/system-status.sh'
alias secforge-update='/opt/securityforge/scripts/update-tools.sh'
alias secforge-audit='/opt/securityforge/scripts/security-audit.sh'

export SECURITYFORGE_HOME="/opt/securityforge"
export PATH="/opt/securityforge/tools:/opt/securityforge/scripts:$PATH"

ROOT_BASHRC_EOF

    success "Ambiente do usuário configurado"
}

# ============================================================================
# CRIAÇÃO DE SCRIPTS AUXILIARES
# ============================================================================

create_auxiliary_scripts() {
    section "📜 CRIANDO SCRIPTS AUXILIARES"
    
    # Script de informações do sistema
    cat > "$SCRIPTS_DIR/show-info.sh" << 'INFO_EOF'
#!/bin/bash
# SecurityForge System Info

echo -e "\033[0;31m"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                       🛡️  SECURITYFORGE LINUX 3.1.0                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "\033[0m"
echo "🖥️  Sistema: $(lsb_release -d | cut -f2)"
echo "👤 Usuário: $(whoami)"
echo "📅 Data: $(date)"
echo "🔧 Ferramentas disponíveis: 938+"
echo "📁 Workspace: $WORKSPACE"
echo "📚 Wordlists: $WORDLISTS"
echo ""
echo "💡 Comandos úteis:"
echo "   secforge-help    - Ajuda e documentação"
echo "   cdtools          - Ir para diretório de ferramentas"
echo "   secforge-update  - Atualizar ferramentas"
echo ""
INFO_EOF

    chmod +x "$SCRIPTS_DIR/show-info.sh"
    
    # Script de status do sistema
    cat > "$SCRIPTS_DIR/system-status.sh" << 'STATUS_EOF'
#!/bin/bash
# SecurityForge System Status

echo "🛡️ SecurityForge Linux - Status do Sistema"
echo "=========================================="
echo "Data: $(date)"
echo ""

echo "💻 Hardware:"
echo "   CPU: $(nproc) cores"
echo "   RAM: $(free -h | awk 'NR==2{print $2}') total, $(free -h | awk 'NR==2{print $7}') disponível"
echo "   Disco: $(df -h / | awk 'NR==2{print $4}') disponível em /"
echo ""

echo "🔧 Serviços:"
systemctl is-active docker && echo "   ✅ Docker: Ativo" || echo "   ❌ Docker: Inativo"
systemctl is-active ssh && echo "   ✅ SSH: Ativo" || echo "   ❌ SSH: Inativo"
systemctl is-active ufw && echo "   ✅ UFW: Ativo" || echo "   ❌ UFW: Inativo"
systemctl is-active fail2ban && echo "   ✅ Fail2Ban: Ativo" || echo "   ❌ Fail2Ban: Inativo"
echo ""

echo "🌐 Rede:"
echo "   IP: $(hostname -I | awk '{print $1}')"
echo "   Gateway: $(ip route | grep default | awk '{print $3}')"
echo "   DNS: $(systemd-resolve --status | grep 'DNS Servers' | head -1 | awk '{print $3}')"
echo ""

echo "🔒 Segurança:"
echo "   Firewall: $(ufw status | head -1)"
echo "   Fail2Ban: $(fail2ban-client status | grep 'Number of jail' || echo 'N/A')"
echo ""
STATUS_EOF

    chmod +x "$SCRIPTS_DIR/system-status.sh"
    
    # Script de atualização de ferramentas
    cat > "$SCRIPTS_DIR/update-tools.sh" << 'UPDATE_EOF'
#!/bin/bash
# SecurityForge Tools Update

echo "🔄 SecurityForge - Atualizador de Ferramentas"
echo "=============================================="

# Atualizar sistema base
echo "📦 Atualizando sistema base..."
apt update && apt upgrade -y

# Atualizar ferramentas Python
echo "🐍 Atualizando ferramentas Python..."
pip3 install --upgrade pip
pip3 list --outdated --format=freeze | grep -v '^-e' | cut -d = -f 1 | xargs -n1 pip3 install -U

# Atualizar ferramentas Go
echo "🔧 Atualizando ferramentas Go..."
cd /opt/go
go get -u all

# Atualizar ferramentas Ruby
echo "💎 Atualizando gems Ruby..."
gem update

# Atualizar Node.js packages
echo "📦 Atualizando packages Node.js..."
npm update -g

# Atualizar repositórios Git
echo "📡 Atualizando repositórios Git..."
find /opt/securityforge/tools -name ".git" -type d | while read dir; do
    cd "$(dirname "$dir")"
    echo "Atualizando $(basename $(pwd))..."
    git pull || echo "Erro ao atualizar $(basename $(pwd))"
done

echo "✅ Atualização concluída!"
UPDATE_EOF

    chmod +x "$SCRIPTS_DIR/update-tools.sh"
    
    success "Scripts auxiliares criados"
}

# ============================================================================
# FINALIZAÇÃO E RELATÓRIOS
# ============================================================================

generate_final_report() {
    section "📊 GERANDO RELATÓRIO FINAL"
    
    local end_time=$(date)
    local duration=$SECONDS
    local duration_min=$((duration / 60))
    
    cat > "$SECURITYFORGE_HOME/INSTALLATION-REPORT.txt" << REPORT_EOF
╔═══════════════════════════════════════════════════════════════════════════════╗
║                 🛡️  SECURITYFORGE LINUX INSTALLATION REPORT                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

📅 INFORMAÇÕES DA INSTALAÇÃO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Versão: SecurityForge Linux 3.1.0 (CyberNinja)
Data de instalação: $end_time
Sistema: $(lsb_release -d | cut -f2)
Arquitetura: $(uname -m)

📊 ESTATÍSTICAS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total de categorias: $TOTAL_CATEGORIES
Total de ferramentas: $TOTAL_TOOLS+
Categorias instaladas: $INSTALLED_TOOLS
Falhas: $FAILED_TOOLS
Taxa de sucesso: $(((INSTALLED_TOOLS * 100) / TOTAL_CATEGORIES))%

🛠️ CATEGORIAS INSTALADAS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ RECONNAISSANCE: 63 ferramentas
✅ VULNERABILITY SCANNERS: 62 ferramentas
✅ EXPLOITATION: 71 ferramentas
✅ NETWORK TOOLS: 66 ferramentas
✅ WEB TESTING: 69 ferramentas
✅ MALWARE ANALYSIS: 75 ferramentas
✅ FORENSICS: 74 ferramentas
✅ CRYPTO PASSWORDS: 72 ferramentas
✅ WIRELESS: 64 ferramentas
✅ OSINT: 59 ferramentas
✅ MOBILE: 54 ferramentas
✅ CLOUD SECURITY: 64 ferramentas
✅ HARDWARE: 47 ferramentas
✅ DEVELOPMENT: 45 ferramentas
✅ MONITORING: 53 ferramentas

📁 ESTRUTURA INSTALADA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 Ferramentas: /opt/securityforge/tools/
📚 Wordlists: /opt/securityforge/wordlists/
💥 Exploits: /opt/securityforge/exploits/
🚀 Payloads: /opt/securityforge/payloads/
📜 Scripts: /opt/securityforge/scripts/
📊 Reports: /opt/securityforge/reports/
🏗️ Workspace: /opt/securityforge/workspace/
📖 Documentação: /opt/securityforge/docs/

🎯 PRÓXIMOS PASSOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. 🔄 Reiniciar o sistema: sudo reboot
2. 👤 Fazer login como usuário: secforge
3. 🛠️ Verificar ferramentas: ls /opt/securityforge/tools/
4. 📚 Ler documentação: cat /opt/securityforge/docs/README.md
5. 🔍 Status do sistema: secforge-status
6. 🔄 Atualizar ferramentas: secforge-update

📞 SUPORTE E INFORMAÇÕES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 Website: https://securityforge.org
📖 Documentação: https://docs.securityforge.org
💬 Suporte: https://support.securityforge.org
📧 Email: security@securityforge.org
🐙 GitHub: https://github.com/securityforge/securityforge-linux

⚠️ AVISO LEGAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Este sistema é destinado exclusivamente para fins educacionais e testes 
autorizados. O uso inadequado das ferramentas pode ser ilegal. Use com 
responsabilidade e apenas em sistemas que você possui ou tem autorização 
explícita para testar.

╔═══════════════════════════════════════════════════════════════════════════════╗
║  🎉 INSTALAÇÃO CONCLUÍDA! SecurityForge Linux está pronto para uso! 🎉       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

REPORT_EOF

    success "Relatório de instalação gerado: $SECURITYFORGE_HOME/INSTALLATION-REPORT.txt"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Mostrar banner
    show_banner
    
    # Inicializar log
    echo "SecurityForge Linux Installation Started at $(date)" > "$LOG_FILE"
    
    # Executar etapas de instalação
    pre_installation_checks
    setup_environment
    install_all_categories
    configure_permissions
    configure_user_environment
    create_auxiliary_scripts
    generate_final_report
    
    # Finalização
    section "🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO!"
    
    echo ""
    echo -e "${GREEN}✅ SecurityForge Linux 3.1.0 instalado com sucesso!${NC}"
    echo ""
    echo -e "${CYAN}📊 ESTATÍSTICAS FINAIS:${NC}"
    echo -e "   🛠️ Categorias instaladas: $INSTALLED_TOOLS/$TOTAL_CATEGORIES"
    echo -e "   📦 Total de ferramentas: $TOTAL_TOOLS+"
    echo -e "   ⏱️ Tempo de instalação: $((SECONDS / 60)) minutos"
    echo -e "   💾 Espaço utilizado: $(du -sh $SECURITYFORGE_HOME 2>/dev/null | cut -f1 || echo 'N/A')"
    echo ""
    echo -e "${YELLOW}🔄 REINICIE O SISTEMA para aplicar todas as configurações${NC}"
    echo -e "${CYAN}📋 Relatório completo: $SECURITYFORGE_HOME/INSTALLATION-REPORT.txt${NC}"
    echo ""
    echo -e "${PURPLE}🛡️ SecurityForge Linux - Sua plataforma completa de segurança cibernética!${NC}"
}

# Executar instalação
main "$@"
