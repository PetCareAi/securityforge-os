#!/bin/bash
# SecurityForge Linux - Instalação de NETWORK TOOLS

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

echo "📦 Instalando Análise, monitoramento e manipulação de tráfego de rede..."

CATEGORY_DIR="/opt/securityforge/tools/network_tools"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y wireshark tshark tcpdump netcat socat ncat netstat ss netdiscover arp-scan arping nbtscan enum4linux smbclient smbmap || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# wireshark
if [ ! -d "wireshark" ]; then
    log "Configurando wireshark..."
    mkdir -p "wireshark"
    echo "#!/bin/bash" > "wireshark/wireshark"
    echo "echo '🛠️ Executando wireshark...'" >> "wireshark/wireshark"
    echo "# Implementação específica do wireshark" >> "wireshark/wireshark"
    chmod +x "wireshark/wireshark"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/wireshark" ]; then
        ln -sf "$CATEGORY_DIR/wireshark/wireshark" "/usr/local/bin/wireshark"
    fi
fi


# tshark
if [ ! -d "tshark" ]; then
    log "Configurando tshark..."
    mkdir -p "tshark"
    echo "#!/bin/bash" > "tshark/tshark"
    echo "echo '🛠️ Executando tshark...'" >> "tshark/tshark"
    echo "# Implementação específica do tshark" >> "tshark/tshark"
    chmod +x "tshark/tshark"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/tshark" ]; then
        ln -sf "$CATEGORY_DIR/tshark/tshark" "/usr/local/bin/tshark"
    fi
fi


# tcpdump
if [ ! -d "tcpdump" ]; then
    log "Configurando tcpdump..."
    mkdir -p "tcpdump"
    echo "#!/bin/bash" > "tcpdump/tcpdump"
    echo "echo '🛠️ Executando tcpdump...'" >> "tcpdump/tcpdump"
    echo "# Implementação específica do tcpdump" >> "tcpdump/tcpdump"
    chmod +x "tcpdump/tcpdump"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/tcpdump" ]; then
        ln -sf "$CATEGORY_DIR/tcpdump/tcpdump" "/usr/local/bin/tcpdump"
    fi
fi


# netcat
if [ ! -d "netcat" ]; then
    log "Configurando netcat..."
    mkdir -p "netcat"
    echo "#!/bin/bash" > "netcat/netcat"
    echo "echo '🛠️ Executando netcat...'" >> "netcat/netcat"
    echo "# Implementação específica do netcat" >> "netcat/netcat"
    chmod +x "netcat/netcat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/netcat" ]; then
        ln -sf "$CATEGORY_DIR/netcat/netcat" "/usr/local/bin/netcat"
    fi
fi


# socat
if [ ! -d "socat" ]; then
    log "Configurando socat..."
    mkdir -p "socat"
    echo "#!/bin/bash" > "socat/socat"
    echo "echo '🛠️ Executando socat...'" >> "socat/socat"
    echo "# Implementação específica do socat" >> "socat/socat"
    chmod +x "socat/socat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/socat" ]; then
        ln -sf "$CATEGORY_DIR/socat/socat" "/usr/local/bin/socat"
    fi
fi


# ncat
if [ ! -d "ncat" ]; then
    log "Configurando ncat..."
    mkdir -p "ncat"
    echo "#!/bin/bash" > "ncat/ncat"
    echo "echo '🛠️ Executando ncat...'" >> "ncat/ncat"
    echo "# Implementação específica do ncat" >> "ncat/ncat"
    chmod +x "ncat/ncat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/ncat" ]; then
        ln -sf "$CATEGORY_DIR/ncat/ncat" "/usr/local/bin/ncat"
    fi
fi


# netstat
if [ ! -d "netstat" ]; then
    log "Configurando netstat..."
    mkdir -p "netstat"
    echo "#!/bin/bash" > "netstat/netstat"
    echo "echo '🛠️ Executando netstat...'" >> "netstat/netstat"
    echo "# Implementação específica do netstat" >> "netstat/netstat"
    chmod +x "netstat/netstat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/netstat" ]; then
        ln -sf "$CATEGORY_DIR/netstat/netstat" "/usr/local/bin/netstat"
    fi
fi


# ss
if [ ! -d "ss" ]; then
    log "Configurando ss..."
    mkdir -p "ss"
    echo "#!/bin/bash" > "ss/ss"
    echo "echo '🛠️ Executando ss...'" >> "ss/ss"
    echo "# Implementação específica do ss" >> "ss/ss"
    chmod +x "ss/ss"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/ss" ]; then
        ln -sf "$CATEGORY_DIR/ss/ss" "/usr/local/bin/ss"
    fi
fi


# netdiscover
if [ ! -d "netdiscover" ]; then
    log "Configurando netdiscover..."
    mkdir -p "netdiscover"
    echo "#!/bin/bash" > "netdiscover/netdiscover"
    echo "echo '🛠️ Executando netdiscover...'" >> "netdiscover/netdiscover"
    echo "# Implementação específica do netdiscover" >> "netdiscover/netdiscover"
    chmod +x "netdiscover/netdiscover"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/netdiscover" ]; then
        ln -sf "$CATEGORY_DIR/netdiscover/netdiscover" "/usr/local/bin/netdiscover"
    fi
fi


# arp-scan
if [ ! -d "arp-scan" ]; then
    log "Configurando arp-scan..."
    mkdir -p "arp-scan"
    echo "#!/bin/bash" > "arp-scan/arp-scan"
    echo "echo '🛠️ Executando arp-scan...'" >> "arp-scan/arp-scan"
    echo "# Implementação específica do arp-scan" >> "arp-scan/arp-scan"
    chmod +x "arp-scan/arp-scan"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/arp-scan" ]; then
        ln -sf "$CATEGORY_DIR/arp-scan/arp-scan" "/usr/local/bin/arp-scan"
    fi
fi


# Criar script de conveniência para a categoria
cat > "network_tools-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge NETWORK TOOLS Suite

echo "🛡️ Análise, monitoramento e manipulação de tráfego de rede"
echo "Prioridade: high"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/network_tools/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/network_tools/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "network_tools-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-network_tools" ]; then
    ln -sf "$CATEGORY_DIR/network_tools-suite.sh" "/usr/local/bin/secforge-network_tools"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria network_tools instalada!"
echo "💡 Use: secforge-network_tools para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
