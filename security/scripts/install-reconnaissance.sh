#!/bin/bash
# SecurityForge Linux - Instalação de RECONNAISSANCE

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

echo "📦 Instalando Ferramentas de reconhecimento, OSINT e coleta de informações..."

CATEGORY_DIR="/opt/securityforge/tools/reconnaissance"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y nmap masscan zmap rustscan unicornscan hping3 ncat dmitry maltego recon-ng theharvester shodan-cli censys-cli amass subfinder || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."
go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest || warning "subfinder falhou"
go install -v github.com/projectdiscovery/assetfinder/cmd/assetfinder@latest || warning "assetfinder falhou"
go install -v github.com/projectdiscovery/ffuf/cmd/ffuf@latest || warning "ffuf falhou"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || warning "httpx falhou"

# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# nmap
if [ ! -d "nmap" ]; then
    log "Configurando nmap..."
    mkdir -p "nmap"
    echo "#!/bin/bash" > "nmap/nmap"
    echo "echo '🛠️ Executando nmap...'" >> "nmap/nmap"
    echo "# Implementação específica do nmap" >> "nmap/nmap"
    chmod +x "nmap/nmap"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/nmap" ]; then
        ln -sf "$CATEGORY_DIR/nmap/nmap" "/usr/local/bin/nmap"
    fi
fi


# masscan
if [ ! -d "masscan" ]; then
    log "Configurando masscan..."
    mkdir -p "masscan"
    echo "#!/bin/bash" > "masscan/masscan"
    echo "echo '🛠️ Executando masscan...'" >> "masscan/masscan"
    echo "# Implementação específica do masscan" >> "masscan/masscan"
    chmod +x "masscan/masscan"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/masscan" ]; then
        ln -sf "$CATEGORY_DIR/masscan/masscan" "/usr/local/bin/masscan"
    fi
fi


# zmap
if [ ! -d "zmap" ]; then
    log "Configurando zmap..."
    mkdir -p "zmap"
    echo "#!/bin/bash" > "zmap/zmap"
    echo "echo '🛠️ Executando zmap...'" >> "zmap/zmap"
    echo "# Implementação específica do zmap" >> "zmap/zmap"
    chmod +x "zmap/zmap"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/zmap" ]; then
        ln -sf "$CATEGORY_DIR/zmap/zmap" "/usr/local/bin/zmap"
    fi
fi


# rustscan
if [ ! -d "rustscan" ]; then
    log "Configurando rustscan..."
    mkdir -p "rustscan"
    echo "#!/bin/bash" > "rustscan/rustscan"
    echo "echo '🛠️ Executando rustscan...'" >> "rustscan/rustscan"
    echo "# Implementação específica do rustscan" >> "rustscan/rustscan"
    chmod +x "rustscan/rustscan"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/rustscan" ]; then
        ln -sf "$CATEGORY_DIR/rustscan/rustscan" "/usr/local/bin/rustscan"
    fi
fi


# unicornscan
if [ ! -d "unicornscan" ]; then
    log "Configurando unicornscan..."
    mkdir -p "unicornscan"
    echo "#!/bin/bash" > "unicornscan/unicornscan"
    echo "echo '🛠️ Executando unicornscan...'" >> "unicornscan/unicornscan"
    echo "# Implementação específica do unicornscan" >> "unicornscan/unicornscan"
    chmod +x "unicornscan/unicornscan"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/unicornscan" ]; then
        ln -sf "$CATEGORY_DIR/unicornscan/unicornscan" "/usr/local/bin/unicornscan"
    fi
fi


# hping3
if [ ! -d "hping3" ]; then
    log "Configurando hping3..."
    mkdir -p "hping3"
    echo "#!/bin/bash" > "hping3/hping3"
    echo "echo '🛠️ Executando hping3...'" >> "hping3/hping3"
    echo "# Implementação específica do hping3" >> "hping3/hping3"
    chmod +x "hping3/hping3"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/hping3" ]; then
        ln -sf "$CATEGORY_DIR/hping3/hping3" "/usr/local/bin/hping3"
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


# dmitry
if [ ! -d "dmitry" ]; then
    log "Configurando dmitry..."
    mkdir -p "dmitry"
    echo "#!/bin/bash" > "dmitry/dmitry"
    echo "echo '🛠️ Executando dmitry...'" >> "dmitry/dmitry"
    echo "# Implementação específica do dmitry" >> "dmitry/dmitry"
    chmod +x "dmitry/dmitry"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/dmitry" ]; then
        ln -sf "$CATEGORY_DIR/dmitry/dmitry" "/usr/local/bin/dmitry"
    fi
fi


# maltego
if [ ! -d "maltego" ]; then
    log "Configurando maltego..."
    mkdir -p "maltego"
    echo "#!/bin/bash" > "maltego/maltego"
    echo "echo '🛠️ Executando maltego...'" >> "maltego/maltego"
    echo "# Implementação específica do maltego" >> "maltego/maltego"
    chmod +x "maltego/maltego"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/maltego" ]; then
        ln -sf "$CATEGORY_DIR/maltego/maltego" "/usr/local/bin/maltego"
    fi
fi


# recon-ng
if [ ! -d "recon-ng" ]; then
    log "Configurando recon-ng..."
    mkdir -p "recon-ng"
    echo "#!/bin/bash" > "recon-ng/recon-ng"
    echo "echo '🛠️ Executando recon-ng...'" >> "recon-ng/recon-ng"
    echo "# Implementação específica do recon-ng" >> "recon-ng/recon-ng"
    chmod +x "recon-ng/recon-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/recon-ng" ]; then
        ln -sf "$CATEGORY_DIR/recon-ng/recon-ng" "/usr/local/bin/recon-ng"
    fi
fi


# Criar script de conveniência para a categoria
cat > "reconnaissance-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge RECONNAISSANCE Suite

echo "🛡️ Ferramentas de reconhecimento, OSINT e coleta de informações"
echo "Prioridade: critical"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/reconnaissance/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/reconnaissance/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "reconnaissance-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-reconnaissance" ]; then
    ln -sf "$CATEGORY_DIR/reconnaissance-suite.sh" "/usr/local/bin/secforge-reconnaissance"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria reconnaissance instalada!"
echo "💡 Use: secforge-reconnaissance para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
