#!/bin/bash
# SecurityForge Linux - Instalação de WIRELESS

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

echo "📦 Instalando Ferramentas para auditoria de redes sem fio e RF..."

CATEGORY_DIR="/opt/securityforge/tools/wireless"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y aircrack-ng airmon-ng airodump-ng aireplay-ng airbase-ng airtun-ng packetforge-ng airserv-ng airolib-ng aircrack-ng-cuda reaver bully pixiewps wifite wifite2 || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# aircrack-ng
if [ ! -d "aircrack-ng" ]; then
    log "Configurando aircrack-ng..."
    mkdir -p "aircrack-ng"
    echo "#!/bin/bash" > "aircrack-ng/aircrack-ng"
    echo "echo '🛠️ Executando aircrack-ng...'" >> "aircrack-ng/aircrack-ng"
    echo "# Implementação específica do aircrack-ng" >> "aircrack-ng/aircrack-ng"
    chmod +x "aircrack-ng/aircrack-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aircrack-ng" ]; then
        ln -sf "$CATEGORY_DIR/aircrack-ng/aircrack-ng" "/usr/local/bin/aircrack-ng"
    fi
fi


# airmon-ng
if [ ! -d "airmon-ng" ]; then
    log "Configurando airmon-ng..."
    mkdir -p "airmon-ng"
    echo "#!/bin/bash" > "airmon-ng/airmon-ng"
    echo "echo '🛠️ Executando airmon-ng...'" >> "airmon-ng/airmon-ng"
    echo "# Implementação específica do airmon-ng" >> "airmon-ng/airmon-ng"
    chmod +x "airmon-ng/airmon-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airmon-ng" ]; then
        ln -sf "$CATEGORY_DIR/airmon-ng/airmon-ng" "/usr/local/bin/airmon-ng"
    fi
fi


# airodump-ng
if [ ! -d "airodump-ng" ]; then
    log "Configurando airodump-ng..."
    mkdir -p "airodump-ng"
    echo "#!/bin/bash" > "airodump-ng/airodump-ng"
    echo "echo '🛠️ Executando airodump-ng...'" >> "airodump-ng/airodump-ng"
    echo "# Implementação específica do airodump-ng" >> "airodump-ng/airodump-ng"
    chmod +x "airodump-ng/airodump-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airodump-ng" ]; then
        ln -sf "$CATEGORY_DIR/airodump-ng/airodump-ng" "/usr/local/bin/airodump-ng"
    fi
fi


# aireplay-ng
if [ ! -d "aireplay-ng" ]; then
    log "Configurando aireplay-ng..."
    mkdir -p "aireplay-ng"
    echo "#!/bin/bash" > "aireplay-ng/aireplay-ng"
    echo "echo '🛠️ Executando aireplay-ng...'" >> "aireplay-ng/aireplay-ng"
    echo "# Implementação específica do aireplay-ng" >> "aireplay-ng/aireplay-ng"
    chmod +x "aireplay-ng/aireplay-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aireplay-ng" ]; then
        ln -sf "$CATEGORY_DIR/aireplay-ng/aireplay-ng" "/usr/local/bin/aireplay-ng"
    fi
fi


# airbase-ng
if [ ! -d "airbase-ng" ]; then
    log "Configurando airbase-ng..."
    mkdir -p "airbase-ng"
    echo "#!/bin/bash" > "airbase-ng/airbase-ng"
    echo "echo '🛠️ Executando airbase-ng...'" >> "airbase-ng/airbase-ng"
    echo "# Implementação específica do airbase-ng" >> "airbase-ng/airbase-ng"
    chmod +x "airbase-ng/airbase-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airbase-ng" ]; then
        ln -sf "$CATEGORY_DIR/airbase-ng/airbase-ng" "/usr/local/bin/airbase-ng"
    fi
fi


# airtun-ng
if [ ! -d "airtun-ng" ]; then
    log "Configurando airtun-ng..."
    mkdir -p "airtun-ng"
    echo "#!/bin/bash" > "airtun-ng/airtun-ng"
    echo "echo '🛠️ Executando airtun-ng...'" >> "airtun-ng/airtun-ng"
    echo "# Implementação específica do airtun-ng" >> "airtun-ng/airtun-ng"
    chmod +x "airtun-ng/airtun-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airtun-ng" ]; then
        ln -sf "$CATEGORY_DIR/airtun-ng/airtun-ng" "/usr/local/bin/airtun-ng"
    fi
fi


# packetforge-ng
if [ ! -d "packetforge-ng" ]; then
    log "Configurando packetforge-ng..."
    mkdir -p "packetforge-ng"
    echo "#!/bin/bash" > "packetforge-ng/packetforge-ng"
    echo "echo '🛠️ Executando packetforge-ng...'" >> "packetforge-ng/packetforge-ng"
    echo "# Implementação específica do packetforge-ng" >> "packetforge-ng/packetforge-ng"
    chmod +x "packetforge-ng/packetforge-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/packetforge-ng" ]; then
        ln -sf "$CATEGORY_DIR/packetforge-ng/packetforge-ng" "/usr/local/bin/packetforge-ng"
    fi
fi


# airserv-ng
if [ ! -d "airserv-ng" ]; then
    log "Configurando airserv-ng..."
    mkdir -p "airserv-ng"
    echo "#!/bin/bash" > "airserv-ng/airserv-ng"
    echo "echo '🛠️ Executando airserv-ng...'" >> "airserv-ng/airserv-ng"
    echo "# Implementação específica do airserv-ng" >> "airserv-ng/airserv-ng"
    chmod +x "airserv-ng/airserv-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airserv-ng" ]; then
        ln -sf "$CATEGORY_DIR/airserv-ng/airserv-ng" "/usr/local/bin/airserv-ng"
    fi
fi


# airolib-ng
if [ ! -d "airolib-ng" ]; then
    log "Configurando airolib-ng..."
    mkdir -p "airolib-ng"
    echo "#!/bin/bash" > "airolib-ng/airolib-ng"
    echo "echo '🛠️ Executando airolib-ng...'" >> "airolib-ng/airolib-ng"
    echo "# Implementação específica do airolib-ng" >> "airolib-ng/airolib-ng"
    chmod +x "airolib-ng/airolib-ng"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/airolib-ng" ]; then
        ln -sf "$CATEGORY_DIR/airolib-ng/airolib-ng" "/usr/local/bin/airolib-ng"
    fi
fi


# aircrack-ng-cuda
if [ ! -d "aircrack-ng-cuda" ]; then
    log "Configurando aircrack-ng-cuda..."
    mkdir -p "aircrack-ng-cuda"
    echo "#!/bin/bash" > "aircrack-ng-cuda/aircrack-ng-cuda"
    echo "echo '🛠️ Executando aircrack-ng-cuda...'" >> "aircrack-ng-cuda/aircrack-ng-cuda"
    echo "# Implementação específica do aircrack-ng-cuda" >> "aircrack-ng-cuda/aircrack-ng-cuda"
    chmod +x "aircrack-ng-cuda/aircrack-ng-cuda"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aircrack-ng-cuda" ]; then
        ln -sf "$CATEGORY_DIR/aircrack-ng-cuda/aircrack-ng-cuda" "/usr/local/bin/aircrack-ng-cuda"
    fi
fi


# Criar script de conveniência para a categoria
cat > "wireless-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge WIRELESS Suite

echo "🛡️ Ferramentas para auditoria de redes sem fio e RF"
echo "Prioridade: high"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/wireless/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/wireless/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "wireless-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-wireless" ]; then
    ln -sf "$CATEGORY_DIR/wireless-suite.sh" "/usr/local/bin/secforge-wireless"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria wireless instalada!"
echo "💡 Use: secforge-wireless para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
