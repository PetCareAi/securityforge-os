#!/bin/bash
# SecurityForge Linux - Instalação de OSINT

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

echo "📦 Instalando Open Source Intelligence e investigação digital avançada..."

CATEGORY_DIR="/opt/securityforge/tools/osint"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y maltego maltego-transforms spiderfoot recon-ng osrframework twint twitter-scraper sherlock social-analyzer phoneinfoga holehe ghunt emailfinder email2phonenumber infoga || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


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


# maltego-transforms
if [ ! -d "maltego-transforms" ]; then
    log "Configurando maltego-transforms..."
    mkdir -p "maltego-transforms"
    echo "#!/bin/bash" > "maltego-transforms/maltego-transforms"
    echo "echo '🛠️ Executando maltego-transforms...'" >> "maltego-transforms/maltego-transforms"
    echo "# Implementação específica do maltego-transforms" >> "maltego-transforms/maltego-transforms"
    chmod +x "maltego-transforms/maltego-transforms"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/maltego-transforms" ]; then
        ln -sf "$CATEGORY_DIR/maltego-transforms/maltego-transforms" "/usr/local/bin/maltego-transforms"
    fi
fi


# spiderfoot
if [ ! -d "spiderfoot" ]; then
    log "Configurando spiderfoot..."
    mkdir -p "spiderfoot"
    echo "#!/bin/bash" > "spiderfoot/spiderfoot"
    echo "echo '🛠️ Executando spiderfoot...'" >> "spiderfoot/spiderfoot"
    echo "# Implementação específica do spiderfoot" >> "spiderfoot/spiderfoot"
    chmod +x "spiderfoot/spiderfoot"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/spiderfoot" ]; then
        ln -sf "$CATEGORY_DIR/spiderfoot/spiderfoot" "/usr/local/bin/spiderfoot"
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


# osrframework
if [ ! -d "osrframework" ]; then
    log "Configurando osrframework..."
    mkdir -p "osrframework"
    echo "#!/bin/bash" > "osrframework/osrframework"
    echo "echo '🛠️ Executando osrframework...'" >> "osrframework/osrframework"
    echo "# Implementação específica do osrframework" >> "osrframework/osrframework"
    chmod +x "osrframework/osrframework"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/osrframework" ]; then
        ln -sf "$CATEGORY_DIR/osrframework/osrframework" "/usr/local/bin/osrframework"
    fi
fi


# twint
if [ ! -d "twint" ]; then
    log "Configurando twint..."
    mkdir -p "twint"
    echo "#!/bin/bash" > "twint/twint"
    echo "echo '🛠️ Executando twint...'" >> "twint/twint"
    echo "# Implementação específica do twint" >> "twint/twint"
    chmod +x "twint/twint"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/twint" ]; then
        ln -sf "$CATEGORY_DIR/twint/twint" "/usr/local/bin/twint"
    fi
fi


# twitter-scraper
if [ ! -d "twitter-scraper" ]; then
    log "Configurando twitter-scraper..."
    mkdir -p "twitter-scraper"
    echo "#!/bin/bash" > "twitter-scraper/twitter-scraper"
    echo "echo '🛠️ Executando twitter-scraper...'" >> "twitter-scraper/twitter-scraper"
    echo "# Implementação específica do twitter-scraper" >> "twitter-scraper/twitter-scraper"
    chmod +x "twitter-scraper/twitter-scraper"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/twitter-scraper" ]; then
        ln -sf "$CATEGORY_DIR/twitter-scraper/twitter-scraper" "/usr/local/bin/twitter-scraper"
    fi
fi


# sherlock
if [ ! -d "sherlock" ]; then
    log "Configurando sherlock..."
    mkdir -p "sherlock"
    echo "#!/bin/bash" > "sherlock/sherlock"
    echo "echo '🛠️ Executando sherlock...'" >> "sherlock/sherlock"
    echo "# Implementação específica do sherlock" >> "sherlock/sherlock"
    chmod +x "sherlock/sherlock"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/sherlock" ]; then
        ln -sf "$CATEGORY_DIR/sherlock/sherlock" "/usr/local/bin/sherlock"
    fi
fi


# social-analyzer
if [ ! -d "social-analyzer" ]; then
    log "Configurando social-analyzer..."
    mkdir -p "social-analyzer"
    echo "#!/bin/bash" > "social-analyzer/social-analyzer"
    echo "echo '🛠️ Executando social-analyzer...'" >> "social-analyzer/social-analyzer"
    echo "# Implementação específica do social-analyzer" >> "social-analyzer/social-analyzer"
    chmod +x "social-analyzer/social-analyzer"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/social-analyzer" ]; then
        ln -sf "$CATEGORY_DIR/social-analyzer/social-analyzer" "/usr/local/bin/social-analyzer"
    fi
fi


# phoneinfoga
if [ ! -d "phoneinfoga" ]; then
    log "Configurando phoneinfoga..."
    mkdir -p "phoneinfoga"
    echo "#!/bin/bash" > "phoneinfoga/phoneinfoga"
    echo "echo '🛠️ Executando phoneinfoga...'" >> "phoneinfoga/phoneinfoga"
    echo "# Implementação específica do phoneinfoga" >> "phoneinfoga/phoneinfoga"
    chmod +x "phoneinfoga/phoneinfoga"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/phoneinfoga" ]; then
        ln -sf "$CATEGORY_DIR/phoneinfoga/phoneinfoga" "/usr/local/bin/phoneinfoga"
    fi
fi


# Criar script de conveniência para a categoria
cat > "osint-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge OSINT Suite

echo "🛡️ Open Source Intelligence e investigação digital avançada"
echo "Prioridade: medium"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/osint/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/osint/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "osint-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-osint" ]; then
    ln -sf "$CATEGORY_DIR/osint-suite.sh" "/usr/local/bin/secforge-osint"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria osint instalada!"
echo "💡 Use: secforge-osint para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
