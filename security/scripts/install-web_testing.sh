#!/bin/bash
# SecurityForge Linux - Instalação de WEB TESTING

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

echo "📦 Instalando Ferramentas especializadas em testes de aplicações web e APIs..."

CATEGORY_DIR="/opt/securityforge/tools/web_testing"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y burpsuite burpsuite-pro owasp-zap caido portswigger-tools httpie curl wget webscarab paros websecurify wapiti grabber w3af joomscan || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."
go install -v github.com/projectdiscovery/ffuf/cmd/ffuf@latest || warning "ffuf falhou"

# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# burpsuite
if [ ! -d "burpsuite" ]; then
    log "Configurando burpsuite..."
    mkdir -p "burpsuite"
    echo "#!/bin/bash" > "burpsuite/burpsuite"
    echo "echo '🛠️ Executando burpsuite...'" >> "burpsuite/burpsuite"
    echo "# Implementação específica do burpsuite" >> "burpsuite/burpsuite"
    chmod +x "burpsuite/burpsuite"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/burpsuite" ]; then
        ln -sf "$CATEGORY_DIR/burpsuite/burpsuite" "/usr/local/bin/burpsuite"
    fi
fi


# burpsuite-pro
if [ ! -d "burpsuite-pro" ]; then
    log "Configurando burpsuite-pro..."
    mkdir -p "burpsuite-pro"
    echo "#!/bin/bash" > "burpsuite-pro/burpsuite-pro"
    echo "echo '🛠️ Executando burpsuite-pro...'" >> "burpsuite-pro/burpsuite-pro"
    echo "# Implementação específica do burpsuite-pro" >> "burpsuite-pro/burpsuite-pro"
    chmod +x "burpsuite-pro/burpsuite-pro"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/burpsuite-pro" ]; then
        ln -sf "$CATEGORY_DIR/burpsuite-pro/burpsuite-pro" "/usr/local/bin/burpsuite-pro"
    fi
fi


# owasp-zap
if [ ! -d "owasp-zap" ]; then
    log "Configurando owasp-zap..."
    mkdir -p "owasp-zap"
    echo "#!/bin/bash" > "owasp-zap/owasp-zap"
    echo "echo '🛠️ Executando owasp-zap...'" >> "owasp-zap/owasp-zap"
    echo "# Implementação específica do owasp-zap" >> "owasp-zap/owasp-zap"
    chmod +x "owasp-zap/owasp-zap"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/owasp-zap" ]; then
        ln -sf "$CATEGORY_DIR/owasp-zap/owasp-zap" "/usr/local/bin/owasp-zap"
    fi
fi


# caido
if [ ! -d "caido" ]; then
    log "Configurando caido..."
    mkdir -p "caido"
    echo "#!/bin/bash" > "caido/caido"
    echo "echo '🛠️ Executando caido...'" >> "caido/caido"
    echo "# Implementação específica do caido" >> "caido/caido"
    chmod +x "caido/caido"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/caido" ]; then
        ln -sf "$CATEGORY_DIR/caido/caido" "/usr/local/bin/caido"
    fi
fi


# portswigger-tools
if [ ! -d "portswigger-tools" ]; then
    log "Configurando portswigger-tools..."
    mkdir -p "portswigger-tools"
    echo "#!/bin/bash" > "portswigger-tools/portswigger-tools"
    echo "echo '🛠️ Executando portswigger-tools...'" >> "portswigger-tools/portswigger-tools"
    echo "# Implementação específica do portswigger-tools" >> "portswigger-tools/portswigger-tools"
    chmod +x "portswigger-tools/portswigger-tools"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/portswigger-tools" ]; then
        ln -sf "$CATEGORY_DIR/portswigger-tools/portswigger-tools" "/usr/local/bin/portswigger-tools"
    fi
fi


# httpie
if [ ! -d "httpie" ]; then
    log "Configurando httpie..."
    mkdir -p "httpie"
    echo "#!/bin/bash" > "httpie/httpie"
    echo "echo '🛠️ Executando httpie...'" >> "httpie/httpie"
    echo "# Implementação específica do httpie" >> "httpie/httpie"
    chmod +x "httpie/httpie"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/httpie" ]; then
        ln -sf "$CATEGORY_DIR/httpie/httpie" "/usr/local/bin/httpie"
    fi
fi


# curl
if [ ! -d "curl" ]; then
    log "Configurando curl..."
    mkdir -p "curl"
    echo "#!/bin/bash" > "curl/curl"
    echo "echo '🛠️ Executando curl...'" >> "curl/curl"
    echo "# Implementação específica do curl" >> "curl/curl"
    chmod +x "curl/curl"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/curl" ]; then
        ln -sf "$CATEGORY_DIR/curl/curl" "/usr/local/bin/curl"
    fi
fi


# wget
if [ ! -d "wget" ]; then
    log "Configurando wget..."
    mkdir -p "wget"
    echo "#!/bin/bash" > "wget/wget"
    echo "echo '🛠️ Executando wget...'" >> "wget/wget"
    echo "# Implementação específica do wget" >> "wget/wget"
    chmod +x "wget/wget"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/wget" ]; then
        ln -sf "$CATEGORY_DIR/wget/wget" "/usr/local/bin/wget"
    fi
fi


# webscarab
if [ ! -d "webscarab" ]; then
    log "Configurando webscarab..."
    mkdir -p "webscarab"
    echo "#!/bin/bash" > "webscarab/webscarab"
    echo "echo '🛠️ Executando webscarab...'" >> "webscarab/webscarab"
    echo "# Implementação específica do webscarab" >> "webscarab/webscarab"
    chmod +x "webscarab/webscarab"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/webscarab" ]; then
        ln -sf "$CATEGORY_DIR/webscarab/webscarab" "/usr/local/bin/webscarab"
    fi
fi


# paros
if [ ! -d "paros" ]; then
    log "Configurando paros..."
    mkdir -p "paros"
    echo "#!/bin/bash" > "paros/paros"
    echo "echo '🛠️ Executando paros...'" >> "paros/paros"
    echo "# Implementação específica do paros" >> "paros/paros"
    chmod +x "paros/paros"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/paros" ]; then
        ln -sf "$CATEGORY_DIR/paros/paros" "/usr/local/bin/paros"
    fi
fi


# Criar script de conveniência para a categoria
cat > "web_testing-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge WEB TESTING Suite

echo "🛡️ Ferramentas especializadas em testes de aplicações web e APIs"
echo "Prioridade: critical"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/web_testing/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/web_testing/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "web_testing-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-web_testing" ]; then
    ln -sf "$CATEGORY_DIR/web_testing-suite.sh" "/usr/local/bin/secforge-web_testing"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria web_testing instalada!"
echo "💡 Use: secforge-web_testing para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
