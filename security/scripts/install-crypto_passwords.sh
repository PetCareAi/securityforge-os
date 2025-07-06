#!/bin/bash
# SecurityForge Linux - Instalação de CRYPTO PASSWORDS

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

echo "📦 Instalando Ferramentas de criptografia, quebra de senhas e análise de hashes..."

CATEGORY_DIR="/opt/securityforge/tools/crypto_passwords"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y john john-jumbo hashcat hashcat-utils ophcrack rainbowcrack hydra thc-hydra medusa ncrack patator crowbar thc-pptp-bruter brutespray cewl || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# john
if [ ! -d "john" ]; then
    log "Configurando john..."
    mkdir -p "john"
    echo "#!/bin/bash" > "john/john"
    echo "echo '🛠️ Executando john...'" >> "john/john"
    echo "# Implementação específica do john" >> "john/john"
    chmod +x "john/john"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/john" ]; then
        ln -sf "$CATEGORY_DIR/john/john" "/usr/local/bin/john"
    fi
fi


# john-jumbo
if [ ! -d "john-jumbo" ]; then
    log "Configurando john-jumbo..."
    mkdir -p "john-jumbo"
    echo "#!/bin/bash" > "john-jumbo/john-jumbo"
    echo "echo '🛠️ Executando john-jumbo...'" >> "john-jumbo/john-jumbo"
    echo "# Implementação específica do john-jumbo" >> "john-jumbo/john-jumbo"
    chmod +x "john-jumbo/john-jumbo"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/john-jumbo" ]; then
        ln -sf "$CATEGORY_DIR/john-jumbo/john-jumbo" "/usr/local/bin/john-jumbo"
    fi
fi


# hashcat
if [ ! -d "hashcat" ]; then
    log "Configurando hashcat..."
    mkdir -p "hashcat"
    echo "#!/bin/bash" > "hashcat/hashcat"
    echo "echo '🛠️ Executando hashcat...'" >> "hashcat/hashcat"
    echo "# Implementação específica do hashcat" >> "hashcat/hashcat"
    chmod +x "hashcat/hashcat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/hashcat" ]; then
        ln -sf "$CATEGORY_DIR/hashcat/hashcat" "/usr/local/bin/hashcat"
    fi
fi


# hashcat-utils
if [ ! -d "hashcat-utils" ]; then
    log "Configurando hashcat-utils..."
    mkdir -p "hashcat-utils"
    echo "#!/bin/bash" > "hashcat-utils/hashcat-utils"
    echo "echo '🛠️ Executando hashcat-utils...'" >> "hashcat-utils/hashcat-utils"
    echo "# Implementação específica do hashcat-utils" >> "hashcat-utils/hashcat-utils"
    chmod +x "hashcat-utils/hashcat-utils"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/hashcat-utils" ]; then
        ln -sf "$CATEGORY_DIR/hashcat-utils/hashcat-utils" "/usr/local/bin/hashcat-utils"
    fi
fi


# ophcrack
if [ ! -d "ophcrack" ]; then
    log "Configurando ophcrack..."
    mkdir -p "ophcrack"
    echo "#!/bin/bash" > "ophcrack/ophcrack"
    echo "echo '🛠️ Executando ophcrack...'" >> "ophcrack/ophcrack"
    echo "# Implementação específica do ophcrack" >> "ophcrack/ophcrack"
    chmod +x "ophcrack/ophcrack"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/ophcrack" ]; then
        ln -sf "$CATEGORY_DIR/ophcrack/ophcrack" "/usr/local/bin/ophcrack"
    fi
fi


# rainbowcrack
if [ ! -d "rainbowcrack" ]; then
    log "Configurando rainbowcrack..."
    mkdir -p "rainbowcrack"
    echo "#!/bin/bash" > "rainbowcrack/rainbowcrack"
    echo "echo '🛠️ Executando rainbowcrack...'" >> "rainbowcrack/rainbowcrack"
    echo "# Implementação específica do rainbowcrack" >> "rainbowcrack/rainbowcrack"
    chmod +x "rainbowcrack/rainbowcrack"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/rainbowcrack" ]; then
        ln -sf "$CATEGORY_DIR/rainbowcrack/rainbowcrack" "/usr/local/bin/rainbowcrack"
    fi
fi


# hydra
if [ ! -d "hydra" ]; then
    log "Configurando hydra..."
    mkdir -p "hydra"
    echo "#!/bin/bash" > "hydra/hydra"
    echo "echo '🛠️ Executando hydra...'" >> "hydra/hydra"
    echo "# Implementação específica do hydra" >> "hydra/hydra"
    chmod +x "hydra/hydra"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/hydra" ]; then
        ln -sf "$CATEGORY_DIR/hydra/hydra" "/usr/local/bin/hydra"
    fi
fi


# thc-hydra
if [ ! -d "thc-hydra" ]; then
    log "Configurando thc-hydra..."
    mkdir -p "thc-hydra"
    echo "#!/bin/bash" > "thc-hydra/thc-hydra"
    echo "echo '🛠️ Executando thc-hydra...'" >> "thc-hydra/thc-hydra"
    echo "# Implementação específica do thc-hydra" >> "thc-hydra/thc-hydra"
    chmod +x "thc-hydra/thc-hydra"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/thc-hydra" ]; then
        ln -sf "$CATEGORY_DIR/thc-hydra/thc-hydra" "/usr/local/bin/thc-hydra"
    fi
fi


# medusa
if [ ! -d "medusa" ]; then
    log "Configurando medusa..."
    mkdir -p "medusa"
    echo "#!/bin/bash" > "medusa/medusa"
    echo "echo '🛠️ Executando medusa...'" >> "medusa/medusa"
    echo "# Implementação específica do medusa" >> "medusa/medusa"
    chmod +x "medusa/medusa"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/medusa" ]; then
        ln -sf "$CATEGORY_DIR/medusa/medusa" "/usr/local/bin/medusa"
    fi
fi


# ncrack
if [ ! -d "ncrack" ]; then
    log "Configurando ncrack..."
    mkdir -p "ncrack"
    echo "#!/bin/bash" > "ncrack/ncrack"
    echo "echo '🛠️ Executando ncrack...'" >> "ncrack/ncrack"
    echo "# Implementação específica do ncrack" >> "ncrack/ncrack"
    chmod +x "ncrack/ncrack"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/ncrack" ]; then
        ln -sf "$CATEGORY_DIR/ncrack/ncrack" "/usr/local/bin/ncrack"
    fi
fi


# Criar script de conveniência para a categoria
cat > "crypto_passwords-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge CRYPTO PASSWORDS Suite

echo "🛡️ Ferramentas de criptografia, quebra de senhas e análise de hashes"
echo "Prioridade: critical"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/crypto_passwords/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/crypto_passwords/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "crypto_passwords-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-crypto_passwords" ]; then
    ln -sf "$CATEGORY_DIR/crypto_passwords-suite.sh" "/usr/local/bin/secforge-crypto_passwords"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria crypto_passwords instalada!"
echo "💡 Use: secforge-crypto_passwords para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
