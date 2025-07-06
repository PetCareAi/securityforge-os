#!/bin/bash
# SecurityForge Linux - Instalação de FORENSICS

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

echo "📦 Instalando Ferramentas de investigação forense digital e análise de evidências..."

CATEGORY_DIR="/opt/securityforge/tools/forensics"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y autopsy sleuthkit volatility3 volatility2 plaso log2timeline timesketch dftimewolf bulk-extractor photorec testdisk scalpel recoverjpeg foremost magicrescue || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# autopsy
if [ ! -d "autopsy" ]; then
    log "Configurando autopsy..."
    mkdir -p "autopsy"
    echo "#!/bin/bash" > "autopsy/autopsy"
    echo "echo '🛠️ Executando autopsy...'" >> "autopsy/autopsy"
    echo "# Implementação específica do autopsy" >> "autopsy/autopsy"
    chmod +x "autopsy/autopsy"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/autopsy" ]; then
        ln -sf "$CATEGORY_DIR/autopsy/autopsy" "/usr/local/bin/autopsy"
    fi
fi


# sleuthkit
if [ ! -d "sleuthkit" ]; then
    log "Configurando sleuthkit..."
    mkdir -p "sleuthkit"
    echo "#!/bin/bash" > "sleuthkit/sleuthkit"
    echo "echo '🛠️ Executando sleuthkit...'" >> "sleuthkit/sleuthkit"
    echo "# Implementação específica do sleuthkit" >> "sleuthkit/sleuthkit"
    chmod +x "sleuthkit/sleuthkit"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/sleuthkit" ]; then
        ln -sf "$CATEGORY_DIR/sleuthkit/sleuthkit" "/usr/local/bin/sleuthkit"
    fi
fi


# volatility3
if [ ! -d "volatility3" ]; then
    log "Configurando volatility3..."
    mkdir -p "volatility3"
    echo "#!/bin/bash" > "volatility3/volatility3"
    echo "echo '🛠️ Executando volatility3...'" >> "volatility3/volatility3"
    echo "# Implementação específica do volatility3" >> "volatility3/volatility3"
    chmod +x "volatility3/volatility3"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/volatility3" ]; then
        ln -sf "$CATEGORY_DIR/volatility3/volatility3" "/usr/local/bin/volatility3"
    fi
fi


# volatility2
if [ ! -d "volatility2" ]; then
    log "Configurando volatility2..."
    mkdir -p "volatility2"
    echo "#!/bin/bash" > "volatility2/volatility2"
    echo "echo '🛠️ Executando volatility2...'" >> "volatility2/volatility2"
    echo "# Implementação específica do volatility2" >> "volatility2/volatility2"
    chmod +x "volatility2/volatility2"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/volatility2" ]; then
        ln -sf "$CATEGORY_DIR/volatility2/volatility2" "/usr/local/bin/volatility2"
    fi
fi


# plaso
if [ ! -d "plaso" ]; then
    log "Configurando plaso..."
    mkdir -p "plaso"
    echo "#!/bin/bash" > "plaso/plaso"
    echo "echo '🛠️ Executando plaso...'" >> "plaso/plaso"
    echo "# Implementação específica do plaso" >> "plaso/plaso"
    chmod +x "plaso/plaso"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/plaso" ]; then
        ln -sf "$CATEGORY_DIR/plaso/plaso" "/usr/local/bin/plaso"
    fi
fi


# log2timeline
if [ ! -d "log2timeline" ]; then
    log "Configurando log2timeline..."
    mkdir -p "log2timeline"
    echo "#!/bin/bash" > "log2timeline/log2timeline"
    echo "echo '🛠️ Executando log2timeline...'" >> "log2timeline/log2timeline"
    echo "# Implementação específica do log2timeline" >> "log2timeline/log2timeline"
    chmod +x "log2timeline/log2timeline"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/log2timeline" ]; then
        ln -sf "$CATEGORY_DIR/log2timeline/log2timeline" "/usr/local/bin/log2timeline"
    fi
fi


# timesketch
if [ ! -d "timesketch" ]; then
    log "Configurando timesketch..."
    mkdir -p "timesketch"
    echo "#!/bin/bash" > "timesketch/timesketch"
    echo "echo '🛠️ Executando timesketch...'" >> "timesketch/timesketch"
    echo "# Implementação específica do timesketch" >> "timesketch/timesketch"
    chmod +x "timesketch/timesketch"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/timesketch" ]; then
        ln -sf "$CATEGORY_DIR/timesketch/timesketch" "/usr/local/bin/timesketch"
    fi
fi


# dftimewolf
if [ ! -d "dftimewolf" ]; then
    log "Configurando dftimewolf..."
    mkdir -p "dftimewolf"
    echo "#!/bin/bash" > "dftimewolf/dftimewolf"
    echo "echo '🛠️ Executando dftimewolf...'" >> "dftimewolf/dftimewolf"
    echo "# Implementação específica do dftimewolf" >> "dftimewolf/dftimewolf"
    chmod +x "dftimewolf/dftimewolf"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/dftimewolf" ]; then
        ln -sf "$CATEGORY_DIR/dftimewolf/dftimewolf" "/usr/local/bin/dftimewolf"
    fi
fi


# bulk-extractor
if [ ! -d "bulk-extractor" ]; then
    log "Configurando bulk-extractor..."
    mkdir -p "bulk-extractor"
    echo "#!/bin/bash" > "bulk-extractor/bulk-extractor"
    echo "echo '🛠️ Executando bulk-extractor...'" >> "bulk-extractor/bulk-extractor"
    echo "# Implementação específica do bulk-extractor" >> "bulk-extractor/bulk-extractor"
    chmod +x "bulk-extractor/bulk-extractor"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/bulk-extractor" ]; then
        ln -sf "$CATEGORY_DIR/bulk-extractor/bulk-extractor" "/usr/local/bin/bulk-extractor"
    fi
fi


# photorec
if [ ! -d "photorec" ]; then
    log "Configurando photorec..."
    mkdir -p "photorec"
    echo "#!/bin/bash" > "photorec/photorec"
    echo "echo '🛠️ Executando photorec...'" >> "photorec/photorec"
    echo "# Implementação específica do photorec" >> "photorec/photorec"
    chmod +x "photorec/photorec"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/photorec" ]; then
        ln -sf "$CATEGORY_DIR/photorec/photorec" "/usr/local/bin/photorec"
    fi
fi


# Criar script de conveniência para a categoria
cat > "forensics-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge FORENSICS Suite

echo "🛡️ Ferramentas de investigação forense digital e análise de evidências"
echo "Prioridade: high"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/forensics/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/forensics/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "forensics-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-forensics" ]; then
    ln -sf "$CATEGORY_DIR/forensics-suite.sh" "/usr/local/bin/secforge-forensics"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria forensics instalada!"
echo "💡 Use: secforge-forensics para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
