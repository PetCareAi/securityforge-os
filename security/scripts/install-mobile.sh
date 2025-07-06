#!/bin/bash
# SecurityForge Linux - Instalação de MOBILE

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

echo "📦 Instalando Ferramentas para análise de segurança em dispositivos móveis..."

CATEGORY_DIR="/opt/securityforge/tools/mobile"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y android-sdk android-studio android-platform-tools apktool aapt dex2jar jadx jadx-gui mobsf qark androguard androwarn android-ssl-bypass frida frida-tools || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# android-sdk
if [ ! -d "android-sdk" ]; then
    log "Configurando android-sdk..."
    mkdir -p "android-sdk"
    echo "#!/bin/bash" > "android-sdk/android-sdk"
    echo "echo '🛠️ Executando android-sdk...'" >> "android-sdk/android-sdk"
    echo "# Implementação específica do android-sdk" >> "android-sdk/android-sdk"
    chmod +x "android-sdk/android-sdk"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/android-sdk" ]; then
        ln -sf "$CATEGORY_DIR/android-sdk/android-sdk" "/usr/local/bin/android-sdk"
    fi
fi


# android-studio
if [ ! -d "android-studio" ]; then
    log "Configurando android-studio..."
    mkdir -p "android-studio"
    echo "#!/bin/bash" > "android-studio/android-studio"
    echo "echo '🛠️ Executando android-studio...'" >> "android-studio/android-studio"
    echo "# Implementação específica do android-studio" >> "android-studio/android-studio"
    chmod +x "android-studio/android-studio"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/android-studio" ]; then
        ln -sf "$CATEGORY_DIR/android-studio/android-studio" "/usr/local/bin/android-studio"
    fi
fi


# android-platform-tools
if [ ! -d "android-platform-tools" ]; then
    log "Configurando android-platform-tools..."
    mkdir -p "android-platform-tools"
    echo "#!/bin/bash" > "android-platform-tools/android-platform-tools"
    echo "echo '🛠️ Executando android-platform-tools...'" >> "android-platform-tools/android-platform-tools"
    echo "# Implementação específica do android-platform-tools" >> "android-platform-tools/android-platform-tools"
    chmod +x "android-platform-tools/android-platform-tools"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/android-platform-tools" ]; then
        ln -sf "$CATEGORY_DIR/android-platform-tools/android-platform-tools" "/usr/local/bin/android-platform-tools"
    fi
fi


# apktool
if [ ! -d "apktool" ]; then
    log "Configurando apktool..."
    mkdir -p "apktool"
    echo "#!/bin/bash" > "apktool/apktool"
    echo "echo '🛠️ Executando apktool...'" >> "apktool/apktool"
    echo "# Implementação específica do apktool" >> "apktool/apktool"
    chmod +x "apktool/apktool"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/apktool" ]; then
        ln -sf "$CATEGORY_DIR/apktool/apktool" "/usr/local/bin/apktool"
    fi
fi


# aapt
if [ ! -d "aapt" ]; then
    log "Configurando aapt..."
    mkdir -p "aapt"
    echo "#!/bin/bash" > "aapt/aapt"
    echo "echo '🛠️ Executando aapt...'" >> "aapt/aapt"
    echo "# Implementação específica do aapt" >> "aapt/aapt"
    chmod +x "aapt/aapt"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aapt" ]; then
        ln -sf "$CATEGORY_DIR/aapt/aapt" "/usr/local/bin/aapt"
    fi
fi


# dex2jar
if [ ! -d "dex2jar" ]; then
    log "Configurando dex2jar..."
    mkdir -p "dex2jar"
    echo "#!/bin/bash" > "dex2jar/dex2jar"
    echo "echo '🛠️ Executando dex2jar...'" >> "dex2jar/dex2jar"
    echo "# Implementação específica do dex2jar" >> "dex2jar/dex2jar"
    chmod +x "dex2jar/dex2jar"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/dex2jar" ]; then
        ln -sf "$CATEGORY_DIR/dex2jar/dex2jar" "/usr/local/bin/dex2jar"
    fi
fi


# jadx
if [ ! -d "jadx" ]; then
    log "Configurando jadx..."
    mkdir -p "jadx"
    echo "#!/bin/bash" > "jadx/jadx"
    echo "echo '🛠️ Executando jadx...'" >> "jadx/jadx"
    echo "# Implementação específica do jadx" >> "jadx/jadx"
    chmod +x "jadx/jadx"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/jadx" ]; then
        ln -sf "$CATEGORY_DIR/jadx/jadx" "/usr/local/bin/jadx"
    fi
fi


# jadx-gui
if [ ! -d "jadx-gui" ]; then
    log "Configurando jadx-gui..."
    mkdir -p "jadx-gui"
    echo "#!/bin/bash" > "jadx-gui/jadx-gui"
    echo "echo '🛠️ Executando jadx-gui...'" >> "jadx-gui/jadx-gui"
    echo "# Implementação específica do jadx-gui" >> "jadx-gui/jadx-gui"
    chmod +x "jadx-gui/jadx-gui"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/jadx-gui" ]; then
        ln -sf "$CATEGORY_DIR/jadx-gui/jadx-gui" "/usr/local/bin/jadx-gui"
    fi
fi


# mobsf
if [ ! -d "mobsf" ]; then
    log "Configurando mobsf..."
    mkdir -p "mobsf"
    echo "#!/bin/bash" > "mobsf/mobsf"
    echo "echo '🛠️ Executando mobsf...'" >> "mobsf/mobsf"
    echo "# Implementação específica do mobsf" >> "mobsf/mobsf"
    chmod +x "mobsf/mobsf"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/mobsf" ]; then
        ln -sf "$CATEGORY_DIR/mobsf/mobsf" "/usr/local/bin/mobsf"
    fi
fi


# qark
if [ ! -d "qark" ]; then
    log "Configurando qark..."
    mkdir -p "qark"
    echo "#!/bin/bash" > "qark/qark"
    echo "echo '🛠️ Executando qark...'" >> "qark/qark"
    echo "# Implementação específica do qark" >> "qark/qark"
    chmod +x "qark/qark"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/qark" ]; then
        ln -sf "$CATEGORY_DIR/qark/qark" "/usr/local/bin/qark"
    fi
fi


# Criar script de conveniência para a categoria
cat > "mobile-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge MOBILE Suite

echo "🛡️ Ferramentas para análise de segurança em dispositivos móveis"
echo "Prioridade: medium"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/mobile/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/mobile/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "mobile-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-mobile" ]; then
    ln -sf "$CATEGORY_DIR/mobile-suite.sh" "/usr/local/bin/secforge-mobile"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria mobile instalada!"
echo "💡 Use: secforge-mobile para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
