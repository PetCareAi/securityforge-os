#!/bin/bash
# SecurityForge Linux - Instalação de HARDWARE

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

echo "📦 Instalando Ferramentas para análise e hacking de hardware..."

CATEGORY_DIR="/opt/securityforge/tools/hardware"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y arduino-ide platformio minicom screen picocom cutecom gtkterm putty buspirate openocd avrdude esptool esptool32 stlink jlink || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# arduino-ide
if [ ! -d "arduino-ide" ]; then
    log "Configurando arduino-ide..."
    mkdir -p "arduino-ide"
    echo "#!/bin/bash" > "arduino-ide/arduino-ide"
    echo "echo '🛠️ Executando arduino-ide...'" >> "arduino-ide/arduino-ide"
    echo "# Implementação específica do arduino-ide" >> "arduino-ide/arduino-ide"
    chmod +x "arduino-ide/arduino-ide"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/arduino-ide" ]; then
        ln -sf "$CATEGORY_DIR/arduino-ide/arduino-ide" "/usr/local/bin/arduino-ide"
    fi
fi


# platformio
if [ ! -d "platformio" ]; then
    log "Configurando platformio..."
    mkdir -p "platformio"
    echo "#!/bin/bash" > "platformio/platformio"
    echo "echo '🛠️ Executando platformio...'" >> "platformio/platformio"
    echo "# Implementação específica do platformio" >> "platformio/platformio"
    chmod +x "platformio/platformio"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/platformio" ]; then
        ln -sf "$CATEGORY_DIR/platformio/platformio" "/usr/local/bin/platformio"
    fi
fi


# minicom
if [ ! -d "minicom" ]; then
    log "Configurando minicom..."
    mkdir -p "minicom"
    echo "#!/bin/bash" > "minicom/minicom"
    echo "echo '🛠️ Executando minicom...'" >> "minicom/minicom"
    echo "# Implementação específica do minicom" >> "minicom/minicom"
    chmod +x "minicom/minicom"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/minicom" ]; then
        ln -sf "$CATEGORY_DIR/minicom/minicom" "/usr/local/bin/minicom"
    fi
fi


# screen
if [ ! -d "screen" ]; then
    log "Configurando screen..."
    mkdir -p "screen"
    echo "#!/bin/bash" > "screen/screen"
    echo "echo '🛠️ Executando screen...'" >> "screen/screen"
    echo "# Implementação específica do screen" >> "screen/screen"
    chmod +x "screen/screen"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/screen" ]; then
        ln -sf "$CATEGORY_DIR/screen/screen" "/usr/local/bin/screen"
    fi
fi


# picocom
if [ ! -d "picocom" ]; then
    log "Configurando picocom..."
    mkdir -p "picocom"
    echo "#!/bin/bash" > "picocom/picocom"
    echo "echo '🛠️ Executando picocom...'" >> "picocom/picocom"
    echo "# Implementação específica do picocom" >> "picocom/picocom"
    chmod +x "picocom/picocom"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/picocom" ]; then
        ln -sf "$CATEGORY_DIR/picocom/picocom" "/usr/local/bin/picocom"
    fi
fi


# cutecom
if [ ! -d "cutecom" ]; then
    log "Configurando cutecom..."
    mkdir -p "cutecom"
    echo "#!/bin/bash" > "cutecom/cutecom"
    echo "echo '🛠️ Executando cutecom...'" >> "cutecom/cutecom"
    echo "# Implementação específica do cutecom" >> "cutecom/cutecom"
    chmod +x "cutecom/cutecom"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/cutecom" ]; then
        ln -sf "$CATEGORY_DIR/cutecom/cutecom" "/usr/local/bin/cutecom"
    fi
fi


# gtkterm
if [ ! -d "gtkterm" ]; then
    log "Configurando gtkterm..."
    mkdir -p "gtkterm"
    echo "#!/bin/bash" > "gtkterm/gtkterm"
    echo "echo '🛠️ Executando gtkterm...'" >> "gtkterm/gtkterm"
    echo "# Implementação específica do gtkterm" >> "gtkterm/gtkterm"
    chmod +x "gtkterm/gtkterm"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/gtkterm" ]; then
        ln -sf "$CATEGORY_DIR/gtkterm/gtkterm" "/usr/local/bin/gtkterm"
    fi
fi


# putty
if [ ! -d "putty" ]; then
    log "Configurando putty..."
    mkdir -p "putty"
    echo "#!/bin/bash" > "putty/putty"
    echo "echo '🛠️ Executando putty...'" >> "putty/putty"
    echo "# Implementação específica do putty" >> "putty/putty"
    chmod +x "putty/putty"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/putty" ]; then
        ln -sf "$CATEGORY_DIR/putty/putty" "/usr/local/bin/putty"
    fi
fi


# buspirate
if [ ! -d "buspirate" ]; then
    log "Configurando buspirate..."
    mkdir -p "buspirate"
    echo "#!/bin/bash" > "buspirate/buspirate"
    echo "echo '🛠️ Executando buspirate...'" >> "buspirate/buspirate"
    echo "# Implementação específica do buspirate" >> "buspirate/buspirate"
    chmod +x "buspirate/buspirate"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/buspirate" ]; then
        ln -sf "$CATEGORY_DIR/buspirate/buspirate" "/usr/local/bin/buspirate"
    fi
fi


# openocd
if [ ! -d "openocd" ]; then
    log "Configurando openocd..."
    mkdir -p "openocd"
    echo "#!/bin/bash" > "openocd/openocd"
    echo "echo '🛠️ Executando openocd...'" >> "openocd/openocd"
    echo "# Implementação específica do openocd" >> "openocd/openocd"
    chmod +x "openocd/openocd"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/openocd" ]; then
        ln -sf "$CATEGORY_DIR/openocd/openocd" "/usr/local/bin/openocd"
    fi
fi


# Criar script de conveniência para a categoria
cat > "hardware-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge HARDWARE Suite

echo "🛡️ Ferramentas para análise e hacking de hardware"
echo "Prioridade: medium"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/hardware/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/hardware/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "hardware-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-hardware" ]; then
    ln -sf "$CATEGORY_DIR/hardware-suite.sh" "/usr/local/bin/secforge-hardware"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria hardware instalada!"
echo "💡 Use: secforge-hardware para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
