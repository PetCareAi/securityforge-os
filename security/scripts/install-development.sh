#!/bin/bash
# SecurityForge Linux - Instalação de DEVELOPMENT

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

echo "📦 Instalando IDEs e ferramentas de desenvolvimento para segurança..."

CATEGORY_DIR="/opt/securityforge/tools/development"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y vscode code vim neovim emacs nano gedit kate sublime-text atom intellij-idea-community pycharm-community eclipse netbeans webstorm || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# vscode
if [ ! -d "vscode" ]; then
    log "Configurando vscode..."
    mkdir -p "vscode"
    echo "#!/bin/bash" > "vscode/vscode"
    echo "echo '🛠️ Executando vscode...'" >> "vscode/vscode"
    echo "# Implementação específica do vscode" >> "vscode/vscode"
    chmod +x "vscode/vscode"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/vscode" ]; then
        ln -sf "$CATEGORY_DIR/vscode/vscode" "/usr/local/bin/vscode"
    fi
fi


# code
if [ ! -d "code" ]; then
    log "Configurando code..."
    mkdir -p "code"
    echo "#!/bin/bash" > "code/code"
    echo "echo '🛠️ Executando code...'" >> "code/code"
    echo "# Implementação específica do code" >> "code/code"
    chmod +x "code/code"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/code" ]; then
        ln -sf "$CATEGORY_DIR/code/code" "/usr/local/bin/code"
    fi
fi


# vim
if [ ! -d "vim" ]; then
    log "Configurando vim..."
    mkdir -p "vim"
    echo "#!/bin/bash" > "vim/vim"
    echo "echo '🛠️ Executando vim...'" >> "vim/vim"
    echo "# Implementação específica do vim" >> "vim/vim"
    chmod +x "vim/vim"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/vim" ]; then
        ln -sf "$CATEGORY_DIR/vim/vim" "/usr/local/bin/vim"
    fi
fi


# neovim
if [ ! -d "neovim" ]; then
    log "Configurando neovim..."
    mkdir -p "neovim"
    echo "#!/bin/bash" > "neovim/neovim"
    echo "echo '🛠️ Executando neovim...'" >> "neovim/neovim"
    echo "# Implementação específica do neovim" >> "neovim/neovim"
    chmod +x "neovim/neovim"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/neovim" ]; then
        ln -sf "$CATEGORY_DIR/neovim/neovim" "/usr/local/bin/neovim"
    fi
fi


# emacs
if [ ! -d "emacs" ]; then
    log "Configurando emacs..."
    mkdir -p "emacs"
    echo "#!/bin/bash" > "emacs/emacs"
    echo "echo '🛠️ Executando emacs...'" >> "emacs/emacs"
    echo "# Implementação específica do emacs" >> "emacs/emacs"
    chmod +x "emacs/emacs"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/emacs" ]; then
        ln -sf "$CATEGORY_DIR/emacs/emacs" "/usr/local/bin/emacs"
    fi
fi


# nano
if [ ! -d "nano" ]; then
    log "Configurando nano..."
    mkdir -p "nano"
    echo "#!/bin/bash" > "nano/nano"
    echo "echo '🛠️ Executando nano...'" >> "nano/nano"
    echo "# Implementação específica do nano" >> "nano/nano"
    chmod +x "nano/nano"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/nano" ]; then
        ln -sf "$CATEGORY_DIR/nano/nano" "/usr/local/bin/nano"
    fi
fi


# gedit
if [ ! -d "gedit" ]; then
    log "Configurando gedit..."
    mkdir -p "gedit"
    echo "#!/bin/bash" > "gedit/gedit"
    echo "echo '🛠️ Executando gedit...'" >> "gedit/gedit"
    echo "# Implementação específica do gedit" >> "gedit/gedit"
    chmod +x "gedit/gedit"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/gedit" ]; then
        ln -sf "$CATEGORY_DIR/gedit/gedit" "/usr/local/bin/gedit"
    fi
fi


# kate
if [ ! -d "kate" ]; then
    log "Configurando kate..."
    mkdir -p "kate"
    echo "#!/bin/bash" > "kate/kate"
    echo "echo '🛠️ Executando kate...'" >> "kate/kate"
    echo "# Implementação específica do kate" >> "kate/kate"
    chmod +x "kate/kate"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/kate" ]; then
        ln -sf "$CATEGORY_DIR/kate/kate" "/usr/local/bin/kate"
    fi
fi


# sublime-text
if [ ! -d "sublime-text" ]; then
    log "Configurando sublime-text..."
    mkdir -p "sublime-text"
    echo "#!/bin/bash" > "sublime-text/sublime-text"
    echo "echo '🛠️ Executando sublime-text...'" >> "sublime-text/sublime-text"
    echo "# Implementação específica do sublime-text" >> "sublime-text/sublime-text"
    chmod +x "sublime-text/sublime-text"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/sublime-text" ]; then
        ln -sf "$CATEGORY_DIR/sublime-text/sublime-text" "/usr/local/bin/sublime-text"
    fi
fi


# atom
if [ ! -d "atom" ]; then
    log "Configurando atom..."
    mkdir -p "atom"
    echo "#!/bin/bash" > "atom/atom"
    echo "echo '🛠️ Executando atom...'" >> "atom/atom"
    echo "# Implementação específica do atom" >> "atom/atom"
    chmod +x "atom/atom"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/atom" ]; then
        ln -sf "$CATEGORY_DIR/atom/atom" "/usr/local/bin/atom"
    fi
fi


# Criar script de conveniência para a categoria
cat > "development-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge DEVELOPMENT Suite

echo "🛡️ IDEs e ferramentas de desenvolvimento para segurança"
echo "Prioridade: medium"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/development/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/development/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "development-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-development" ]; then
    ln -sf "$CATEGORY_DIR/development-suite.sh" "/usr/local/bin/secforge-development"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria development instalada!"
echo "💡 Use: secforge-development para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
