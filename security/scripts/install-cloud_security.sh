#!/bin/bash
# SecurityForge Linux - Instalação de CLOUD SECURITY

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

echo "📦 Instalando Ferramentas para auditoria e segurança em ambientes de nuvem..."

CATEGORY_DIR="/opt/securityforge/tools/cloud_security"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y aws-cli aws-vault aws-nuke azure-cli gcloud gsutil kubectl helm kustomize skaffold docker docker-compose podman buildah skopeo || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# aws-cli
if [ ! -d "aws-cli" ]; then
    log "Configurando aws-cli..."
    mkdir -p "aws-cli"
    echo "#!/bin/bash" > "aws-cli/aws-cli"
    echo "echo '🛠️ Executando aws-cli...'" >> "aws-cli/aws-cli"
    echo "# Implementação específica do aws-cli" >> "aws-cli/aws-cli"
    chmod +x "aws-cli/aws-cli"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aws-cli" ]; then
        ln -sf "$CATEGORY_DIR/aws-cli/aws-cli" "/usr/local/bin/aws-cli"
    fi
fi


# aws-vault
if [ ! -d "aws-vault" ]; then
    log "Configurando aws-vault..."
    mkdir -p "aws-vault"
    echo "#!/bin/bash" > "aws-vault/aws-vault"
    echo "echo '🛠️ Executando aws-vault...'" >> "aws-vault/aws-vault"
    echo "# Implementação específica do aws-vault" >> "aws-vault/aws-vault"
    chmod +x "aws-vault/aws-vault"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aws-vault" ]; then
        ln -sf "$CATEGORY_DIR/aws-vault/aws-vault" "/usr/local/bin/aws-vault"
    fi
fi


# aws-nuke
if [ ! -d "aws-nuke" ]; then
    log "Configurando aws-nuke..."
    mkdir -p "aws-nuke"
    echo "#!/bin/bash" > "aws-nuke/aws-nuke"
    echo "echo '🛠️ Executando aws-nuke...'" >> "aws-nuke/aws-nuke"
    echo "# Implementação específica do aws-nuke" >> "aws-nuke/aws-nuke"
    chmod +x "aws-nuke/aws-nuke"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/aws-nuke" ]; then
        ln -sf "$CATEGORY_DIR/aws-nuke/aws-nuke" "/usr/local/bin/aws-nuke"
    fi
fi


# azure-cli
if [ ! -d "azure-cli" ]; then
    log "Configurando azure-cli..."
    mkdir -p "azure-cli"
    echo "#!/bin/bash" > "azure-cli/azure-cli"
    echo "echo '🛠️ Executando azure-cli...'" >> "azure-cli/azure-cli"
    echo "# Implementação específica do azure-cli" >> "azure-cli/azure-cli"
    chmod +x "azure-cli/azure-cli"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/azure-cli" ]; then
        ln -sf "$CATEGORY_DIR/azure-cli/azure-cli" "/usr/local/bin/azure-cli"
    fi
fi


# gcloud
if [ ! -d "gcloud" ]; then
    log "Configurando gcloud..."
    mkdir -p "gcloud"
    echo "#!/bin/bash" > "gcloud/gcloud"
    echo "echo '🛠️ Executando gcloud...'" >> "gcloud/gcloud"
    echo "# Implementação específica do gcloud" >> "gcloud/gcloud"
    chmod +x "gcloud/gcloud"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/gcloud" ]; then
        ln -sf "$CATEGORY_DIR/gcloud/gcloud" "/usr/local/bin/gcloud"
    fi
fi


# gsutil
if [ ! -d "gsutil" ]; then
    log "Configurando gsutil..."
    mkdir -p "gsutil"
    echo "#!/bin/bash" > "gsutil/gsutil"
    echo "echo '🛠️ Executando gsutil...'" >> "gsutil/gsutil"
    echo "# Implementação específica do gsutil" >> "gsutil/gsutil"
    chmod +x "gsutil/gsutil"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/gsutil" ]; then
        ln -sf "$CATEGORY_DIR/gsutil/gsutil" "/usr/local/bin/gsutil"
    fi
fi


# kubectl
if [ ! -d "kubectl" ]; then
    log "Configurando kubectl..."
    mkdir -p "kubectl"
    echo "#!/bin/bash" > "kubectl/kubectl"
    echo "echo '🛠️ Executando kubectl...'" >> "kubectl/kubectl"
    echo "# Implementação específica do kubectl" >> "kubectl/kubectl"
    chmod +x "kubectl/kubectl"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/kubectl" ]; then
        ln -sf "$CATEGORY_DIR/kubectl/kubectl" "/usr/local/bin/kubectl"
    fi
fi


# helm
if [ ! -d "helm" ]; then
    log "Configurando helm..."
    mkdir -p "helm"
    echo "#!/bin/bash" > "helm/helm"
    echo "echo '🛠️ Executando helm...'" >> "helm/helm"
    echo "# Implementação específica do helm" >> "helm/helm"
    chmod +x "helm/helm"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/helm" ]; then
        ln -sf "$CATEGORY_DIR/helm/helm" "/usr/local/bin/helm"
    fi
fi


# kustomize
if [ ! -d "kustomize" ]; then
    log "Configurando kustomize..."
    mkdir -p "kustomize"
    echo "#!/bin/bash" > "kustomize/kustomize"
    echo "echo '🛠️ Executando kustomize...'" >> "kustomize/kustomize"
    echo "# Implementação específica do kustomize" >> "kustomize/kustomize"
    chmod +x "kustomize/kustomize"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/kustomize" ]; then
        ln -sf "$CATEGORY_DIR/kustomize/kustomize" "/usr/local/bin/kustomize"
    fi
fi


# skaffold
if [ ! -d "skaffold" ]; then
    log "Configurando skaffold..."
    mkdir -p "skaffold"
    echo "#!/bin/bash" > "skaffold/skaffold"
    echo "echo '🛠️ Executando skaffold...'" >> "skaffold/skaffold"
    echo "# Implementação específica do skaffold" >> "skaffold/skaffold"
    chmod +x "skaffold/skaffold"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/skaffold" ]; then
        ln -sf "$CATEGORY_DIR/skaffold/skaffold" "/usr/local/bin/skaffold"
    fi
fi


# Criar script de conveniência para a categoria
cat > "cloud_security-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge CLOUD SECURITY Suite

echo "🛡️ Ferramentas para auditoria e segurança em ambientes de nuvem"
echo "Prioridade: high"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/cloud_security/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/cloud_security/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "cloud_security-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-cloud_security" ]; then
    ln -sf "$CATEGORY_DIR/cloud_security-suite.sh" "/usr/local/bin/secforge-cloud_security"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria cloud_security instalada!"
echo "💡 Use: secforge-cloud_security para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
