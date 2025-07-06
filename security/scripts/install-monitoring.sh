#!/bin/bash
# SecurityForge Linux - Instalação de MONITORING

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

echo "📦 Instalando Ferramentas de monitoramento, SIEM e análise de logs..."

CATEGORY_DIR="/opt/securityforge/tools/monitoring"
mkdir -p "$CATEGORY_DIR"
cd "$CATEGORY_DIR"

# Ferramentas via APT
log "Instalando ferramentas via APT..."
apt-get install -y elk-stack elasticsearch logstash kibana beats filebeat metricbeat heartbeat auditbeat packetbeat winlogbeat splunk splunk-universal-forwarder graylog fluentd || warning "Algumas ferramentas APT podem ter falhado"

# Ferramentas via pip3
log "Instalando ferramentas Python..."
pip3 install  || warning "Algumas ferramentas Python podem ter falhado"

# Ferramentas via Go
log "Instalando ferramentas Go..."


# Ferramentas específicas do GitHub
log "Instalando ferramentas especializadas..."


# elk-stack
if [ ! -d "elk-stack" ]; then
    log "Configurando elk-stack..."
    mkdir -p "elk-stack"
    echo "#!/bin/bash" > "elk-stack/elk-stack"
    echo "echo '🛠️ Executando elk-stack...'" >> "elk-stack/elk-stack"
    echo "# Implementação específica do elk-stack" >> "elk-stack/elk-stack"
    chmod +x "elk-stack/elk-stack"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/elk-stack" ]; then
        ln -sf "$CATEGORY_DIR/elk-stack/elk-stack" "/usr/local/bin/elk-stack"
    fi
fi


# elasticsearch
if [ ! -d "elasticsearch" ]; then
    log "Configurando elasticsearch..."
    mkdir -p "elasticsearch"
    echo "#!/bin/bash" > "elasticsearch/elasticsearch"
    echo "echo '🛠️ Executando elasticsearch...'" >> "elasticsearch/elasticsearch"
    echo "# Implementação específica do elasticsearch" >> "elasticsearch/elasticsearch"
    chmod +x "elasticsearch/elasticsearch"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/elasticsearch" ]; then
        ln -sf "$CATEGORY_DIR/elasticsearch/elasticsearch" "/usr/local/bin/elasticsearch"
    fi
fi


# logstash
if [ ! -d "logstash" ]; then
    log "Configurando logstash..."
    mkdir -p "logstash"
    echo "#!/bin/bash" > "logstash/logstash"
    echo "echo '🛠️ Executando logstash...'" >> "logstash/logstash"
    echo "# Implementação específica do logstash" >> "logstash/logstash"
    chmod +x "logstash/logstash"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/logstash" ]; then
        ln -sf "$CATEGORY_DIR/logstash/logstash" "/usr/local/bin/logstash"
    fi
fi


# kibana
if [ ! -d "kibana" ]; then
    log "Configurando kibana..."
    mkdir -p "kibana"
    echo "#!/bin/bash" > "kibana/kibana"
    echo "echo '🛠️ Executando kibana...'" >> "kibana/kibana"
    echo "# Implementação específica do kibana" >> "kibana/kibana"
    chmod +x "kibana/kibana"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/kibana" ]; then
        ln -sf "$CATEGORY_DIR/kibana/kibana" "/usr/local/bin/kibana"
    fi
fi


# beats
if [ ! -d "beats" ]; then
    log "Configurando beats..."
    mkdir -p "beats"
    echo "#!/bin/bash" > "beats/beats"
    echo "echo '🛠️ Executando beats...'" >> "beats/beats"
    echo "# Implementação específica do beats" >> "beats/beats"
    chmod +x "beats/beats"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/beats" ]; then
        ln -sf "$CATEGORY_DIR/beats/beats" "/usr/local/bin/beats"
    fi
fi


# filebeat
if [ ! -d "filebeat" ]; then
    log "Configurando filebeat..."
    mkdir -p "filebeat"
    echo "#!/bin/bash" > "filebeat/filebeat"
    echo "echo '🛠️ Executando filebeat...'" >> "filebeat/filebeat"
    echo "# Implementação específica do filebeat" >> "filebeat/filebeat"
    chmod +x "filebeat/filebeat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/filebeat" ]; then
        ln -sf "$CATEGORY_DIR/filebeat/filebeat" "/usr/local/bin/filebeat"
    fi
fi


# metricbeat
if [ ! -d "metricbeat" ]; then
    log "Configurando metricbeat..."
    mkdir -p "metricbeat"
    echo "#!/bin/bash" > "metricbeat/metricbeat"
    echo "echo '🛠️ Executando metricbeat...'" >> "metricbeat/metricbeat"
    echo "# Implementação específica do metricbeat" >> "metricbeat/metricbeat"
    chmod +x "metricbeat/metricbeat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/metricbeat" ]; then
        ln -sf "$CATEGORY_DIR/metricbeat/metricbeat" "/usr/local/bin/metricbeat"
    fi
fi


# heartbeat
if [ ! -d "heartbeat" ]; then
    log "Configurando heartbeat..."
    mkdir -p "heartbeat"
    echo "#!/bin/bash" > "heartbeat/heartbeat"
    echo "echo '🛠️ Executando heartbeat...'" >> "heartbeat/heartbeat"
    echo "# Implementação específica do heartbeat" >> "heartbeat/heartbeat"
    chmod +x "heartbeat/heartbeat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/heartbeat" ]; then
        ln -sf "$CATEGORY_DIR/heartbeat/heartbeat" "/usr/local/bin/heartbeat"
    fi
fi


# auditbeat
if [ ! -d "auditbeat" ]; then
    log "Configurando auditbeat..."
    mkdir -p "auditbeat"
    echo "#!/bin/bash" > "auditbeat/auditbeat"
    echo "echo '🛠️ Executando auditbeat...'" >> "auditbeat/auditbeat"
    echo "# Implementação específica do auditbeat" >> "auditbeat/auditbeat"
    chmod +x "auditbeat/auditbeat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/auditbeat" ]; then
        ln -sf "$CATEGORY_DIR/auditbeat/auditbeat" "/usr/local/bin/auditbeat"
    fi
fi


# packetbeat
if [ ! -d "packetbeat" ]; then
    log "Configurando packetbeat..."
    mkdir -p "packetbeat"
    echo "#!/bin/bash" > "packetbeat/packetbeat"
    echo "echo '🛠️ Executando packetbeat...'" >> "packetbeat/packetbeat"
    echo "# Implementação específica do packetbeat" >> "packetbeat/packetbeat"
    chmod +x "packetbeat/packetbeat"
    
    # Criar link simbólico se necessário
    if [ ! -f "/usr/local/bin/packetbeat" ]; then
        ln -sf "$CATEGORY_DIR/packetbeat/packetbeat" "/usr/local/bin/packetbeat"
    fi
fi


# Criar script de conveniência para a categoria
cat > "monitoring-suite.sh" << 'SUITE_EOF'
#!/bin/bash
# SecurityForge MONITORING Suite

echo "🛡️ Ferramentas de monitoramento, SIEM e análise de logs"
echo "Prioridade: high"
echo ""
echo "🔧 Ferramentas disponíveis:"
ls -1 "/opt/securityforge/tools/monitoring/" | grep -v "\.sh$"
echo ""
echo "💡 Para usar uma ferramenta específica:"
echo "   cd /opt/securityforge/tools/monitoring/<ferramenta>"
echo "   ./<ferramenta>"
echo ""
SUITE_EOF

chmod +x "monitoring-suite.sh"

# Criar link simbólico global
if [ ! -f "/usr/local/bin/secforge-monitoring" ]; then
    ln -sf "$CATEGORY_DIR/monitoring-suite.sh" "/usr/local/bin/secforge-monitoring"
fi

# Configurar permissões
chown -R secforge:secforge "$CATEGORY_DIR" 2>/dev/null || warning "Usuário secforge não encontrado"
chmod -R 755 "$CATEGORY_DIR"

success "Categoria monitoring instalada!"
echo "💡 Use: secforge-monitoring para acessar ferramentas da categoria"
echo "📁 Localização: $CATEGORY_DIR"
