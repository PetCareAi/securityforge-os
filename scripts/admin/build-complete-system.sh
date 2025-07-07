#!/bin/bash
# SecurityForge Linux - Build Completo Avançado v3.1.0
# Script ultra-robusto para criação de sistema completo

set -euo pipefail

# ============================================================================
# CONFIGURAÇÕES E VARIÁVEIS GLOBAIS
# ============================================================================

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# Detectar usuário atual e home directory
CURRENT_USER=$(whoami)
if [ "$CURRENT_USER" = "root" ]; then
    REAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo "root")}
    if [ "$REAL_USER" = "root" ]; then
        USER_HOME="/root"
    else
        USER_HOME="/home/$REAL_USER"
    fi
else
    REAL_USER="$CURRENT_USER"
    USER_HOME="$HOME"
fi

# Configurações do sistema
readonly WORK_DIR="$USER_HOME/securityforge-os"
readonly ROOTFS_DIR="$WORK_DIR/rootfs"
readonly ISO_DIR="$WORK_DIR/iso"
readonly CHROOT_DIR="$WORK_DIR/chroot"
readonly SCRIPTS_DIR="$WORK_DIR/scripts"
readonly LOG_FILE="$WORK_DIR/build.log"

# Configurações do sistema operacional
readonly DISTRO_CODENAME="jammy"
readonly DISTRO_VERSION="22.04"
readonly SYSTEM_USER="secforge"
readonly SYSTEM_PASSWORD="live"
readonly HOSTNAME="securityforge"

# URLs e repositórios - com fallbacks
readonly UBUNTU_MIRROR="http://archive.ubuntu.com/ubuntu"
readonly UBUNTU_MIRROR_BR="http://br.archive.ubuntu.com/ubuntu"
readonly UBUNTU_MIRROR_FALLBACK="http://old-releases.ubuntu.com/ubuntu"
readonly SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

# ============================================================================
# FUNÇÕES DE LOGGING E UTILITÁRIOS
# ============================================================================

create_base_directories() {
    echo "Criando diretórios base..."
    mkdir -p "$WORK_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    if [ "$CURRENT_USER" = "root" ] && [ "$REAL_USER" != "root" ]; then
        chown -R "$REAL_USER:$REAL_USER" "$WORK_DIR" 2>/dev/null || true
    fi
}

log() { 
    local msg="[$(date +'%H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || echo "$msg"
}

success() { 
    local msg="✅ $1"
    echo -e "${GREEN}$msg${NC}"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || echo "$msg"
}

warning() { 
    local msg="⚠️  $1"
    echo -e "${YELLOW}$msg${NC}"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || echo "$msg"
}

error() { 
    local msg="❌ $1"
    echo -e "${RED}$msg${NC}"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || echo "$msg"
}

header() { 
    echo -e "${PURPLE}$1${NC}"
    echo "$1" >> "$LOG_FILE" 2>/dev/null || echo "$1"
}

info() { 
    echo -e "${CYAN}ℹ️  $1${NC}"
    echo "$1" >> "$LOG_FILE" 2>/dev/null || echo "$1"
}

section() { 
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}"
    {
        echo "════════════════════════════════════════════════════════════════════════════════"
        echo "$1"
        echo "════════════════════════════════════════════════════════════════════════════════"
    } >> "$LOG_FILE" 2>/dev/null || true
}

# ============================================================================
# FUNÇÕES DE DIAGNÓSTICO E CORREÇÃO DE REDE
# ============================================================================

diagnose_network() {
    section "DIAGNÓSTICO COMPLETO DE REDE"
    
    log "Verificando configuração de rede..."
    
    # Verificar interfaces de rede
    log "Interfaces de rede:"
    ip addr show | grep -E "(inet|UP|DOWN)" | head -10
    
    # Verificar rota padrão
    log "Rota padrão:"
    ip route show default || echo "Nenhuma rota padrão encontrada"
    
    # Verificar resolv.conf
    log "Configuração DNS atual:"
    if [ -f "/etc/resolv.conf" ]; then
        cat /etc/resolv.conf | head -10
    else
        echo "Arquivo /etc/resolv.conf não encontrado"
    fi
    
    # Verificar conectividade básica
    log "Testando conectividade básica..."
    
    # Teste de ping para gateway
    local gateway=$(ip route show default | awk '/default/ { print $3 }' | head -1)
    if [ -n "$gateway" ]; then
        if ping -c 2 -W 3 "$gateway" >/dev/null 2>&1; then
            success "Conectividade com gateway ($gateway): OK"
        else
            warning "Sem conectividade com gateway ($gateway)"
        fi
    else
        warning "Gateway não encontrado"
    fi
    
    # Teste de ping para DNS públicos
    local dns_servers=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    for dns in "${dns_servers[@]}"; do
        if ping -c 2 -W 3 "$dns" >/dev/null 2>&1; then
            success "Conectividade IP com $dns: OK"
            return 0
        else
            warning "Sem conectividade IP com $dns"
        fi
    done
    
    return 1
}

fix_dns() {
    section "CORRIGINDO CONFIGURAÇÃO DE DNS"
    
    log "Fazendo backup do resolv.conf atual..."
    if [ -f "/etc/resolv.conf" ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%s)
    fi
    
    log "Configurando DNS robusto..."
    cat > /etc/resolv.conf << 'EOF'
# SecurityForge DNS Configuration - Fixed
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 208.67.222.222
nameserver 208.67.220.220
options timeout:5
options attempts:3
options rotate
options edns0
EOF
    
    # Tentar reiniciar serviços de rede
    log "Reiniciando serviços de rede..."
    
    # Flush DNS cache
    if command -v systemd-resolve >/dev/null 2>&1; then
        systemd-resolve --flush-caches 2>/dev/null || true
    fi
    
    # Reiniciar NetworkManager se disponível
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        systemctl restart NetworkManager 2>/dev/null || true
        sleep 3
    fi
    
    # Reiniciar networking se disponível
    if systemctl is-active networking >/dev/null 2>&1; then
        systemctl restart networking 2>/dev/null || true
        sleep 3
    fi
    
    success "DNS reconfigurado"
}

verify_network() {
    section "VERIFICANDO CONECTIVIDADE DE REDE"
    
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log "Tentativa $attempt de $max_attempts..."
        
        # Verificar conectividade IP básica
        log "Verificando conectividade IP..."
        local ip_ok=false
        local dns_servers=("8.8.8.8" "1.1.1.1" "208.67.222.222")
        
        for dns in "${dns_servers[@]}"; do
            if ping -c 2 -W 5 "$dns" >/dev/null 2>&1; then
                success "Conectividade IP OK ($dns)"
                ip_ok=true
                break
            fi
        done
        
        if [ "$ip_ok" = false ]; then
            warning "Sem conectividade IP básica"
            if [ $attempt -lt $max_attempts ]; then
                log "Tentando diagnosticar e corrigir..."
                diagnose_network
                fix_dns
                sleep 5
                ((attempt++))
                continue
            else
                return 1
            fi
        fi
        
        # Verificar resolução DNS
        log "Verificando resolução DNS..."
        local dns_targets=("archive.ubuntu.com" "google.com" "cloudflare.com")
        
        for target in "${dns_targets[@]}"; do
            if nslookup "$target" >/dev/null 2>&1; then
                success "DNS funcionando ($target)"
                return 0
            fi
        done
        
        warning "DNS não está funcionando"
        if [ $attempt -lt $max_attempts ]; then
            log "Tentando corrigir DNS..."
            fix_dns
            sleep 5
            ((attempt++))
        else
            return 1
        fi
    done
    
    return 1
}

setup_offline_mode() {
    section "CONFIGURANDO MODO OFFLINE"
    
    warning "Conectividade limitada detectada. Configurando modo offline..."
    
    # Tentar usar cache local do APT se disponível
    if [ -d "/var/cache/apt/archives" ] && [ "$(ls -A /var/cache/apt/archives/*.deb 2>/dev/null | wc -l)" -gt 0 ]; then
        log "Cache local de pacotes encontrado"
        success "Modo offline configurado com cache local"
        return 0
    fi
    
    # Verificar se há um mirror local
    local local_mirrors=("http://localhost/ubuntu" "http://127.0.0.1/ubuntu" "http://192.168.1.1/ubuntu")
    
    for mirror in "${local_mirrors[@]}"; do
        if curl -s --connect-timeout 5 "$mirror/ls-lR.gz" >/dev/null 2>&1; then
            log "Mirror local encontrado: $mirror"
            export UBUNTU_MIRROR="$mirror"
            success "Usando mirror local: $mirror"
            return 0
        fi
    done
    
    error "Nenhuma fonte offline disponível"
    return 1
}

# ============================================================================
# RESTO DAS FUNÇÕES (mantidas iguais)
# ============================================================================

ultra_cleanup() {
    log "Executando limpeza ultra-robusta..."
    
    if [ -d "$CHROOT_DIR" ]; then
        log "Terminando processos no chroot..."
        fuser -k "$CHROOT_DIR" 2>/dev/null || true
        fuser -9 -k "$CHROOT_DIR" 2>/dev/null || true
        sleep 3
        
        local mount_points=(
            "$CHROOT_DIR/run/snapd/ns/firefox.mnt"
            "$CHROOT_DIR/run/user"
            "$CHROOT_DIR/run/shm" 
            "$CHROOT_DIR/run/lock"
            "$CHROOT_DIR/run"
            "$CHROOT_DIR/sys/fs/cgroup"
            "$CHROOT_DIR/sys"
            "$CHROOT_DIR/proc"
            "$CHROOT_DIR/dev/pts"
            "$CHROOT_DIR/dev"
        )
        
        for mount_point in "${mount_points[@]}"; do
            if mountpoint -q "$mount_point" 2>/dev/null; then
                log "Desmontando: $mount_point"
                umount -l "$mount_point" 2>/dev/null || true
                umount -f "$mount_point" 2>/dev/null || true
            fi
        done
        
        sleep 2
        
        if ! rm -rf "$CHROOT_DIR" 2>/dev/null; then
            warning "Não foi possível remover $CHROOT_DIR, movendo para backup"
            mv "$CHROOT_DIR" "$CHROOT_DIR.backup.$(date +%s)" 2>/dev/null || true
        fi
    fi
    
    rm -rf "$ROOTFS_DIR" "$ISO_DIR" 2>/dev/null || true
    success "Limpeza concluída"
}

install_host_dependencies() {
    section "INSTALANDO DEPENDÊNCIAS DO HOST"
    
    log "Atualizando repositórios do host..."
    
    # Tentar várias vezes com diferentes configurações
    local success=false
    local attempts=3
    
    for ((i=1; i<=attempts; i++)); do
        log "Tentativa $i de $attempts para atualizar repositórios..."
        
        if apt update 2>/dev/null; then
            success=true
            break
        else
            warning "Falha na tentativa $i"
            if [ $i -lt $attempts ]; then
                log "Reconfigurando DNS e tentando novamente..."
                fix_dns
                sleep 5
            fi
        fi
    done
    
    if [ "$success" = false ]; then
        warning "Não foi possível atualizar repositórios online"
        log "Tentando usar cache local..."
        
        # Verificar se há pacotes essenciais já instalados
        if ! command -v debootstrap >/dev/null 2>&1; then
            error "debootstrap não está instalado e não há conectividade"
            error "Instale manualmente: apt install debootstrap"
            return 1
        fi
    fi
    
    log "Instalando dependências essenciais..."
    local packages=(
        "debootstrap"
        "squashfs-tools"
        "genisoimage"
        "syslinux-utils"
        "xorriso"
        "grub2-common"
        "grub-pc-bin" 
        "grub-efi-amd64-bin"
        "isolinux"
        "wget"
        "curl"
        "git"
        "build-essential"
        "rsync"
        "locales"
        "psmisc"
        "lsof"
        "ubuntu-keyring"
        "ca-certificates"
        "gnupg"
    )
    
    # Tentar instalar pacotes um por um se a instalação em lote falhar
    if ! apt install -y "${packages[@]}" 2>/dev/null; then
        warning "Instalação em lote falhou, tentando individualmente..."
        
        for pkg in "${packages[@]}"; do
            if ! dpkg -l | grep -q "^ii.*$pkg"; then
                if apt install -y "$pkg" 2>/dev/null; then
                    success "Instalado: $pkg"
                else
                    warning "Falha ao instalar: $pkg"
                fi
            else
                log "Já instalado: $pkg"
            fi
        done
    fi
    
    success "Dependências do host processadas"
}

run_debootstrap() {
    section "EXECUTANDO DEBOOTSTRAP"
    
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log "Tentativa $attempt de $max_attempts - Criando sistema base Ubuntu $DISTRO_VERSION..."
        
        if [ -d "$CHROOT_DIR" ]; then
            log "Removendo chroot anterior..."
            ultra_cleanup
        fi
        
        # Criar diretório chroot
        mkdir -p "$CHROOT_DIR"
        
        # Tentar diferentes mirrors
        local mirrors=("$UBUNTU_MIRROR" "$UBUNTU_MIRROR_BR" "$UBUNTU_MIRROR_FALLBACK")
        local debootstrap_success=false
        
        for mirror in "${mirrors[@]}"; do
            log "Tentando mirror: $mirror"
            
            if debootstrap \
                --arch=amd64 \
                --variant=minbase \
                --include=systemd-sysv,locales,language-pack-en,ubuntu-minimal,apt-utils,ca-certificates,gnupg \
                --verbose \
                --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
                "$DISTRO_CODENAME" \
                "$CHROOT_DIR" \
                "$mirror" 2>/dev/null; then
                
                log "Debootstrap bem-sucedido com mirror: $mirror"
                debootstrap_success=true
                break
            else
                warning "Falha com mirror: $mirror"
            fi
        done
        
        if [ "$debootstrap_success" = true ]; then
            log "Debootstrap concluído, verificando integridade..."
            
            # Aguardar um momento para garantir que tudo foi criado
            sleep 5
            
            # Criar diretórios que podem estar faltando
            log "Criando diretórios essenciais se necessário..."
            mkdir -p "$CHROOT_DIR"/{proc,sys,dev/pts,run,tmp,etc,var,usr,home,root,boot,opt,srv,media,mnt}
            
            # Verificar se o debootstrap realmente funcionou
            if [ -f "$CHROOT_DIR/bin/bash" ] && [ -f "$CHROOT_DIR/usr/bin/dpkg" ]; then
                success "Debootstrap executado com sucesso na tentativa $attempt"
                return 0
            else
                warning "Debootstrap incompleto na tentativa $attempt"
            fi
        else
            warning "Debootstrap falhou em todos os mirrors na tentativa $attempt"
        fi
        
        ((attempt++))
        if [ $attempt -le $max_attempts ]; then
            log "Aguardando 10 segundos antes da próxima tentativa..."
            sleep 10
        fi
    done
    
    error "Debootstrap falhou após $max_attempts tentativas"
    return 1
}

mount_chroot_systems() {
    log "Montando sistemas de arquivos para chroot..."
    
    # Verificar se o chroot existe e está correto
    if [ ! -d "$CHROOT_DIR" ]; then
        error "Diretório chroot não encontrado: $CHROOT_DIR"
        return 1
    fi
    
    # Criar diretórios essenciais se não existirem
    log "Criando diretórios essenciais..."
    mkdir -p "$CHROOT_DIR"/{proc,sys,dev/pts,run,tmp,etc,var,usr,home,root,boot}
    
    # Montar sistemas essenciais
    log "Montando sistemas de arquivos..."
    mount --bind /dev "$CHROOT_DIR/dev" 2>/dev/null || true
    mount --bind /dev/pts "$CHROOT_DIR/dev/pts" 2>/dev/null || true  
    mount --bind /proc "$CHROOT_DIR/proc" 2>/dev/null || true
    mount --bind /sys "$CHROOT_DIR/sys" 2>/dev/null || true
    mount --bind /run "$CHROOT_DIR/run" 2>/dev/null || true
    
    # Configurar resolv.conf no chroot
    log "Configurando resolv.conf no chroot..."
    cat > "$CHROOT_DIR/etc/resolv.conf" << 'EOF'
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
options timeout:5
options attempts:3
EOF
    
    success "Sistemas de arquivos montados"
}

chroot_exec() {
    local cmd="$1"
    local allow_fail="${2:-false}"
    
    log "Executando no chroot: $cmd"
    
    if [ ! -d "$CHROOT_DIR" ] || [ ! -f "$CHROOT_DIR/bin/bash" ]; then
        error "Chroot não está disponível"
        return 1
    fi
    
    if chroot "$CHROOT_DIR" /bin/bash -c "
        export DEBIAN_FRONTEND=noninteractive
        export DEBCONF_NONINTERACTIVE_SEEN=true
        export LC_ALL=C
        export LANGUAGE=C
        export LANG=C
        $cmd
    " 2>/dev/null; then
        return 0
    else
        if [ "$allow_fail" = "true" ]; then
            warning "Comando falhou (permitido): $cmd"
            return 1
        else
            error "Comando crítico falhou: $cmd"
            return 1
        fi
    fi
}

create_minimal_system() {
    section "CRIANDO SISTEMA MÍNIMO"
    
    log "Configurando sistema base mínimo..."
    
    # Configurar repositórios
    cat > "$CHROOT_DIR/etc/apt/sources.list" << EOF
deb $UBUNTU_MIRROR $DISTRO_CODENAME main restricted universe multiverse
deb $UBUNTU_MIRROR $DISTRO_CODENAME-updates main restricted universe multiverse
deb $SECURITY_MIRROR $DISTRO_CODENAME-security main restricted universe multiverse
EOF
    
    # Configurar locale
    echo "en_US.UTF-8 UTF-8" > "$CHROOT_DIR/etc/locale.gen"
    chroot_exec "locale-gen" true
    
    # Configurar timezone
    chroot_exec "ln -sf /usr/share/zoneinfo/UTC /etc/localtime" true
    
    # Criar usuário
    chroot_exec "useradd -m -s /bin/bash $SYSTEM_USER" true
    chroot_exec "echo '$SYSTEM_USER:$SYSTEM_PASSWORD' | chpasswd" true
    chroot_exec "echo 'root:$SYSTEM_PASSWORD' | chpasswd" true
    chroot_exec "usermod -aG sudo $SYSTEM_USER" true
    
    # Configurar sudo
    echo "$SYSTEM_USER ALL=(ALL) NOPASSWD: ALL" > "$CHROOT_DIR/etc/sudoers.d/securityforge"
    chmod 440 "$CHROOT_DIR/etc/sudoers.d/securityforge"
    
    # Criar estrutura SecurityForge
    mkdir -p "$CHROOT_DIR/opt/securityforge"/{tools,scripts,wordlists,workspace,reports}
    
    success "Sistema mínimo criado"
}

finalize_build() {
    section "FINALIZANDO BUILD"
    
    log "Desmontando sistemas de arquivos..."
    local mount_points=(
        "$CHROOT_DIR/run"
        "$CHROOT_DIR/sys"
        "$CHROOT_DIR/proc"
        "$CHROOT_DIR/dev/pts"
        "$CHROOT_DIR/dev"
    )
    
    for mount_point in "${mount_points[@]}"; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            log "Desmontando: $mount_point"
            umount -l "$mount_point" 2>/dev/null || true
        fi
    done
    
    log "Copiando sistema para rootfs..."
    mkdir -p "$ROOTFS_DIR"
    rsync -av --progress "$CHROOT_DIR/" "$ROOTFS_DIR/" \
        --exclude='/proc/*' \
        --exclude='/sys/*' \
        --exclude='/dev/*' \
        --exclude='/run/*' \
        --exclude='/tmp/*' \
        --exclude='/var/tmp/*'
    
    mkdir -p "$ROOTFS_DIR"/{proc,sys,dev,run,tmp,var/tmp}
    
    cat > "$ROOTFS_DIR/opt/securityforge/BUILD_INFO.txt" << EOF
SecurityForge Linux 3.1.0 - CyberNinja
Build Date: $(date)
Build Host: $(hostname)
Build User: $(whoami)
Ubuntu Base: $DISTRO_VERSION ($DISTRO_CODENAME)
Size: $(du -sh "$ROOTFS_DIR" | cut -f1)
EOF
    
    success "Build finalizado"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    if [[ $EUID -ne 0 ]]; then
       error "Este script deve ser executado como root"
       exit 1
    fi
    
    create_base_directories
    
    header "╔═══════════════════════════════════════════════════════════════════════════════╗"
    header "║                🛡️  SECURITYFORGE LINUX BUILD AVANÇADO v3.1.0               ║"
    header "║                    Sistema Operacional Completo - CyberNinja                ║"
    header "╚═══════════════════════════════════════════════════════════════════════════════╝"
    
    echo "SecurityForge Linux Build Started at $(date)" >> "$LOG_FILE"
    echo "User: $REAL_USER (running as $CURRENT_USER)" >> "$LOG_FILE"
    echo "Work Directory: $WORK_DIR" >> "$LOG_FILE"
    
    # Diagnosticar e tentar corrigir rede
    if ! verify_network; then
        warning "Problemas de conectividade detectados"
        
        log "Tentando diagnóstico e correção avançada..."
        diagnose_network
        
        if ! verify_network; then
            warning "Não foi possível estabelecer conectividade completa"
            
            if ! setup_offline_mode; then
                error "Nem conectividade nem modo offline disponível"
                echo ""
                echo "SOLUÇÕES POSSÍVEIS:"
                echo "1. Verificar conexão de internet"
                echo "2. Configurar DNS manualmente"
                echo "3. Usar hotspot mobile"
                echo "4. Executar em máquina com internet"
                exit 1
            fi
        fi
    fi
    
    install_host_dependencies
    ultra_cleanup
    mkdir -p "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"
    
    if ! run_debootstrap; then
        error "Falha crítica no debootstrap. Tentando sistema mínimo..."
        
        # Tentar criar um sistema muito básico
        mkdir -p "$CHROOT_DIR"/{bin,sbin,etc,var,usr,home,root,tmp,proc,sys,dev}
        
        if ! mount_chroot_systems; then
            error "Falha ao montar sistemas. Abortando."
            exit 1
        fi
        
        create_minimal_system
    else
        if ! mount_chroot_systems; then
            error "Falha ao montar sistemas de arquivos. Abortando."
            exit 1
        fi
        
        create_minimal_system
    fi
    
    finalize_build
    
    header "🎯 BUILD CONCLUÍDO!"
    success "Sistema SecurityForge Linux criado!"
    info "Localização: $ROOTFS_DIR"
    
    if [ -d "$ROOTFS_DIR" ]; then
        info "Tamanho: $(du -sh "$ROOTFS_DIR" | cut -f1)"
    fi
    
    info "Log completo: $LOG_FILE"
    
    echo ""
    header "📋 SISTEMA CRIADO:"
    echo "✅ Sistema Ubuntu base"
    echo "✅ Usuário '$SYSTEM_USER' (senha: $SYSTEM_PASSWORD)"
    echo "✅ Estrutura SecurityForge básica"
    echo ""
    info "Próximo passo: sudo ./create-iso-fixed.sh"
    
    header "═══════════════════════════════════════════════════════════════════════════════"
}

main "$@"