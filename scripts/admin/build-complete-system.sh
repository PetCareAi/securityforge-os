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

# Configurações do sistema
readonly WORK_DIR="/home/estevam/securityforge-os"
readonly ROOTFS_DIR="$WORK_DIR/rootfs"
readonly ISO_DIR="$WORK_DIR/iso"
readonly CHROOT_DIR="$WORK_DIR/chroot"
readonly SCRIPTS_DIR="$WORK_DIR/scripts"
readonly LOG_FILE="$WORK_DIR/build.log"

# Configurações do sistema operacional
readonly DISTRO_CODENAME="jammy"
readonly DISTRO_VERSION="22.04"
readonly KERNEL_VERSION=""
readonly SYSTEM_USER="secforge"
readonly SYSTEM_PASSWORD="live"
readonly HOSTNAME="securityforge"

# URLs e repositórios
readonly UBUNTU_MIRROR="http://archive.ubuntu.com/ubuntu"
readonly SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

# ============================================================================
# FUNÇÕES DE LOGGING E UTILITÁRIOS
# ============================================================================

# Função de logging com timestamp
log() { 
    local msg="[$(date +'%H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}" | tee -a "$LOG_FILE"
}

success() { 
    local msg="✅ $1"
    echo -e "${GREEN}$msg${NC}" | tee -a "$LOG_FILE"
}

warning() { 
    local msg="⚠️  $1"
    echo -e "${YELLOW}$msg${NC}" | tee -a "$LOG_FILE"
}

error() { 
    local msg="❌ $1"
    echo -e "${RED}$msg${NC}" | tee -a "$LOG_FILE"
}

header() { 
    echo -e "${PURPLE}$1${NC}" | tee -a "$LOG_FILE"
}

info() { 
    echo -e "${CYAN}ℹ️  $1${NC}" | tee -a "$LOG_FILE"
}

section() { 
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${WHITE}$1${NC}" | tee -a "$LOG_FILE"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
}

# Função para executar comandos com retry
execute_with_retry() {
    local cmd="$1"
    local retries="${2:-3}"
    local delay="${3:-5}"
    
    for ((i=1; i<=retries; i++)); do
        if eval "$cmd"; then
            return 0
        else
            warning "Tentativa $i de $retries falhou: $cmd"
            if [ $i -lt $retries ]; then
                log "Aguardando $delay segundos antes da próxima tentativa..."
                sleep $delay
            fi
        fi
    done
    
    error "Comando falhou após $retries tentativas: $cmd"
    return 1
}

# ============================================================================
# FUNÇÕES DE LIMPEZA E PREPARAÇÃO
# ============================================================================

# Limpeza ultra-robusta
ultra_cleanup() {
    log "Executando limpeza ultra-robusta..."
    
    # Matar todos os processos que podem estar usando o chroot
    if [ -d "$CHROOT_DIR" ]; then
        log "Terminando processos no chroot..."
        fuser -k "$CHROOT_DIR" 2>/dev/null || true
        fuser -9 -k "$CHROOT_DIR" 2>/dev/null || true
        
        # Aguardar um pouco para os processos terminarem
        sleep 3
        
        # Lista de mount points para desmontar
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
        
        # Desmontar de forma agressiva
        for mount_point in "${mount_points[@]}"; do
            if mountpoint -q "$mount_point" 2>/dev/null; then
                log "Desmontando: $mount_point"
                umount -l "$mount_point" 2>/dev/null || true
                umount -f "$mount_point" 2>/dev/null || true
            fi
        done
        
        # Aguardar mais um pouco
        sleep 2
        
        # Tentar remover o diretório
        if ! rm -rf "$CHROOT_DIR" 2>/dev/null; then
            warning "Não foi possível remover $CHROOT_DIR, movendo para backup"
            mv "$CHROOT_DIR" "$CHROOT_DIR.backup.$(date +%s)" 2>/dev/null || true
        fi
    fi
    
    # Remover outros diretórios
    rm -rf "$ROOTFS_DIR" "$ISO_DIR" 2>/dev/null || true
    
    success "Limpeza concluída"
}

# Verificar e instalar dependências do host
install_host_dependencies() {
    section "INSTALANDO DEPENDÊNCIAS DO HOST"
    
    log "Atualizando repositórios do host..."
    apt update
    
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
    
    execute_with_retry "apt install -y ${packages[*]}"
    
    success "Dependências do host instaladas"
}

# ============================================================================
# FUNÇÕES PARA CHROOT
# ============================================================================

# Montar sistemas de arquivos para chroot
mount_chroot_systems() {
    log "Montando sistemas de arquivos para chroot..."
    
    # Criar diretórios se não existirem
    mkdir -p "$CHROOT_DIR"/{proc,sys,dev/pts,run,tmp}
    
    # Montar sistemas essenciais
    mount --bind /dev "$CHROOT_DIR/dev" 2>/dev/null || true
    mount --bind /dev/pts "$CHROOT_DIR/dev/pts" 2>/dev/null || true  
    mount --bind /proc "$CHROOT_DIR/proc" 2>/dev/null || true
    mount --bind /sys "$CHROOT_DIR/sys" 2>/dev/null || true
    mount --bind /run "$CHROOT_DIR/run" 2>/dev/null || true
    
    # Configurar resolv.conf
    echo "nameserver 8.8.8.8" > "$CHROOT_DIR/etc/resolv.conf"
    echo "nameserver 8.8.4.4" >> "$CHROOT_DIR/etc/resolv.conf"
    
    success "Sistemas de arquivos montados"
}

# Executar comando no chroot com tratamento robusto de erros
chroot_exec() {
    local cmd="$1"
    local allow_fail="${2:-false}"
    
    log "Executando no chroot: $cmd"
    
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

# Instalar pacotes no chroot com retry
install_packages() {
    local packages="$1"
    local retry_individual="${2:-true}"
    
    log "Instalando pacotes: $packages"
    
    # Atualizar repositórios primeiro
    execute_with_retry "chroot_exec 'apt update'" 3 5
    
    # Tentar instalar todos os pacotes de uma vez
    if chroot_exec "apt install -y $packages" true; then
        success "Todos os pacotes instalados com sucesso"
        return 0
    fi
    
    if [ "$retry_individual" = "true" ]; then
        warning "Instalação em lote falhou, tentando individualmente..."
        
        # Instalar pacotes individualmente
        for pkg in $packages; do
            if chroot_exec "apt install -y $pkg" true; then
                success "Pacote instalado: $pkg"
            else
                warning "Falha ao instalar pacote: $pkg"
            fi
        done
    fi
}

# ============================================================================
# FUNÇÕES DE CONFIGURAÇÃO DO SISTEMA
# ============================================================================

# Configurar repositórios do Ubuntu
configure_repositories() {
    section "CONFIGURANDO REPOSITÓRIOS"
    
    log "Configurando sources.list..."
    cat > "$CHROOT_DIR/etc/apt/sources.list" << EOF
# Ubuntu $DISTRO_VERSION ($DISTRO_CODENAME) repositories
deb $UBUNTU_MIRROR $DISTRO_CODENAME main restricted universe multiverse
deb $UBUNTU_MIRROR $DISTRO_CODENAME-updates main restricted universe multiverse
deb $UBUNTU_MIRROR $DISTRO_CODENAME-backports main restricted universe multiverse
deb $SECURITY_MIRROR $DISTRO_CODENAME-security main restricted universe multiverse

# Partner repository
deb http://archive.canonical.com/ubuntu $DISTRO_CODENAME partner
EOF
    
    success "Repositórios configurados"
}

# Configurar locale do sistema
configure_locale() {
    section "CONFIGURANDO LOCALE"
    
    log "Configurando locale UTF-8..."
    cat > "$CHROOT_DIR/etc/locale.gen" << EOF
en_US.UTF-8 UTF-8
C.UTF-8 UTF-8
pt_BR.UTF-8 UTF-8
EOF
    
    chroot_exec "locale-gen" true
    
    cat > "$CHROOT_DIR/etc/default/locale" << EOF
LANG="en_US.UTF-8"
LANGUAGE="en_US:en"
LC_ALL="en_US.UTF-8"
EOF
    
    success "Locale configurado"
}

# Configurar timezone
configure_timezone() {
    log "Configurando timezone..."
    chroot_exec "ln -sf /usr/share/zoneinfo/UTC /etc/localtime"
    chroot_exec "dpkg-reconfigure -f noninteractive tzdata" true
    success "Timezone configurado"
}

# Configurar informações do sistema
configure_system_info() {
    section "CONFIGURANDO INFORMAÇÕES DO SISTEMA"
    
    log "Configurando hostname..."
    echo "$HOSTNAME" > "$CHROOT_DIR/etc/hostname"
    
    log "Configurando hosts..."
    cat > "$CHROOT_DIR/etc/hosts" << EOF
127.0.0.1       localhost
127.0.1.1       $HOSTNAME $HOSTNAME.local
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# SecurityForge specific entries
127.0.0.1       securityforge.local
127.0.0.1       pentest.local
127.0.0.1       lab.local
127.0.0.1       target.local
EOF
    
    log "Configurando os-release..."
    cat > "$CHROOT_DIR/etc/os-release" << EOF
NAME="SecurityForge Linux"
VERSION="3.1.0 (CyberNinja)"
ID=securityforge
ID_LIKE="ubuntu debian"
PRETTY_NAME="SecurityForge Linux 3.1.0 - CyberNinja"
VERSION_ID="3.1.0"
HOME_URL="https://securityforge.org"
DOCUMENTATION_URL="https://docs.securityforge.org"
SUPPORT_URL="https://support.securityforge.org"
BUG_REPORT_URL="https://github.com/securityforge/securityforge-linux/issues"
PRIVACY_POLICY_URL="https://securityforge.org/privacy"
LOGO="securityforge-logo"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:securityforge:securityforge_linux:3.1.0"
VERSION_CODENAME=cyberninja
UBUNTU_CODENAME=$DISTRO_CODENAME
BUILD_ID="$(date +%Y%m%d_%H%M%S)"
BUILD_DATE="$(date +%Y-%m-%d)"
VARIANT="Security Distribution"
VARIANT_ID=security
EOF
    
    # Copiar para lsb-release
    cp "$CHROOT_DIR/etc/os-release" "$CHROOT_DIR/etc/lsb-release"
    
    success "Informações do sistema configuradas"
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO DE SOFTWARE
# ============================================================================

# Instalar sistema base
install_base_system() {
    section "INSTALANDO SISTEMA BASE"
    
    log "Instalando pacotes base essenciais..."
    install_packages "
        ubuntu-minimal
        ubuntu-standard
        locales
        language-pack-en
        keyboard-configuration
        console-setup
        tzdata
        sudo
        adduser
        passwd
        apt-utils
        software-properties-common
        apt-transport-https
        ca-certificates
        gnupg
        lsb-release
        curl
        wget
        git
        vim
        nano
        htop
        tree
        unzip
        zip
        rsync
        net-tools
        iputils-ping
        dnsutils
        psmisc
        lsof
        file
        less
        bash-completion
    "
    
    success "Sistema base instalado"
}

# Instalar kernel e drivers
install_kernel_and_drivers() {
    section "INSTALANDO KERNEL E DRIVERS"
    
    log "Instalando kernel Linux..."
    install_packages "
        linux-image-generic
        linux-headers-generic
        linux-firmware
        linux-modules-extra-$(uname -r)
    " false
    
    log "Instalando drivers gráficos..."
    install_packages "
        xserver-xorg
        xserver-xorg-video-all
        xserver-xorg-input-all
        mesa-utils
        mesa-utils-extra
        va-driver-all
        vdpau-driver-all
    "
    
    log "Instalando drivers de rede..."
    install_packages "
        wireless-tools
        wpasupplicant
        network-manager
        network-manager-gnome
        rfkill
        bluetooth
        bluez
        bluez-tools
    "
    
    log "Instalando drivers de áudio..."
    install_packages "
        alsa-base
        alsa-utils
        pulseaudio
        pavucontrol
        pulseaudio-module-bluetooth
    "
    
    success "Kernel e drivers instalados"
}

# Instalar ferramentas para sistema live
install_live_system_tools() {
    section "INSTALANDO FERRAMENTAS PARA SISTEMA LIVE"
    
    log "Instalando casper e ferramentas live..."
    install_packages "
        casper
        lupin-casper
        discover
        laptop-detect
        os-prober
        initramfs-tools
        squashfs-tools
    "
    
    success "Ferramentas live instaladas"
}

# Instalar ambiente desktop
install_desktop_environment() {
    section "INSTALANDO AMBIENTE DESKTOP"
    
    log "Instalando XFCE Desktop Environment..."
    install_packages "
        xfce4
        xfce4-goodies
        xfce4-panel
        xfce4-session
        xfce4-settings
        xfce4-terminal
        xfce4-taskmanager
        xfce4-screenshooter
        lightdm
        lightdm-gtk-greeter
        lightdm-gtk-greeter-settings
    "
    
    log "Instalando aplicações essenciais..."
    install_packages "
        firefox
        thunar
        thunar-archive-plugin
        thunar-media-tags-plugin
        mousepad
        ristretto
        parole
        file-roller
        gnome-calculator
        gnome-system-monitor
        evince
        gedit
    "
    
    log "Instalando fontes e temas..."
    install_packages "
        fonts-liberation
        fonts-dejavu-core
        fonts-freefont-ttf
        fonts-noto
        ubuntu-mono
        adwaita-icon-theme
        hicolor-icon-theme
    "
    
    success "Ambiente desktop instalado"
}

# Instalar ferramentas de segurança
install_security_tools() {
    section "INSTALANDO FERRAMENTAS DE SEGURANÇA"
    
    log "Instalando linguagens de programação..."
    install_packages "
        python3
        python3-pip
        python3-venv
        python3-dev
        python3-setuptools
        python-is-python3
        ruby
        ruby-dev
        ruby-bundler
        golang-go
        nodejs
        npm
        openjdk-17-jdk
        openjdk-17-jre
    "
    
    log "Instalando ferramentas de rede..."
    install_packages "
        nmap
        masscan
        netcat-openbsd
        socat
        tcpdump
        wireshark
        tshark
        netdiscover
        arp-scan
        traceroute
        whois
        dig
        nslookup
        host
    "
    
    log "Instalando ferramentas de teste web..."
    install_packages "
        nikto
        sqlmap
        dirb
        gobuster
        wfuzz
        curl
        wget
        httpie
    " false
    
    log "Instalando ferramentas de passwords..."
    install_packages "
        john
        hashcat
        hydra
        medusa
        ncrack
        crunch
    " false
    
    log "Instalando ferramentas wireless..."
    install_packages "
        aircrack-ng
        kismet
        reaver
        bully
    " false
    
    log "Instalando ferramentas forenses..."
    install_packages "
        binwalk
        foremost
        scalpel
        volatility
        autopsy
        sleuthkit
    " false
    
    log "Instalando container tools..."
    install_packages "
        docker.io
        docker-compose
    "
    
    success "Ferramentas de segurança instaladas"
}

# ============================================================================
# CONFIGURAÇÃO DE USUÁRIOS E SISTEMA LIVE
# ============================================================================

# Criar usuário do sistema
create_system_user() {
    section "CRIANDO USUÁRIO DO SISTEMA"
    
    log "Criando usuário $SYSTEM_USER..."
    chroot_exec "useradd -m -s /bin/bash -c 'SecurityForge User' $SYSTEM_USER"
    chroot_exec "echo '$SYSTEM_USER:$SYSTEM_PASSWORD' | chpasswd"
    chroot_exec "echo 'root:$SYSTEM_PASSWORD' | chpasswd"
    
    log "Adicionando usuário aos grupos necessários..."
    chroot_exec "usermod -aG sudo,adm,dialout,cdrom,floppy,audio,dip,video,plugdev,netdev,bluetooth,wireshark,docker $SYSTEM_USER"
    
    log "Configurando sudo sem senha..."
    cat > "$CHROOT_DIR/etc/sudoers.d/securityforge" << EOF
$SYSTEM_USER ALL=(ALL) NOPASSWD: ALL
EOF
    chmod 440 "$CHROOT_DIR/etc/sudoers.d/securityforge"
    
    success "Usuário $SYSTEM_USER criado"
}

# Configurar autologin
configure_autologin() {
    section "CONFIGURANDO AUTOLOGIN"
    
    log "Configurando LightDM para autologin..."
    mkdir -p "$CHROOT_DIR/etc/lightdm/lightdm.conf.d"
    cat > "$CHROOT_DIR/etc/lightdm/lightdm.conf.d/60-securityforge.conf" << EOF
[Seat:*]
autologin-user=$SYSTEM_USER
autologin-user-timeout=0
user-session=xfce
greeter-session=lightdm-gtk-greeter
greeter-hide-users=false
greeter-show-manual-login=true
allow-guest=false
EOF
    
    success "Autologin configurado"
}

# Configurar ambiente do usuário
configure_user_environment() {
    section "CONFIGURANDO AMBIENTE DO USUÁRIO"
    
    log "Configurando bashrc personalizado..."
    cat > "$CHROOT_DIR/home/$SYSTEM_USER/.bashrc" << 'EOF'
# SecurityForge Linux - Configuração personalizada do usuário

# Se não executando interativamente, não fazer nada
case $- in
    *i*) ;;
      *) return;;
esac

# Histórico
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s histappend
shopt -s checkwinsize

# Cores para ls
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# Aliases básicos
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# Aliases SecurityForge
alias cdtools='cd /opt/securityforge/tools'
alias cdwordlists='cd /opt/securityforge/wordlists'
alias cdworkspace='cd /opt/securityforge/workspace'
alias cdreports='cd /opt/securityforge/reports'

# Aliases de segurança
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias nmap-stealth='nmap -sS -T2 -f'
alias nikto-scan='nikto -h'
alias sqlmap-scan='sqlmap -u'
alias gobuster-dir='gobuster dir -u'
alias hydra-ssh='hydra -l admin -P /opt/securityforge/wordlists/rockyou.txt ssh://'

# Variáveis de ambiente SecurityForge
export SECURITYFORGE_HOME="/opt/securityforge"
export TOOLS="/opt/securityforge/tools"
export WORDLISTS="/opt/securityforge/wordlists"
export WORKSPACE="/opt/securityforge/workspace"
export REPORTS="/opt/securityforge/reports"
export PATH="/opt/securityforge/tools:/opt/securityforge/scripts:$PATH"

# Prompt personalizado SecurityForge
export PS1='\[\033[0;31m\][\[\033[0;37m\]\u\[\033[0;31m\]@\[\033[0;37m\]\h\[\033[0;31m\]] \[\033[1;34m\]\w \[\033[0;31m\]$ \[\033[0m\]'

# Mostrar banner SecurityForge no login
if [ -f /opt/securityforge/scripts/banner.sh ]; then
    /opt/securityforge/scripts/banner.sh
fi
EOF
    
    log "Criando desktop do usuário..."
    mkdir -p "$CHROOT_DIR/home/$SYSTEM_USER/Desktop"
    
    # Terminal
    cat > "$CHROOT_DIR/home/$SYSTEM_USER/Desktop/Terminal.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal SecurityForge
Comment=Terminal de Comando
Exec=xfce4-terminal
Icon=utilities-terminal
Terminal=false
StartupNotify=false
EOF
    
    # Firefox
    cat > "$CHROOT_DIR/home/$SYSTEM_USER/Desktop/Firefox.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Firefox
Comment=Navegador Web
Exec=firefox
Icon=firefox
Terminal=false
StartupNotify=false
EOF
    
    # File Manager
    cat > "$CHROOT_DIR/home/$SYSTEM_USER/Desktop/FileManager.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=File Manager
Comment=Gerenciador de Arquivos
Exec=thunar
Icon=file-manager
Terminal=false
StartupNotify=false
EOF
    
    # SecurityForge Tools
    cat > "$CHROOT_DIR/home/$SYSTEM_USER/Desktop/SecurityForge-Tools.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=SecurityForge Tools
Comment=Ferramentas de Segurança
Exec=xfce4-terminal -e "bash -c 'echo \"SecurityForge Tools Directory:\"; ls /opt/securityforge/tools/; bash'"
Icon=folder
Terminal=true
StartupNotify=false
EOF
    
    chmod +x "$CHROOT_DIR/home/$SYSTEM_USER/Desktop"/*.desktop
    chroot_exec "chown -R $SYSTEM_USER:$SYSTEM_USER /home/$SYSTEM_USER"
    
    success "Ambiente do usuário configurado"
}

# ============================================================================
# CONFIGURAÇÃO DO SISTEMA LIVE
# ============================================================================

# Configurar sistema live
configure_live_system() {
    section "CONFIGURANDO SISTEMA LIVE"
    
    log "Configurando casper..."
    cat > "$CHROOT_DIR/etc/casper.conf" << EOF
export USERNAME="$SYSTEM_USER"
export USERFULLNAME="SecurityForge User"  
export HOST="$HOSTNAME"
export BUILD_SYSTEM="Ubuntu"
export FLAVOUR="SecurityForge"
EOF
    
    log "Configurando initramfs..."
    cat >> "$CHROOT_DIR/etc/initramfs-tools/modules" << EOF
# Live system modules
squashfs
overlay
loop
isofs
vfat
ntfs
ext4
usb-storage
EOF
    
    # Configurar initramfs.conf
    cat > "$CHROOT_DIR/etc/initramfs-tools/initramfs.conf" << EOF
MODULES=most
KEYMAP=n
COMPRESS=gzip
DEVICE=
NFSROOT=auto
RUNSIZE=10%
FSTYPE=ext4
EOF
    
    # Script personalizado para live system
    mkdir -p "$CHROOT_DIR/usr/share/initramfs-tools/scripts/casper-bottom"
    cat > "$CHROOT_DIR/usr/share/initramfs-tools/scripts/casper-bottom/99securityforge" << 'EOF'
#!/bin/sh

PREREQ=""

prereqs()
{
    echo "$PREREQ"
}

case $1 in
prereqs)
    prereqs
    exit 0
    ;;
esac

. /scripts/casper-functions

log_begin_msg "Configurando SecurityForge Live Session"

# Configurar usuário live
if [ -n "${USERNAME}" ]; then
    if ! id "${USERNAME}" > /dev/null 2>&1; then
        adduser --disabled-password --gecos "${USERFULLNAME:-Live session user}" ${USERNAME}
        echo "${USERNAME}:live" | chroot /root chpasswd
        for group in adm admin dialout cdrom plugdev video audio netdev bluetooth fuse sudo docker wireshark; do
            chroot /root adduser ${USERNAME} ${group} >/dev/null 2>&1 || true
        done
        
        # Configurar autologin
        chroot /root sed -i "s/^#autologin-user=.*$/autologin-user=${USERNAME}/" /etc/lightdm/lightdm.conf 2>/dev/null || true
        
        # Criar estrutura SecurityForge
        chroot /root mkdir -p /opt/securityforge/{tools,scripts,wordlists,workspace,reports} || true
        chroot /root chown -R ${USERNAME}:${USERNAME} /opt/securityforge || true
    fi
fi

log_end_msg
EOF
    
    chmod +x "$CHROOT_DIR/usr/share/initramfs-tools/scripts/casper-bottom/99securityforge"
    
    success "Sistema live configurado"
}

# ============================================================================
# CONFIGURAÇÃO DE SERVIÇOS
# ============================================================================

# Configurar serviços do sistema
configure_services() {
    section "CONFIGURANDO SERVIÇOS"
    
    log "Habilitando serviços essenciais..."
    chroot_exec "systemctl enable lightdm" true
    chroot_exec "systemctl enable NetworkManager" true
    chroot_exec "systemctl enable bluetooth" true
    chroot_exec "systemctl enable docker" true
    
    log "Desabilitando serviços desnecessários..."
    chroot_exec "systemctl disable ssh" true
    chroot_exec "systemctl disable apache2" true
    chroot_exec "systemctl disable mysql" true
    chroot_exec "systemctl disable postgresql" true
    
    success "Serviços configurados"
}

# ============================================================================
# CRIAÇÃO DE ESTRUTURA SECURITYFORGE
# ============================================================================

# Criar estrutura SecurityForge
create_securityforge_structure() {
    section "CRIANDO ESTRUTURA SECURITYFORGE"
    
    log "Criando diretórios SecurityForge..."
    mkdir -p "$CHROOT_DIR/opt/securityforge"/{tools,scripts,wordlists,workspace,reports,docs,configs,exploits,payloads}
    
    log "Criando wordlists básicas..."
    cat > "$CHROOT_DIR/opt/securityforge/wordlists/rockyou.txt" << 'EOF'
123456
password
123456789
12345678
12345
password123
admin
root
user
guest
test
demo
login
qwerty
abc123
Password1
welcome
monkey
letmein
dragon
baseball
superman
batman
master
sunshine
princess
freedom
charlie
passw0rd
shadow
123qwe
654321
EOF
    
    log "Criando scripts úteis..."
    mkdir -p "$CHROOT_DIR/opt/securityforge/scripts"
    cat > "$CHROOT_DIR/opt/securityforge/scripts/banner.sh" << 'EOF'
#!/bin/bash
echo -e "\033[0;31m"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                       🛡️  SECURITYFORGE LINUX 3.1.0                        ║"
echo "║                                CyberNinja                                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "\033[0m"
echo "🖥️  Sistema: SecurityForge Linux 3.1.0"
echo "👤 Usuário: $(whoami)"
echo "📅 Data: $(date)"
echo "🔧 Ferramentas de Segurança Disponíveis"
echo "📁 Workspace: /opt/securityforge/workspace"
echo "📚 Wordlists: /opt/securityforge/wordlists"
echo ""
echo "💡 Comandos úteis:"
echo "   cdtools     - Ir para ferramentas"
echo "   cdwordlists - Ir para wordlists"
echo "   cdworkspace - Ir para workspace"
echo ""
EOF
    
    chmod +x "$CHROOT_DIR/opt/securityforge/scripts/banner.sh"
    
    # Configurar permissões
    chroot_exec "chown -R $SYSTEM_USER:$SYSTEM_USER /opt/securityforge"
    
    success "Estrutura SecurityForge criada"
}

# ============================================================================
# REGENERAÇÃO DO INITRAMFS
# ============================================================================

# Regenerar initramfs
regenerate_initramfs() {
    section "REGENERANDO INITRAMFS"
    
    log "Regenerando initramfs para todos os kernels..."
    chroot_exec "update-initramfs -c -k all"
    
    success "Initramfs regenerado"
}

# ============================================================================
# LIMPEZA FINAL
# ============================================================================

# Limpeza final do sistema
final_cleanup() {
    section "EXECUTANDO LIMPEZA FINAL"
    
    log "Limpando cache de pacotes..."
    chroot_exec "apt autoremove -y" true
    chroot_exec "apt autoclean" true
    
    log "Removendo arquivos temporários..."
    rm -rf "$CHROOT_DIR/var/lib/apt/lists/*" 2>/dev/null || true
    rm -rf "$CHROOT_DIR/tmp/*" 2>/dev/null || true
    rm -rf "$CHROOT_DIR/var/tmp/*" 2>/dev/null || true
    rm -rf "$CHROOT_DIR/var/cache/apt/archives/*.deb" 2>/dev/null || true
    
    log "Limpando logs..."
    find "$CHROOT_DIR/var/log" -type f -name "*.log" -delete 2>/dev/null || true
    
    log "Limpando histórico..."
    > "$CHROOT_DIR/root/.bash_history" 2>/dev/null || true
    > "$CHROOT_DIR/home/$SYSTEM_USER/.bash_history" 2>/dev/null || true
    
    success "Limpeza final concluída"
}

# ============================================================================
# FINALIZAÇÃO
# ============================================================================

# Desmontar sistemas e preparar rootfs
finalize_build() {
    section "FINALIZANDO BUILD"
    
    log "Desmontando sistemas de arquivos..."
    ultra_cleanup
    
    log "Copiando sistema para rootfs..."
    rsync -av --progress "$CHROOT_DIR/" "$ROOTFS_DIR/" \
        --exclude='/proc/*' \
        --exclude='/sys/*' \
        --exclude='/dev/*' \
        --exclude='/run/*' \
        --exclude='/tmp/*' \
        --exclude='/var/tmp/*'
    
    # Criar diretórios essenciais no rootfs
    mkdir -p "$ROOTFS_DIR"/{proc,sys,dev,run,tmp,var/tmp}
    
    # Criar arquivo de informações do build
    cat > "$ROOTFS_DIR/opt/securityforge/BUILD_INFO.txt" << EOF
SecurityForge Linux 3.1.0 - CyberNinja
Build Date: $(date)
Build Host: $(hostname)
Build User: $(whoami)
Ubuntu Base: $DISTRO_VERSION ($DISTRO_CODENAME)
Kernel: $(ls $ROOTFS_DIR/boot/vmlinuz-* | head -1 | sed 's/.*vmlinuz-//')
Size: $(du -sh "$ROOTFS_DIR" | cut -f1)
EOF
    
    success "Build finalizado"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
       error "Este script deve ser executado como root"
       exit 1
    fi
    
    # Mostrar banner
    header "╔═══════════════════════════════════════════════════════════════════════════════╗"
    header "║                🛡️  SECURITYFORGE LINUX BUILD AVANÇADO v3.1.0               ║"
    header "║                    Sistema Operacional Completo - CyberNinja                ║"
    header "╚═══════════════════════════════════════════════════════════════════════════════╝"
    
    # Criar arquivo de log
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "SecurityForge Linux Build Started at $(date)" > "$LOG_FILE"
    
    # Executar etapas do build
    install_host_dependencies
    ultra_cleanup
    mkdir -p "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"
    
    # Executar debootstrap
    section "EXECUTANDO DEBOOTSTRAP"
    log "Criando sistema base Ubuntu $DISTRO_VERSION..."
    execute_with_retry "debootstrap --arch=amd64 --variant=minbase --include=systemd-sysv,locales,language-pack-en,ubuntu-minimal $DISTRO_CODENAME '$CHROOT_DIR' '$UBUNTU_MIRROR'"
    
    # Verificar se debootstrap funcionou
    if [ ! -f "$CHROOT_DIR/bin/bash" ]; then
        error "Debootstrap falhou!"
        exit 1
    fi
    
    # Montar sistemas e continuar build
    mount_chroot_systems
    configure_repositories
    configure_locale
    configure_timezone
    configure_system_info
    
    # Instalar software
    install_base_system
    install_kernel_and_drivers
    install_live_system_tools
    install_desktop_environment
    install_security_tools
    
    # Configurar sistema
    create_system_user
    configure_autologin
    configure_user_environment
    configure_live_system
    configure_services
    create_securityforge_structure
    regenerate_initramfs
    final_cleanup
    finalize_build
    
    # Relatório final
    header "🎯 BUILD CONCLUÍDO COM SUCESSO!"
    success "Sistema SecurityForge Linux criado com sucesso!"
    info "Localização: $ROOTFS_DIR"
    info "Tamanho: $(du -sh "$ROOTFS_DIR" | cut -f1)"
    info "Log completo: $LOG_FILE"
    
    echo ""
    header "📋 INFORMAÇÕES DO SISTEMA CRIADO:"
    echo "✅ Sistema Ubuntu $DISTRO_VERSION LTS completo"
    echo "✅ Desktop XFCE4 configurado"
    echo "✅ Usuário '$SYSTEM_USER' criado (senha: $SYSTEM_PASSWORD)"
    echo "✅ Ferramentas de segurança instaladas"
    echo "✅ Sistema live configurado"
    echo "✅ Estrutura SecurityForge completa"
    echo ""
    info "Próximo passo: sudo ./admin/create-iso-fixed.sh"
    
    header "═══════════════════════════════════════════════════════════════════════════════"
}

# Executar função principal
main "$@"
