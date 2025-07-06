#!/bin/bash
# SecurityForge Linux - Build Completo do Sistema Operacional (CORRIGIDO v2)

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
header() { echo -e "${PURPLE}$1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }

# Configurações
WORK_DIR="/home/estevam/securityforge-os"
ROOTFS_DIR="$WORK_DIR/rootfs"
ISO_DIR="$WORK_DIR/iso"
CHROOT_DIR="$WORK_DIR/chroot"
SCRIPTS_DIR="$WORK_DIR/scripts"

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

header "╔═══════════════════════════════════════════════════════════════════════════════╗"
header "║                🛡️  SECURITYFORGE LINUX COMPLETE BUILD v2                    ║"
header "║                    Sistema Operacional Completo v3.1.0                      ║"
header "╚═══════════════════════════════════════════════════════════════════════════════╝"

# Função para executar comandos no chroot
chroot_exec() {
    local cmd="$1"
    log "Executando no chroot: $cmd"
    if ! chroot "$CHROOT_DIR" /bin/bash -c "$cmd" 2>/dev/null; then
        warning "Comando falhou (não crítico): $cmd"
        return 1
    fi
    return 0
}

# Função para instalar pacotes
install_packages() {
    local packages="$1"
    log "Instalando pacotes: $packages"
    chroot_exec "apt update" || warning "Falha ao atualizar repositórios"
    chroot_exec "DEBIAN_FRONTEND=noninteractive apt install -y $packages" || {
        warning "Alguns pacotes falharam: $packages"
        for pkg in $packages; do
            chroot_exec "DEBIAN_FRONTEND=noninteractive apt install -y $pkg" || warning "Falha ao instalar: $pkg"
        done
    }
}

# Função para montar sistemas de arquivos
mount_systems() {
    log "Montando sistemas de arquivos para chroot..."
    mount --bind /dev "$CHROOT_DIR/dev" 2>/dev/null || true
    mount --bind /dev/pts "$CHROOT_DIR/dev/pts" 2>/dev/null || true
    mount --bind /proc "$CHROOT_DIR/proc" 2>/dev/null || true
    mount --bind /sys "$CHROOT_DIR/sys" 2>/dev/null || true
    mount --bind /run "$CHROOT_DIR/run" 2>/dev/null || true
}

# Função para desmontar sistemas de arquivos
umount_systems() {
    log "Desmontando sistemas de arquivos..."
    umount "$CHROOT_DIR/run" 2>/dev/null || true
    umount "$CHROOT_DIR/sys" 2>/dev/null || true
    umount "$CHROOT_DIR/proc" 2>/dev/null || true
    umount "$CHROOT_DIR/dev/pts" 2>/dev/null || true
    umount "$CHROOT_DIR/dev" 2>/dev/null || true
}

# Cleanup
cleanup() {
    log "Executando limpeza..."
    umount_systems
}
trap cleanup EXIT

# 1. PREPARAR AMBIENTE
header "📋 ETAPA 1: PREPARAÇÃO DO AMBIENTE"

log "Instalando dependências do host..."
apt update
apt install -y debootstrap squashfs-tools genisoimage syslinux-utils \
    xorriso grub2-common grub-pc-bin grub-efi-amd64-bin isolinux \
    wget curl git build-essential rsync locales

log "Limpando diretórios anteriores..."
umount_systems 2>/dev/null || true
rm -rf "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"
mkdir -p "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"

# 2. CRIAR SISTEMA BASE
header "🏗️ ETAPA 2: CRIANDO SISTEMA BASE UBUNTU"

log "Executando debootstrap para Ubuntu 22.04..."
debootstrap --arch=amd64 --variant=minbase \
    --include=systemd-sysv,locales,language-pack-en,ubuntu-minimal,linux-generic \
    jammy "$CHROOT_DIR" http://archive.ubuntu.com/ubuntu/

log "Configurando repositórios..."
cat > "$CHROOT_DIR/etc/apt/sources.list" << 'SOURCES_EOF'
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
SOURCES_EOF

# Montar sistemas necessários
mount_systems

# Configurar locale
log "Configurando locale..."
cat > "$CHROOT_DIR/etc/locale.gen" << 'LOCALE_EOF'
en_US.UTF-8 UTF-8
C.UTF-8 UTF-8
LOCALE_EOF

chroot_exec "locale-gen" || warning "locale-gen falhou"
echo 'LANG="en_US.UTF-8"' > "$CHROOT_DIR/etc/default/locale"

log "Atualizando sistema base..."
chroot_exec "apt update"
chroot_exec "DEBIAN_FRONTEND=noninteractive apt upgrade -y"

# 3. INSTALAR KERNEL E DRIVERS
header "🔧 ETAPA 3: INSTALANDO KERNEL E DRIVERS"

log "Instalando kernel e drivers essenciais..."
install_packages "linux-image-generic linux-headers-generic linux-firmware"
install_packages "initramfs-tools casper discover laptop-detect os-prober"

# Drivers gráficos e hardware essenciais
log "Instalando drivers gráficos e hardware..."
install_packages "xserver-xorg xserver-xorg-video-all xserver-xorg-input-all"
install_packages "mesa-utils mesa-utils-extra"
install_packages "firmware-linux firmware-linux-free firmware-linux-nonfree" || warning "Alguns firmwares falharam"

# Hardware adicional
install_packages "alsa-base alsa-utils pulseaudio"
install_packages "bluetooth bluez bluez-tools"
install_packages "network-manager wireless-tools wpasupplicant"

# 4. INSTALAR SISTEMA DESKTOP
header "🖥️ ETAPA 4: INSTALANDO SISTEMA DESKTOP"

log "Instalando ambiente desktop..."
install_packages "ubuntu-desktop-minimal" || {
    warning "ubuntu-desktop-minimal falhou, instalando XFCE..."
    install_packages "xfce4 xfce4-goodies lightdm lightdm-gtk-greeter"
}

install_packages "firefox thunar mousepad ristretto xfce4-terminal"
install_packages "pulseaudio pavucontrol"

# 5. CONFIGURAR SISTEMA
header "⚙️ ETAPA 5: CONFIGURANDO SISTEMA"

log "Configurando hostname..."
echo "securityforge" > "$CHROOT_DIR/etc/hostname"

log "Configurando hosts..."
cat > "$CHROOT_DIR/etc/hosts" << 'HOSTS_EOF'
127.0.0.1       localhost
127.0.1.1       securityforge securityforge.local
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
HOSTS_EOF

log "Configurando informações do sistema..."
cat > "$CHROOT_DIR/etc/os-release" << 'OS_RELEASE_EOF'
NAME="SecurityForge Linux"
VERSION="3.1.0 (CyberNinja)"
ID=securityforge
ID_LIKE="ubuntu debian"
PRETTY_NAME="SecurityForge Linux 3.1.0 - CyberNinja"
VERSION_ID="3.1.0"
HOME_URL="https://securityforge.org"
BUILD_ID="$(date +%Y%m%d_%H%M%S)"
BUILD_DATE="$(date +%Y-%m-%d)"
UBUNTU_CODENAME=jammy
OS_RELEASE_EOF

log "Criando usuário live..."
chroot_exec "useradd -m -s /bin/bash -G sudo,adm,dialout,cdrom,floppy,audio,dip,video,plugdev,netdev secforge"
chroot_exec "echo 'secforge:live' | chpasswd"
chroot_exec "echo 'root:live' | chpasswd"

# Configurar sudo
cat > "$CHROOT_DIR/etc/sudoers.d/securityforge" << 'SUDO_EOF'
secforge ALL=(ALL) NOPASSWD: ALL
SUDO_EOF
chmod 440 "$CHROOT_DIR/etc/sudoers.d/securityforge"

# 6. CONFIGURAR SISTEMA LIVE
header "💿 ETAPA 6: CONFIGURANDO SISTEMA LIVE"

log "Configurando casper..."
install_packages "casper lupin-casper"

# Configurar casper corretamente
cat > "$CHROOT_DIR/etc/casper.conf" << 'CASPER_EOF'
export USERNAME="secforge"
export USERFULLNAME="SecurityForge User"
export HOST="securityforge"
export BUILD_SYSTEM="Ubuntu"
export FLAVOUR="SecurityForge"
CASPER_EOF

# Configurar autologin
mkdir -p "$CHROOT_DIR/etc/lightdm/lightdm.conf.d"
cat > "$CHROOT_DIR/etc/lightdm/lightdm.conf.d/60-securityforge.conf" << 'LIGHTDM_EOF'
[Seat:*]
autologin-user=secforge
autologin-user-timeout=0
user-session=ubuntu
greeter-session=unity-greeter
LIGHTDM_EOF

# Configurar live session
cat > "$CHROOT_DIR/usr/share/initramfs-tools/scripts/casper-bottom/99securityforge" << 'LIVE_SCRIPT_EOF'
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

log_begin_msg "Configuring SecurityForge Live Session"

# Configure live user
if [ -n "${USERNAME}" ]; then
    if ! id "${USERNAME}" > /dev/null 2>&1; then
        adduser --disabled-password --gecos "${USERFULLNAME:-Live session user}" ${USERNAME}
        echo "${USERNAME}:live" | chroot /root chpasswd
        for group in adm admin dialout cdrom plugdev video audio netdev bluetooth fuse sudo; do
            chroot /root adduser ${USERNAME} ${group} >/dev/null 2>&1 || true
        done
    fi
fi

log_end_msg

LIVE_SCRIPT_EOF

chmod +x "$CHROOT_DIR/usr/share/initramfs-tools/scripts/casper-bottom/99securityforge"

# 7. INSTALAR FERRAMENTAS BÁSICAS
header "🛠️ ETAPA 7: INSTALANDO FERRAMENTAS BÁSICAS"

log "Instalando ferramentas de segurança básicas..."
install_packages "nmap nikto sqlmap curl wget git vim nano"
install_packages "python3 python3-pip"
install_packages "net-tools iputils-ping"

# Criar estrutura SecurityForge
mkdir -p "$CHROOT_DIR/opt/securityforge"/{tools,scripts,wordlists,workspace}

# 8. CONFIGURAR INITRAMFS
header "🔄 ETAPA 8: CONFIGURANDO INITRAMFS"

log "Configurando módulos do initramfs..."
cat >> "$CHROOT_DIR/etc/initramfs-tools/modules" << 'MODULES_EOF'
# Live system modules
squashfs
overlay
loop
isofs
vfat
ntfs
ext4
MODULES_EOF

# Configurar initramfs
echo 'MODULES=most' > "$CHROOT_DIR/etc/initramfs-tools/initramfs.conf"
echo 'BUSYBOX=y' >> "$CHROOT_DIR/etc/initramfs-tools/initramfs.conf"
echo 'COMPRESS=gzip' >> "$CHROOT_DIR/etc/initramfs-tools/initramfs.conf"

# Regenerar initramfs
chroot_exec "update-initramfs -c -k all"

# 9. CONFIGURAR REDE E SERVIÇOS
header "🌐 ETAPA 9: CONFIGURANDO REDE E SERVIÇOS"

log "Configurando Network Manager..."
chroot_exec "systemctl enable NetworkManager"
chroot_exec "systemctl disable networking" || true

log "Configurando serviços essenciais..."
chroot_exec "systemctl enable lightdm" || warning "Falha ao habilitar lightdm"
chroot_exec "systemctl disable ssh" || true

# 10. LIMPAR SISTEMA
header "🧹 ETAPA 10: LIMPANDO SISTEMA"

log "Limpando cache e arquivos temporários..."
chroot_exec "apt autoremove -y"
chroot_exec "apt autoclean"
rm -rf "$CHROOT_DIR/var/lib/apt/lists/*"
rm -rf "$CHROOT_DIR/tmp/*"
rm -rf "$CHROOT_DIR/var/tmp/*"
rm -f "$CHROOT_DIR/var/log"/*.log

# Limpar histórico
> "$CHROOT_DIR/root/.bash_history" 2>/dev/null || true
> "$CHROOT_DIR/home/secforge/.bash_history" 2>/dev/null || true

# Desmontar sistemas
umount_systems

# 11. COPIAR PARA ROOTFS
header "📁 ETAPA 11: PREPARANDO ROOTFS"

log "Copiando sistema para rootfs..."
rsync -av --progress "$CHROOT_DIR/" "$ROOTFS_DIR/"

success "Sistema SecurityForge Linux criado com sucesso!"
info "Localização: $ROOTFS_DIR"
info "Tamanho: $(du -sh "$ROOTFS_DIR" | cut -f1)"

echo ""
header "🎯 PRÓXIMOS PASSOS:"
echo "1. Execute: sudo ./admin/create-iso-fixed.sh"
echo "2. Teste a ISO em uma VM"
echo "3. Use parâmetros de boot seguros se houver problemas"
