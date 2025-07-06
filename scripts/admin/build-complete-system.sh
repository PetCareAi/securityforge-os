#!/bin/bash
# SecurityForge Linux - Build Completo do Sistema Operacional (CORRIGIDO)

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
header "║                🛡️  SECURITYFORGE LINUX COMPLETE BUILD                       ║"
header "║                    Sistema Operacional Completo v3.1.0                      ║"
header "╚═══════════════════════════════════════════════════════════════════════════════╝"

# Função para executar comandos no chroot com tratamento de erro
chroot_exec() {
    local cmd="$1"
    log "Executando no chroot: $cmd"
    if ! chroot "$CHROOT_DIR" /bin/bash -c "$cmd"; then
        error "Falha ao executar: $cmd"
        return 1
    fi
}

# Função para instalar pacotes com verificação
install_packages() {
    local packages="$1"
    log "Instalando pacotes: $packages"
    chroot_exec "apt update"
    chroot_exec "DEBIAN_FRONTEND=noninteractive apt install -y $packages" || {
        warning "Alguns pacotes falharam, continuando..."
    }
}

# Função para montar sistemas de arquivos necessários
mount_systems() {
    log "Montando sistemas de arquivos para chroot..."
    mount --bind /dev "$CHROOT_DIR/dev" || true
    mount --bind /dev/pts "$CHROOT_DIR/dev/pts" || true
    mount --bind /proc "$CHROOT_DIR/proc" || true
    mount --bind /sys "$CHROOT_DIR/sys" || true
    mount --bind /run "$CHROOT_DIR/run" || true
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

# Cleanup em caso de erro
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
    wget curl git build-essential rsync

log "Limpando diretórios anteriores..."
umount_systems 2>/dev/null || true
rm -rf "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"
mkdir -p "$CHROOT_DIR" "$ROOTFS_DIR" "$ISO_DIR"

# 2. CRIAR SISTEMA BASE
header "🏗️ ETAPA 2: CRIANDO SISTEMA BASE UBUNTU"

log "Executando debootstrap para Ubuntu 22.04..."
debootstrap --arch=amd64 --variant=minbase --include=systemd-sysv jammy "$CHROOT_DIR" http://archive.ubuntu.com/ubuntu/

log "Configurando repositórios no chroot..."
cat > "$CHROOT_DIR/etc/apt/sources.list" << 'SOURCES_EOF'
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
deb http://archive.canonical.com/ubuntu jammy partner
SOURCES_EOF

# Montar sistemas necessários
mount_systems

# Configurar locale e timezone
log "Configurando locale e timezone..."
chroot_exec "locale-gen en_US.UTF-8"
chroot_exec "update-locale LANG=en_US.UTF-8"
echo 'LANG="en_US.UTF-8"' > "$CHROOT_DIR/etc/default/locale"

log "Atualizando sistema base..."
chroot_exec "apt update"
chroot_exec "DEBIAN_FRONTEND=noninteractive apt upgrade -y"

# 3. INSTALAR SISTEMA ESSENCIAL
header "⚙️ ETAPA 3: INSTALANDO SISTEMA ESSENCIAL"

log "Instalando kernel e componentes essenciais..."
install_packages "linux-image-generic linux-headers-generic linux-firmware"
install_packages "initramfs-tools casper discover laptop-detect os-prober"
install_packages "grub-common grub-pc-bin grub-efi-amd64 grub-efi-amd64-bin"

log "Instalando ferramentas de rede..."
install_packages "network-manager wireless-tools wpasupplicant net-tools"
install_packages "openssh-client openssh-server"

log "Instalando utilitários básicos..."
install_packages "sudo curl wget git vim nano htop tree unzip zip"
install_packages "software-properties-common apt-transport-https ca-certificates gnupg lsb-release"

log "Instalando desktop environment XFCE..."
install_packages "xfce4 xfce4-goodies lightdm lightdm-gtk-greeter"
install_packages "firefox thunar mousepad ristretto xfce4-terminal"
install_packages "pulseaudio pavucontrol"

# 4. CONFIGURAR SISTEMA
header "🔧 ETAPA 4: CONFIGURANDO SISTEMA"

log "Configurando hostname..."
echo "securityforge-workstation" > "$CHROOT_DIR/etc/hostname"

log "Configurando hosts..."
cat > "$CHROOT_DIR/etc/hosts" << 'HOSTS_EOF'
127.0.0.1       localhost
127.0.1.1       securityforge-workstation securityforge
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# SecurityForge specific entries
127.0.0.1       securityforge.local
127.0.0.1       pentest.local
127.0.0.1       lab.local
127.0.0.1       target.local
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
DOCUMENTATION_URL="https://docs.securityforge.org"
SUPPORT_URL="https://support.securityforge.org"
BUG_REPORT_URL="https://github.com/securityforge/securityforge-linux/issues"
PRIVACY_POLICY_URL="https://securityforge.org/privacy"
LOGO="securityforge-logo"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:securityforge:securityforge_linux:3.1.0"
VERSION_CODENAME=cyberninja
UBUNTU_CODENAME=jammy
BUILD_ID="$(date +%Y%m%d_%H%M%S)"
BUILD_DATE="$(date +%Y-%m-%d)"
VARIANT="Security Distribution"
VARIANT_ID=security
OS_RELEASE_EOF

cp "$CHROOT_DIR/etc/os-release" "$CHROOT_DIR/etc/lsb-release"

log "Criando usuário secforge..."
chroot_exec "useradd -m -s /bin/bash -G sudo,adm,dialout,cdrom,floppy,audio,dip,video,plugdev,netdev secforge"
chroot_exec "echo 'secforge:SecurityForge2024!' | chpasswd"
chroot_exec "echo 'root:SecurityForge2024!' | chpasswd"

# Configurar sudo sem senha para o usuário secforge
cat > "$CHROOT_DIR/etc/sudoers.d/securityforge" << 'SUDO_EOF'
secforge ALL=(ALL) NOPASSWD: ALL
EOF

log "Configurando autologin..."
mkdir -p "$CHROOT_DIR/etc/lightdm/lightdm.conf.d"
cat > "$CHROOT_DIR/etc/lightdm/lightdm.conf.d/60-securityforge.conf" << 'LIGHTDM_EOF'
[Seat:*]
autologin-user=secforge
autologin-user-timeout=0
user-session=xfce
greeter-session=lightdm-gtk-greeter
greeter-hide-users=false
greeter-show-manual-login=true
allow-guest=false
LIGHTDM_EOF

# 5. INSTALAR FERRAMENTAS DE SEGURANÇA
header "🛡️ ETAPA 5: INSTALANDO FERRAMENTAS DE SEGURANÇA"

log "Criando estrutura SecurityForge..."
mkdir -p "$CHROOT_DIR/opt/securityforge"/{tools,scripts,wordlists,workspace,reports,docs}

log "Instalando linguagens de programação..."
install_packages "python3 python3-pip python3-venv"
install_packages "ruby ruby-dev"
install_packages "golang-go"
install_packages "nodejs npm"
install_packages "openjdk-17-jdk"

log "Instalando ferramentas básicas de segurança..."
install_packages "nmap masscan"
install_packages "nikto sqlmap dirb gobuster"
install_packages "hydra john hashcat"
install_packages "aircrack-ng"
install_packages "wireshark tshark tcpdump"
install_packages "netcat-openbsd socat"
install_packages "curl wget git"
install_packages "metasploit-framework" || warning "Metasploit não disponível via apt"

log "Instalando Docker..."
install_packages "docker.io docker-compose"
chroot_exec "systemctl enable docker"
chroot_exec "usermod -aG docker secforge"

log "Instalando ferramentas Python para segurança..."
chroot_exec "pip3 install --break-system-packages requests beautifulsoup4 scapy pwntools" || warning "Algumas ferramentas Python falharam"

log "Configurando ferramentas Go..."
chroot_exec "export GOPATH=/opt/go && mkdir -p /opt/go"
chroot_exec "export GOPATH=/opt/go && export PATH=\$PATH:/usr/local/go/bin:/opt/go/bin && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" || warning "Subfinder falhou"

# 6. CONFIGURAR WORDLISTS
header "📚 ETAPA 6: CONFIGURANDO WORDLISTS"

log "Criando wordlists básicas..."
mkdir -p "$CHROOT_DIR/opt/securityforge/wordlists"

# Criar rockyou básico
cat > "$CHROOT_DIR/opt/securityforge/wordlists/rockyou.txt" << 'WORDLIST_EOF'
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
trustno1
hunter
jennifer
jordan
michelle
matthew
andrew
daniel
anthony
mark
donald
steven
kenneth
joshua
kevin
brian
george
edward
ronald
timothy
jason
jeffrey
ryan
jacob
gary
nicholas
eric
jonathan
stephen
larry
justin
scott
brandon
benjamin
samuel
gregory
frank
raymond
alexander
patrick
jack
dennis
jerry
tyler
aaron
jose
henry
adam
douglas
nathan
peter
zachary
kyle
noah
william
oliver
WORDLIST_EOF

# Criar wordlists de diretórios web
cat > "$CHROOT_DIR/opt/securityforge/wordlists/web-directories.txt" << 'WEBDIR_EOF'
admin
administrator
login
wp-admin
wp-content
wp-includes
administrator
admin-panel
control-panel
cpanel
phpmyadmin
mysql
database
backup
config
test
demo
uploads
images
files
docs
api
assets
css
js
javascript
include
includes
lib
libs
src
app
application
system
bin
tmp
temp
cache
log
logs
private
public
static
media
content
data
old
new
backup
bak
archive
dev
development
staging
beta
alpha
EOF

# Criar wordlists de subdomínios
cat > "$CHROOT_DIR/opt/securityforge/wordlists/subdomains.txt" << 'SUBDOMAIN_EOF'
www
mail
ftp
admin
api
app
blog
dev
test
staging
beta
alpha
cdn
static
media
assets
files
docs
support
help
portal
dashboard
panel
cp
cpanel
webmail
mx
ns1
ns2
dns
smtp
pop
imap
vpn
ssh
sftp
secure
ssl
remote
mobile
m
wap
store
shop
payment
pay
checkout
forum
wiki
news
downloads
upload
uploads
backup
old
new
demo
sandbox
lab
EOF

# Instalar SecLists se possível
chroot_exec "cd /opt/securityforge/wordlists && git clone --depth 1 https://github.com/danielmiessler/SecLists.git seclists" || warning "SecLists não baixado"

# 7. CONFIGURAR AMBIENTE DO USUÁRIO
header "👤 ETAPA 7: CONFIGURANDO AMBIENTE DO USUÁRIO"

log "Configurando bashrc personalizado..."
cat > "$CHROOT_DIR/home/secforge/.bashrc" << 'BASHRC_EOF'
# SecurityForge Linux - Configuração personalizada

# Aliases básicos
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias grep='grep --color=auto'

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
alias wireshark-sudo='sudo wireshark'

# Variáveis de ambiente SecurityForge
export SECURITYFORGE_HOME="/opt/securityforge"
export TOOLS="/opt/securityforge/tools"
export WORDLISTS="/opt/securityforge/wordlists"
export WORKSPACE="/opt/securityforge/workspace"
export REPORTS="/opt/securityforge/reports"
export PATH="/opt/securityforge/tools:/opt/go/bin:$PATH"
export GOPATH="/opt/go"

# Prompt personalizado SecurityForge
export PS1='\[\033[0;31m\][\[\033[0;37m\]\u\[\033[0;31m\]@\[\033[0;37m\]\h\[\033[0;31m\]] \[\033[1;34m\]\w \[\033[0;31m\]$ \[\033[0m\]'

# Mostrar banner SecurityForge na primeira execução
if [ -f /opt/securityforge/scripts/banner.sh ] && [ "$PS1" ]; then
    /opt/securityforge/scripts/banner.sh
fi

# Configurações para ferramentas
export METASPLOIT_BASEDIR="/opt/metasploit-framework"
export MSF_DATABASE_CONFIG="/opt/metasploit-framework/config/database.yml"
BASHRC_EOF

log "Criando script de banner..."
mkdir -p "$CHROOT_DIR/opt/securityforge/scripts"
cat > "$CHROOT_DIR/opt/securityforge/scripts/banner.sh" << 'BANNER_EOF'
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
echo "🔧 Ferramentas de Segurança Instaladas"
echo "📁 Workspace: $WORKSPACE"
echo "📚 Wordlists: $WORDLISTS"
echo ""
echo "💡 Comandos úteis:"
echo "   cdtools     - Ir para ferramentas (/opt/securityforge/tools)"
echo "   cdwordlists - Ir para wordlists (/opt/securityforge/wordlists)"
echo "   cdworkspace - Ir para workspace (/opt/securityforge/workspace)"
echo ""
echo "🛡️ Ferramentas principais:"
echo "   nmap, nikto, sqlmap, gobuster, hydra, john, hashcat"
echo "   wireshark, aircrack-ng, metasploit"
echo ""
BANNER_EOF

chmod +x "$CHROOT_DIR/opt/securityforge/scripts/banner.sh"

log "Configurando desktop do usuário..."
mkdir -p "$CHROOT_DIR/home/secforge/Desktop"

# Atalho para terminal
cat > "$CHROOT_DIR/home/secforge/Desktop/Terminal.desktop" << 'TERMINAL_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal SecurityForge
Comment=Terminal de Comando
Exec=xfce4-terminal
Icon=utilities-terminal
Terminal=false
StartupNotify=false
TERMINAL_EOF

# Atalho para Wireshark
cat > "$CHROOT_DIR/home/secforge/Desktop/Wireshark.desktop" << 'WIRESHARK_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Wireshark
Comment=Analisador de Rede
Exec=sudo wireshark
Icon=wireshark
Terminal=false
StartupNotify=false
WIRESHARK_EOF

# Atalho para Firefox
cat > "$CHROOT_DIR/home/secforge/Desktop/Firefox.desktop" << 'FIREFOX_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Firefox
Comment=Navegador Web
Exec=firefox
Icon=firefox
Terminal=false
StartupNotify=false
FIREFOX_EOF

# Atalho para File Manager
cat > "$CHROOT_DIR/home/secforge/Desktop/FileManager.desktop" << 'FILEMANAGER_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=File Manager
Comment=Gerenciador de Arquivos
Exec=thunar
Icon=file-manager
Terminal=false
StartupNotify=false
FILEMANAGER_EOF

chmod +x "$CHROOT_DIR/home/secforge/Desktop"/*.desktop
chroot_exec "chown -R secforge:secforge /home/secforge"

# 8. CONFIGURAR LIVE SYSTEM
header "💿 ETAPA 8: CONFIGURANDO SISTEMA LIVE"

log "Configurando casper para live boot..."
mkdir -p "$CHROOT_DIR/etc/casper.conf"
cat > "$CHROOT_DIR/etc/casper.conf" << 'CASPER_EOF'
# SecurityForge Live System Configuration
export USERNAME="secforge"
export USERFULLNAME="SecurityForge User"
export HOST="securityforge-workstation"
CASPER_EOF

log "Configurando initramfs..."
echo "squashfs" >> "$CHROOT_DIR/etc/initramfs-tools/modules"
echo "overlay" >> "$CHROOT_DIR/etc/initramfs-tools/modules"
echo "loop" >> "$CHROOT_DIR/etc/initramfs-tools/modules"

# Configurar hooks para live system
mkdir -p "$CHROOT_DIR/etc/initramfs-tools/scripts/casper-bottom"
cat > "$CHROOT_DIR/etc/initramfs-tools/scripts/casper-bottom/99securityforge" << 'HOOK_EOF'
#!/bin/sh
# SecurityForge Live System Hook

case $1 in
    prereqs)
        exit 0
        ;;
esac

# Criar usuário live se não existir
if ! id secforge >/dev/null 2>&1; then
    adduser --gecos "SecurityForge User" --disabled-password secforge
    echo "secforge:SecurityForge2024!" | chpasswd
    usermod -aG sudo,adm,dialout,cdrom,floppy,audio,dip,video,plugdev,netdev,docker secforge
fi
HOOK_EOF

chmod +x "$CHROOT_DIR/etc/initramfs-tools/scripts/casper-bottom/99securityforge"

# Regenerar initramfs
chroot_exec "update-initramfs -c -k all"

# 9. LIMPAR SISTEMA
header "🧹 ETAPA 9: LIMPANDO SISTEMA"

log "Removendo arquivos temporários..."
chroot_exec "apt autoremove -y"
chroot_exec "apt autoclean"
rm -rf "$CHROOT_DIR/var/lib/apt/lists/*"
rm -rf "$CHROOT_DIR/tmp/*"
rm -rf "$CHROOT_DIR/var/tmp/*"
rm -f "$CHROOT_DIR/var/log"/*.log

# Limpar histórico
> "$CHROOT_DIR/root/.bash_history"
> "$CHROOT_DIR/home/secforge/.bash_history"

# Desmontar sistemas
umount_systems

# 10. COPIAR PARA ROOTFS
header "📁 ETAPA 10: PREPARANDO ROOTFS"

log "Copiando sistema para rootfs..."
rsync -av --progress "$CHROOT_DIR/" "$ROOTFS_DIR/"

success "Sistema SecurityForge Linux criado com sucesso!"
info "Localização: $ROOTFS_DIR"
info "Tamanho: $(du -sh "$ROOTFS_DIR" | cut -f1)"
info "Próximo passo: Executar create-iso-improved.sh para gerar ISO"

echo ""
header "🎯 SISTEMA CRIADO COM SUCESSO!"
echo "✅ Sistema Ubuntu 22.04 completo"
echo "✅ XFCE Desktop Environment"
echo "✅ Ferramentas de segurança instaladas"
echo "✅ Usuário 'secforge' configurado"
echo "✅ Wordlists básicas criadas"
echo "✅ Ambiente live configurado"
echo ""
echo "Execute agora: sudo ./admin/create-iso-improved.sh"