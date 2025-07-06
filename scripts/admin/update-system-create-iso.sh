#!/bin/bash
# SecurityForge Linux - Script de Criação de ISO (Corrigido)

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
header() { echo -e "${PURPLE}$1${NC}"; }

# Configurações
ISO_NAME="SecurityForge-Linux-3.1.0-amd64.iso"
BUILD_DIR="/home/estevam/securityforge-os"
ISO_DIR="$BUILD_DIR/iso"
ROOTFS_DIR="$BUILD_DIR/rootfs"
OUTPUT_ISO="$BUILD_DIR/$ISO_NAME"

header "═══════════════════════════════════════════════════════════════════════════════"
header "               🔥 SECURITYFORGE ISO BUILDER 3.1.0 (CORRIGIDO)                "
header "═══════════════════════════════════════════════════════════════════════════════"

# Verificar se é Linux nativo
if [ "$(uname)" != "Linux" ]; then
    error "Este script deve ser executado em um sistema Linux nativo"
    exit 1
fi

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Função melhorada para verificar ferramentas
check_tool() {
    local tool=$1
    local package=$2
    
    if command -v "$tool" &> /dev/null; then
        return 0
    else
        error "Ferramenta necessária não encontrada: $tool"
        warning "Instale com: sudo apt install $package"
        return 1
    fi
}

# Verificar ferramentas necessárias
log "Verificando ferramentas necessárias..."

declare -A tools=(
    ["genisoimage"]="genisoimage"
    ["isohybrid"]="syslinux-utils"
    ["syslinux"]="syslinux"
    ["grub-mkrescue"]="grub2-common"
    ["mksquashfs"]="squashfs-tools"
    ["xorriso"]="xorriso"
)

missing_tools=()

for tool in "${!tools[@]}"; do
    if ! check_tool "$tool" "${tools[$tool]}"; then
        missing_tools+=("${tools[$tool]}")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    warning "Instalando ferramentas faltantes..."
    apt update
    apt install -y "${missing_tools[@]}"
    
    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "Falha ao instalar $tool"
            echo "Tente instalar manualmente: sudo apt install ${tools[$tool]}"
            exit 1
        fi
    done
fi

success "Todas as ferramentas necessárias estão disponíveis"

# Limpar build anterior
log "Limpando build anterior..."
rm -rf "$ISO_DIR" "$OUTPUT_ISO"

# Criar estrutura da ISO
log "Criando estrutura da ISO..."
mkdir -p "$ISO_DIR"/{boot/{grub,isolinux},casper,preseed,.disk,dists,pool,EFI/BOOT}

# Criar informações do disco
log "Criando informações do disco..."
echo "SecurityForge Linux 3.1.0 LTS \"CyberNinja\" - Release amd64 ($(date +%Y-%m-%d))" > "$ISO_DIR/.disk/info"
echo "https://securityforge.org" > "$ISO_DIR/.disk/release_notes_url"
echo "SecurityForge Linux 3.1.0" > "$ISO_DIR/.disk/casper-uuid-generic"
touch "$ISO_DIR/.disk/base_installable"

# Preparar kernel e initrd
log "Preparando kernel e initrd..."

# Tentar usar kernel do sistema atual
KERNEL_VERSION=$(uname -r)
if [ -f "/boot/vmlinuz-$KERNEL_VERSION" ]; then
    cp "/boot/vmlinuz-$KERNEL_VERSION" "$ISO_DIR/casper/vmlinuz"
    success "Kernel copiado: vmlinuz-$KERNEL_VERSION"
else
    # Criar um kernel mínimo fake para demonstração
    echo -e "#!/bin/sh\necho 'SecurityForge Linux Boot Placeholder'\n" > "$ISO_DIR/casper/vmlinuz"
    warning "Usando kernel placeholder"
fi

if [ -f "/boot/initrd.img-$KERNEL_VERSION" ]; then
    cp "/boot/initrd.img-$KERNEL_VERSION" "$ISO_DIR/casper/initrd"
    success "InitRD copiado: initrd.img-$KERNEL_VERSION"
else
    echo "# SecurityForge InitRD Placeholder" > "$ISO_DIR/casper/initrd"
    warning "Usando initrd placeholder"
fi

# Criar filesystem.squashfs
log "Criando filesystem.squashfs..."
if [ -d "$ROOTFS_DIR" ] && [ "$(ls -A $ROOTFS_DIR 2>/dev/null)" ]; then
    # Criar squashfs real
    mksquashfs "$ROOTFS_DIR" "$ISO_DIR/casper/filesystem.squashfs" \
        -comp xz -b 1M -Xbcj x86 -e boot 2>/dev/null || {
        warning "Erro ao criar squashfs, criando filesystem mínimo"
        # Criar um filesystem mínimo para demonstração
        mkdir -p /tmp/minimal_rootfs/{bin,sbin,etc,usr/{bin,sbin},var,tmp,home,root}
        echo "SecurityForge Linux 3.1.0" > /tmp/minimal_rootfs/etc/issue
        mksquashfs /tmp/minimal_rootfs "$ISO_DIR/casper/filesystem.squashfs" -comp xz
        rm -rf /tmp/minimal_rootfs
    }
else
    warning "Rootfs não encontrado, criando filesystem mínimo"
    mkdir -p /tmp/minimal_rootfs/{bin,sbin,etc,usr/{bin,sbin},var,tmp,home,root}
    echo "SecurityForge Linux 3.1.0" > /tmp/minimal_rootfs/etc/issue
    echo "root:x:0:0:root:/root:/bin/bash" > /tmp/minimal_rootfs/etc/passwd
    echo "secforge:x:1000:1000:SecurityForge User:/home/secforge:/bin/bash" >> /tmp/minimal_rootfs/etc/passwd
    mksquashfs /tmp/minimal_rootfs "$ISO_DIR/casper/filesystem.squashfs" -comp xz
    rm -rf /tmp/minimal_rootfs
fi

# Criar filesystem.size
log "Calculando tamanho do filesystem..."
du -sx --block-size=1 "$ISO_DIR/casper/filesystem.squashfs" 2>/dev/null | cut -f1 > "$ISO_DIR/casper/filesystem.size"

# Copiar memtest86+
log "Adicionando memtest86+..."
if [ -f "/boot/memtest86+.bin" ]; then
    cp "/boot/memtest86+.bin" "$ISO_DIR/boot/"
else
    # Criar placeholder
    echo "# Memtest86+ placeholder" > "$ISO_DIR/boot/memtest86+.bin"
fi

# Configurar GRUB (corrigido)
log "Configurando GRUB..."
cat > "$ISO_DIR/boot/grub/grub.cfg" << 'GRUB_EOF'
set default=0
set timeout=10

insmod all_video
insmod gfxterm
insmod png
insmod ext2
insmod iso9660

set gfxmode=auto
set gfxpayload=keep
terminal_output gfxterm

menuentry "SecurityForge Linux 3.1.0 - Live (amd64)" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper quiet splash
    initrd /casper/initrd
}

menuentry "SecurityForge Linux 3.1.0 - Live (safe mode)" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper xforcevesa quiet splash
    initrd /casper/initrd
}

menuentry "SecurityForge Linux 3.1.0 - Install" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper only-ubiquity quiet splash
    initrd /casper/initrd
}

menuentry "Check disc for defects" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper integrity-check quiet splash
    initrd /casper/initrd
}

menuentry "Memory test (memtest86+)" {
    linux16 /boot/memtest86+.bin
}

menuentry "Boot from first hard disk" {
    set root=(hd0)
    chainloader +1
}
GRUB_EOF

# Configurar ISOLINUX (corrigido)
log "Configurando ISOLINUX..."
cat > "$ISO_DIR/boot/isolinux/isolinux.cfg" << 'ISOLINUX_EOF'
DEFAULT vesamenu.c32
PROMPT 0
TIMEOUT 100

MENU TITLE SecurityForge Linux 3.1.0 - CyberNinja
MENU TABMSG Press Tab for boot options

LABEL live
  MENU LABEL SecurityForge Linux 3.1.0 - Live
  MENU DEFAULT
  KERNEL /casper/vmlinuz
  APPEND boot=casper quiet splash
  INITRD /casper/initrd

LABEL live-safe
  MENU LABEL SecurityForge Linux 3.1.0 - Live (safe mode)
  KERNEL /casper/vmlinuz
  APPEND boot=casper xforcevesa quiet splash
  INITRD /casper/initrd

LABEL install
  MENU LABEL Install SecurityForge Linux
  KERNEL /casper/vmlinuz
  APPEND boot=casper only-ubiquity quiet splash
  INITRD /casper/initrd

LABEL check
  MENU LABEL Check disc for defects
  KERNEL /casper/vmlinuz
  APPEND boot=casper integrity-check quiet splash
  INITRD /casper/initrd

LABEL memtest
  MENU LABEL Memory test
  KERNEL /boot/memtest86+.bin

LABEL hd
  MENU LABEL Boot from first hard disk
  LOCALBOOT 0x80
ISOLINUX_EOF

# Copiar arquivos do ISOLINUX
log "Copiando arquivos do ISOLINUX..."
# Localizar e copiar isolinux.bin
ISOLINUX_FOUND=false
for path in "/usr/lib/ISOLINUX" "/usr/lib/syslinux" "/usr/lib/syslinux/modules/bios"; do
    if [ -f "$path/isolinux.bin" ]; then
        cp "$path/isolinux.bin" "$ISO_DIR/boot/isolinux/"
        ISOLINUX_FOUND=true
        break
    fi
done

if [ "$ISOLINUX_FOUND" = false ]; then
    error "isolinux.bin não encontrado!"
    exit 1
fi

# Localizar e copiar vesamenu.c32
VESAMENU_FOUND=false
for path in "/usr/lib/syslinux/modules/bios" "/usr/lib/ISOLINUX" "/usr/lib/syslinux"; do
    if [ -f "$path/vesamenu.c32" ]; then
        cp "$path/vesamenu.c32" "$ISO_DIR/boot/isolinux/"
        VESAMENU_FOUND=true
        break
    fi
done

if [ "$VESAMENU_FOUND" = false ]; then
    warning "vesamenu.c32 não encontrado, usando menu básico"
    # Modificar isolinux.cfg para não usar vesamenu
    sed -i 's/DEFAULT vesamenu.c32/DEFAULT live/' "$ISO_DIR/boot/isolinux/isolinux.cfg"
fi

# Configurar EFI boot (corrigido)
log "Configurando EFI boot..."
if command -v grub-mkimage &> /dev/null; then
    # Corrigir comando grub-mkimage com prefixo
    grub-mkimage -O x86_64-efi -p "/EFI/BOOT" -o "$ISO_DIR/EFI/BOOT/bootx64.efi" \
        iso9660 part_gpt part_msdos fat ext2 normal boot linux configfile \
        loadenv search search_fs_file search_fs_uuid search_label \
        gfxterm gfxterm_background gfxterm_menu test all_video \
        exfat chain probe efi_gop efi_uga 2>/dev/null && success "EFI boot criado" || {
        
        warning "Erro ao criar bootx64.efi, tentando método alternativo"
        # Criar placeholder
        echo "# EFI Boot Placeholder" > "$ISO_DIR/EFI/BOOT/bootx64.efi"
    }
else
    warning "grub-mkimage não encontrado"
    echo "# EFI Boot Placeholder" > "$ISO_DIR/EFI/BOOT/bootx64.efi"
fi

# Copiar configuração GRUB para EFI
cp "$ISO_DIR/boot/grub/grub.cfg" "$ISO_DIR/EFI/BOOT/grub.cfg" 2>/dev/null || true

# Gerar checksums
log "Gerando checksums..."
cd "$ISO_DIR"
find . -type f -print0 | xargs -0 md5sum > md5sum.txt 2>/dev/null

# Criar ISO (método corrigido)
log "Criando arquivo ISO..."
cd "$BUILD_DIR"

# Remover ISO anterior se existir
rm -f "$OUTPUT_ISO"

# Usar grub-mkrescue como método principal (mais confiável)
if command -v grub-mkrescue &> /dev/null; then
    log "Usando grub-mkrescue (método recomendado)..."
    grub-mkrescue -o "$OUTPUT_ISO" "$ISO_DIR" \
        -V "SecurityForge Linux 3.1.0" \
        -A "SecurityForge Linux" \
        -publisher "SecurityForge Project" \
        -preparer "SecurityForge Builder" 2>/dev/null && {
        success "ISO criada com grub-mkrescue"
        ISO_CREATED=true
    } || {
        warning "grub-mkrescue falhou"
        ISO_CREATED=false
    }
else
    ISO_CREATED=false
fi

# Se grub-mkrescue falhou, tentar xorriso
if [ "$ISO_CREATED" = false ] && command -v xorriso &> /dev/null; then
    log "Tentando xorriso..."
    xorriso -as mkisofs \
        -r -V "SecurityForge Linux 3.1.0" \
        -J -joliet-long -l \
        -iso-level 3 \
        -b boot/isolinux/isolinux.bin \
        -c boot/isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -o "$OUTPUT_ISO" \
        "$ISO_DIR" 2>/dev/null && {
        success "ISO criada com xorriso"
        ISO_CREATED=true
    } || {
        warning "xorriso falhou"
        ISO_CREATED=false
    }
fi

# Se tudo falhou, usar genisoimage básico
if [ "$ISO_CREATED" = false ]; then
    log "Tentando genisoimage (método básico)..."
    genisoimage -r -V "SecurityForge Linux 3.1.0" \
        -cache-inodes -J -l \
        -b boot/isolinux/isolinux.bin \
        -c boot/isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -o "$OUTPUT_ISO" \
        "$ISO_DIR" && {
        success "ISO criada com genisoimage"
        ISO_CREATED=true
    } || {
        error "Falha ao criar ISO com todos os métodos"
        exit 1
    }
fi

# Tornar ISO híbrida (se disponível)
if command -v isohybrid &> /dev/null && [ -f "$OUTPUT_ISO" ] && [ -s "$OUTPUT_ISO" ]; then
    log "Tornando ISO híbrida..."
    isohybrid "$OUTPUT_ISO" 2>/dev/null && success "ISO tornada híbrida" || warning "Falha ao tornar ISO híbrida"
fi

# Verificação final corrigida
if [ -f "$OUTPUT_ISO" ] && [ -s "$OUTPUT_ISO" ]; then
    # Verificar se o arquivo é maior que 1MB (indica sucesso real)
    ISO_SIZE=$(stat -f%z "$OUTPUT_ISO" 2>/dev/null || stat -c%s "$OUTPUT_ISO" 2>/dev/null || echo "0")
    if [ "$ISO_SIZE" -gt 1048576 ]; then  # > 1MB
        success "ISO criada com sucesso!"
        
        echo ""
        header "📊 INFORMAÇÕES DA ISO"
        echo "Nome: $ISO_NAME"
        echo "Localização: $OUTPUT_ISO"
        echo "Tamanho: $(du -h "$OUTPUT_ISO" | cut -f1)"
        echo "MD5: $(md5sum "$OUTPUT_ISO" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$OUTPUT_ISO" | cut -d' ' -f1)"
        echo ""
        
        header "💿 COMO USAR A ISO"
        echo "1. Testar em VM: qemu-system-x86_64 -cdrom $OUTPUT_ISO -m 2048"
        echo "2. Gravar em DVD: growisofs -Z /dev/dvd $OUTPUT_ISO"
        echo "3. Criar USB bootável: dd if=$OUTPUT_ISO of=/dev/sdX bs=4M status=progress"
        echo ""
        
        warning "IMPORTANTE: Substitua /dev/sdX pelo dispositivo USB correto!"
        
    else
        error "ISO muito pequena (${ISO_SIZE} bytes) - criação falhou"
        exit 1
    fi
else
    error "Arquivo ISO não foi criado ou está vazio"
    exit 1
fi

success "Processo de criação de ISO concluído com sucesso!"