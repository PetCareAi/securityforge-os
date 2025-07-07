#!/bin/bash
# SecurityForge Linux - Criação de ISO Corrigida

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
WORK_DIR="/home/estevam/securityforge-os"
ROOTFS_DIR="$WORK_DIR/rootfs"
ISO_DIR="$WORK_DIR/iso"
OUTPUT_ISO="$WORK_DIR/SecurityForge-Linux-3.1.0-amd64-fixed.iso"

header "╔═══════════════════════════════════════════════════════════════════════════════╗"
header "║               🔥 SECURITYFORGE ISO BUILDER - FIXED VERSION                   ║"
header "╚═══════════════════════════════════════════════════════════════════════════════╝"

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Verificar se rootfs existe
if [ ! -d "$ROOTFS_DIR" ] || [ ! "$(ls -A $ROOTFS_DIR)" ]; then
    error "ROOTFS não encontrado! Execute primeiro: build-complete-system.sh"
    exit 1
fi

log "Removendo ISO anterior..."
rm -rf "$ISO_DIR" "$OUTPUT_ISO"

log "Criando estrutura da ISO..."
mkdir -p "$ISO_DIR"/{boot/{grub,isolinux},casper,.disk,EFI/BOOT}

# Informações do disco
log "Criando informações do disco..."
echo "SecurityForge Linux 3.1.0 LTS \"CyberNinja\" - Release amd64 ($(date +%Y-%m-%d))" > "$ISO_DIR/.disk/info"
echo "https://securityforge.org" > "$ISO_DIR/.disk/release_notes_url"
touch "$ISO_DIR/.disk/base_installable"

# Copiar kernel e initrd
log "Copiando kernel e initrd..."
KERNEL_VERSION=$(ls "$ROOTFS_DIR/boot/vmlinuz-"* 2>/dev/null | head -1 | sed 's/.*vmlinuz-//' || echo "")
if [ -n "$KERNEL_VERSION" ] && [ -f "$ROOTFS_DIR/boot/vmlinuz-$KERNEL_VERSION" ]; then
    cp "$ROOTFS_DIR/boot/vmlinuz-$KERNEL_VERSION" "$ISO_DIR/casper/vmlinuz"
    cp "$ROOTFS_DIR/boot/initrd.img-$KERNEL_VERSION" "$ISO_DIR/casper/initrd"
    success "Kernel copiado: $KERNEL_VERSION"
else
    error "Kernel não encontrado no rootfs!"
    exit 1
fi

# Criar squashfs
log "Criando filesystem.squashfs..."
mksquashfs "$ROOTFS_DIR" "$ISO_DIR/casper/filesystem.squashfs" \
    -comp xz -b 1M -Xbcj x86 -e boot -wildcards

# Calcular tamanho
du -sx --block-size=1 "$ROOTFS_DIR" | cut -f1 > "$ISO_DIR/casper/filesystem.size"

# Manifest
log "Criando manifest..."
chroot "$ROOTFS_DIR" dpkg-query -W --showformat='${Package} ${Version}\n' > "$ISO_DIR/casper/filesystem.manifest" 2>/dev/null || echo "# Empty manifest" > "$ISO_DIR/casper/filesystem.manifest"
cp "$ISO_DIR/casper/filesystem.manifest" "$ISO_DIR/casper/filesystem.manifest-desktop"

# Configurar GRUB com parâmetros seguros
log "Configurando GRUB..."
cat > "$ISO_DIR/boot/grub/grub.cfg" << 'GRUB_EOF'
set default=0
set timeout=10

loadfont unicode
set gfxmode=auto
set gfxpayload=keep
terminal_output gfxterm

menuentry "SecurityForge Linux 3.1.0 - Live Session" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper quiet splash nomodeset
    initrd /casper/initrd
}

menuentry "SecurityForge Linux 3.1.0 - Safe Graphics Mode" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper quiet splash nomodeset vga=normal
    initrd /casper/initrd
}

menuentry "SecurityForge Linux 3.1.0 - Debug Mode" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper debug=1 systemd.log_level=debug
    initrd /casper/initrd
}

menuentry "SecurityForge Linux 3.1.0 - Text Mode" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper text systemd.unit=multi-user.target
    initrd /casper/initrd
}

menuentry "Check disc for defects" {
    set gfxpayload=keep
    linux /casper/vmlinuz boot=casper integrity-check quiet splash
    initrd /casper/initrd
}

menuentry "Boot from first hard disk" {
    set root=(hd0)
    chainloader +1
}
GRUB_EOF

# Configurar ISOLINUX
log "Configurando ISOLINUX..."
cat > "$ISO_DIR/boot/isolinux/isolinux.cfg" << 'ISOLINUX_EOF'
DEFAULT vesamenu.c32
PROMPT 0
TIMEOUT 100

MENU TITLE SecurityForge Linux 3.1.0 - CyberNinja
MENU TABMSG Press Tab for boot options

LABEL live
  MENU LABEL SecurityForge Linux 3.1.0 - Live Session
  MENU DEFAULT
  KERNEL /casper/vmlinuz
  APPEND boot=casper quiet splash nomodeset
  INITRD /casper/initrd

LABEL safe
  MENU LABEL SecurityForge Linux 3.1.0 - Safe Graphics Mode
  KERNEL /casper/vmlinuz
  APPEND boot=casper quiet splash nomodeset vga=normal
  INITRD /casper/initrd

LABEL debug
  MENU LABEL SecurityForge Linux 3.1.0 - Debug Mode
  KERNEL /casper/vmlinuz
  APPEND boot=casper debug=1
  INITRD /casper/initrd

LABEL text
  MENU LABEL SecurityForge Linux 3.1.0 - Text Mode
  KERNEL /casper/vmlinuz
  APPEND boot=casper text systemd.unit=multi-user.target
  INITRD /casper/initrd

LABEL check
  MENU LABEL Check disc for defects
  KERNEL /casper/vmlinuz
  APPEND boot=casper integrity-check quiet splash
  INITRD /casper/initrd

LABEL hd
  MENU LABEL Boot from first hard disk
  LOCALBOOT 0x80
ISOLINUX_EOF

# Copiar arquivos ISOLINUX
log "Copiando arquivos ISOLINUX..."
for path in "/usr/lib/ISOLINUX" "/usr/lib/syslinux" "/usr/lib/syslinux/modules/bios"; do
    if [ -f "$path/isolinux.bin" ]; then
        cp "$path/isolinux.bin" "$ISO_DIR/boot/isolinux/"
        break
    fi
done

for path in "/usr/lib/syslinux/modules/bios" "/usr/lib/ISOLINUX" "/usr/lib/syslinux"; do
    if [ -f "$path/vesamenu.c32" ]; then
        cp "$path/vesamenu.c32" "$ISO_DIR/boot/isolinux/"
        break
    fi
done

# Configurar EFI
log "Configurando EFI boot..."
if command -v grub-mkimage &> /dev/null; then
    grub-mkimage -O x86_64-efi -p "/EFI/BOOT" -o "$ISO_DIR/EFI/BOOT/bootx64.efi" \
        iso9660 part_gpt part_msdos fat ext2 normal boot linux configfile \
        loadenv search search_fs_file search_fs_uuid search_label \
        gfxterm gfxterm_background gfxterm_menu test all_video efi_gop efi_uga 2>/dev/null || warning "EFI boot falhou"
fi

cp "$ISO_DIR/boot/grub/grub.cfg" "$ISO_DIR/EFI/BOOT/grub.cfg" 2>/dev/null || true

# Gerar checksums
log "Gerando checksums..."
cd "$ISO_DIR"
find . -type f -print0 | xargs -0 md5sum > md5sum.txt

# Criar ISO
log "Criando ISO..."
cd "$WORK_DIR"
grub-mkrescue -o "$OUTPUT_ISO" "$ISO_DIR" \
    -V "SecurityForge Linux 3.1.0" \
    -A "SecurityForge Linux" \
    -publisher "SecurityForge Project" \
    -preparer "SecurityForge Builder" 2>/dev/null || {
    
    warning "grub-mkrescue falhou, tentando xorriso..."
    xorriso -as mkisofs \
        -r -V "SecurityForge Linux 3.1.0" \
        -J -joliet-long -l \
        -iso-level 3 \
        -b boot/isolinux/isolinux.bin \
        -c boot/isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot \
        -e EFI/BOOT/bootx64.efi \
        -no-emul-boot \
        -o "$OUTPUT_ISO" \
        "$ISO_DIR" 2>/dev/null || {
        
        error "Falha ao criar ISO"
        exit 1
    }
}

# Tornar híbrida
if command -v isohybrid &> /dev/null; then
    isohybrid "$OUTPUT_ISO" 2>/dev/null || warning "Falha ao tornar híbrida"
fi

# Verificação final
if [ -f "$OUTPUT_ISO" ] && [ $(stat -c%s "$OUTPUT_ISO") -gt 50000000 ]; then
    success "ISO criada com sucesso!"
    
    echo ""
    header "📊 INFORMAÇÕES DA ISO"
    echo "Nome: SecurityForge-Linux-3.1.0-amd64-fixed.iso"
    echo "Localização: $OUTPUT_ISO"
    echo "Tamanho: $(du -h "$OUTPUT_ISO" | cut -f1)"
    echo "MD5: $(md5sum "$OUTPUT_ISO" | cut -d' ' -f1)"
    echo ""
    
    header "🛡️ OPÇÕES DE BOOT SEGURAS"
    echo "1. Live Session - Boot padrão com nomodeset"
    echo "2. Safe Graphics Mode - Para problemas de vídeo"
    echo "3. Debug Mode - Para diagnóstico"
    echo "4. Text Mode - Modo texto apenas"
    echo ""
    
    header "🧪 TESTAR A ISO"
    echo "QEMU: qemu-system-x86_64 -cdrom '$OUTPUT_ISO' -m 4096 -enable-kvm"
    echo "VirtualBox: Criar VM com 4GB RAM"
    echo ""
    
    success "SecurityForge Linux está pronto!"
else
    error "Falha ao criar ISO"
    exit 1
fi
