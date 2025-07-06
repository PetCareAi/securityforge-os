#!/bin/bash
# SecurityForge Linux - Configuração do Desktop

set -euo pipefail

log() { echo -e "\033[0;34m[$(date +'%H:%M:%S')]\033[0m $1"; }
success() { echo -e "\033[0;32m✅ $1\033[0m"; }

log "Configurando ambiente desktop SecurityForge..."

# Instalar XFCE como desktop principal
apt-get install -y xfce4 xfce4-goodies lightdm

# Configurar wallpaper personalizado
mkdir -p /opt/securityforge/assets
cat > /opt/securityforge/assets/set-wallpaper.sh << 'WALLPAPER_EOF'
#!/bin/bash
# Configurar wallpaper SecurityForge
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s /opt/securityforge/assets/wallpaper.jpg
WALLPAPER_EOF
chmod +x /opt/securityforge/assets/set-wallpaper.sh

# Criar atalhos no desktop
mkdir -p /home/secforge/Desktop

# Terminal
cat > /home/secforge/Desktop/Terminal.desktop << 'TERMINAL_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal
Comment=Terminal Emulator
Exec=xfce4-terminal
Icon=utilities-terminal
Path=
Terminal=false
StartupNotify=false
TERMINAL_EOF

# Burp Suite
cat > /home/secforge/Desktop/BurpSuite.desktop << 'BURP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Burp Suite
Comment=Web Application Security Testing
Exec=java -jar /opt/BurpSuite/burpsuite_community.jar
Icon=burpsuite
Path=
Terminal=false
StartupNotify=false
BURP_EOF

# SecurityForge Tools
cat > /home/secforge/Desktop/SecurityForge-Tools.desktop << 'TOOLS_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=SecurityForge Tools
Comment=Security Tools Collection
Exec=xfce4-terminal -e "bash -c 'ls /opt/securityforge/tools/; bash'"
Icon=folder
Path=/opt/securityforge/tools
Terminal=true
StartupNotify=false
TOOLS_EOF

# Configurar permissões
chown -R secforge:secforge /home/secforge/Desktop/
chmod +x /home/secforge/Desktop/*.desktop

success "Desktop configurado!"
