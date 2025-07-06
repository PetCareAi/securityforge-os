# 🛡️ SecurityForge Linux 3.1.0 - CyberNinja

## 📋 Visão Geral

**SecurityForge Linux** é uma distribuição especializada em segurança da informação baseada no Ubuntu 22.04 LTS, projetada especificamente para profissionais de segurança cibernética, pesquisadores, pentester e entusiastas de ethical hacking.

### 🎯 Características Principais

- **938+ Ferramentas Especializadas** organizadas em 15 categorias
- **Sistema Ultra-Hardened** com configurações avançadas de segurança
- **Ambiente de Laboratório Completo** para testes e pesquisa
- **Documentação Abrangente** e tutoriais integrados
- **Atualizações Automáticas** de ferramentas e wordlists
- **Interface Intuitiva** otimizada para trabalho técnico

## 🛠️ Ferramentas Incluídas (938+)

### RECONNAISSANCE (63 ferramentas)
**Prioridade:** CRITICAL  
**Descrição:** Ferramentas de reconhecimento, OSINT e coleta de informações

**Ferramentas principais:**
- `nmap`
- `masscan`
- `zmap`
- `rustscan`
- `unicornscan`
- `hping3`
- `ncat`
- `dmitry`
- `maltego`
- `recon-ng`
- ... e mais 53 ferramentas


**Localização:** `/opt/securityforge/tools/reconnaissance/`  
**Comando rápido:** `secforge-reconnaissance`

### VULNERABILITY SCANNERS (62 ferramentas)
**Prioridade:** CRITICAL  
**Descrição:** Scanners de vulnerabilidades e análise de segurança automatizada

**Ferramentas principais:**
- `nessus`
- `openvas`
- `greenbone-vulnerability-manager`
- `nikto`
- `w3af`
- `skipfish`
- `arachni`
- `vega`
- `nuclei`
- `jaeles`
- ... e mais 52 ferramentas


**Localização:** `/opt/securityforge/tools/vulnerability_scanners/`  
**Comando rápido:** `secforge-vulnerability_scanners`

### EXPLOITATION (71 ferramentas)
**Prioridade:** CRITICAL  
**Descrição:** Frameworks de exploração, desenvolvimento de payloads e post-exploitation

**Ferramentas principais:**
- `metasploit-framework`
- `msfvenom`
- `msfconsole`
- `armitage`
- `cobalt-strike`
- `empire`
- `powershell-empire`
- `covenant`
- `merlin`
- `sliver`
- ... e mais 61 ferramentas


**Localização:** `/opt/securityforge/tools/exploitation/`  
**Comando rápido:** `secforge-exploitation`

### NETWORK TOOLS (66 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Análise, monitoramento e manipulação de tráfego de rede

**Ferramentas principais:**
- `wireshark`
- `tshark`
- `tcpdump`
- `netcat`
- `socat`
- `ncat`
- `netstat`
- `ss`
- `netdiscover`
- `arp-scan`
- ... e mais 56 ferramentas


**Localização:** `/opt/securityforge/tools/network_tools/`  
**Comando rápido:** `secforge-network_tools`

### WEB TESTING (69 ferramentas)
**Prioridade:** CRITICAL  
**Descrição:** Ferramentas especializadas em testes de aplicações web e APIs

**Ferramentas principais:**
- `burpsuite`
- `burpsuite-pro`
- `owasp-zap`
- `caido`
- `portswigger-tools`
- `httpie`
- `curl`
- `wget`
- `webscarab`
- `paros`
- ... e mais 59 ferramentas


**Localização:** `/opt/securityforge/tools/web_testing/`  
**Comando rápido:** `secforge-web_testing`

### MALWARE ANALYSIS (75 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Análise de malware, engenharia reversa e análise de binários

**Ferramentas principais:**
- `radare2`
- `r2pipe`
- `ghidra`
- `ida-free`
- `ida-pro`
- `x64dbg`
- `x32dbg`
- `ollydbg`
- `immunity-debugger`
- `windbg`
- ... e mais 65 ferramentas


**Localização:** `/opt/securityforge/tools/malware_analysis/`  
**Comando rápido:** `secforge-malware_analysis`

### FORENSICS (74 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Ferramentas de investigação forense digital e análise de evidências

**Ferramentas principais:**
- `autopsy`
- `sleuthkit`
- `volatility3`
- `volatility2`
- `plaso`
- `log2timeline`
- `timesketch`
- `dftimewolf`
- `bulk-extractor`
- `photorec`
- ... e mais 64 ferramentas


**Localização:** `/opt/securityforge/tools/forensics/`  
**Comando rápido:** `secforge-forensics`

### CRYPTO PASSWORDS (72 ferramentas)
**Prioridade:** CRITICAL  
**Descrição:** Ferramentas de criptografia, quebra de senhas e análise de hashes

**Ferramentas principais:**
- `john`
- `john-jumbo`
- `hashcat`
- `hashcat-utils`
- `ophcrack`
- `rainbowcrack`
- `hydra`
- `thc-hydra`
- `medusa`
- `ncrack`
- ... e mais 62 ferramentas


**Localização:** `/opt/securityforge/tools/crypto_passwords/`  
**Comando rápido:** `secforge-crypto_passwords`

### WIRELESS (64 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Ferramentas para auditoria de redes sem fio e RF

**Ferramentas principais:**
- `aircrack-ng`
- `airmon-ng`
- `airodump-ng`
- `aireplay-ng`
- `airbase-ng`
- `airtun-ng`
- `packetforge-ng`
- `airserv-ng`
- `airolib-ng`
- `aircrack-ng-cuda`
- ... e mais 54 ferramentas


**Localização:** `/opt/securityforge/tools/wireless/`  
**Comando rápido:** `secforge-wireless`

### OSINT (59 ferramentas)
**Prioridade:** MEDIUM  
**Descrição:** Open Source Intelligence e investigação digital avançada

**Ferramentas principais:**
- `maltego`
- `maltego-transforms`
- `spiderfoot`
- `recon-ng`
- `osrframework`
- `twint`
- `twitter-scraper`
- `sherlock`
- `social-analyzer`
- `phoneinfoga`
- ... e mais 49 ferramentas


**Localização:** `/opt/securityforge/tools/osint/`  
**Comando rápido:** `secforge-osint`

### MOBILE (54 ferramentas)
**Prioridade:** MEDIUM  
**Descrição:** Ferramentas para análise de segurança em dispositivos móveis

**Ferramentas principais:**
- `android-sdk`
- `android-studio`
- `android-platform-tools`
- `apktool`
- `aapt`
- `dex2jar`
- `jadx`
- `jadx-gui`
- `mobsf`
- `qark`
- ... e mais 44 ferramentas


**Localização:** `/opt/securityforge/tools/mobile/`  
**Comando rápido:** `secforge-mobile`

### CLOUD SECURITY (64 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Ferramentas para auditoria e segurança em ambientes de nuvem

**Ferramentas principais:**
- `aws-cli`
- `aws-vault`
- `aws-nuke`
- `azure-cli`
- `gcloud`
- `gsutil`
- `kubectl`
- `helm`
- `kustomize`
- `skaffold`
- ... e mais 54 ferramentas


**Localização:** `/opt/securityforge/tools/cloud_security/`  
**Comando rápido:** `secforge-cloud_security`

### HARDWARE (47 ferramentas)
**Prioridade:** MEDIUM  
**Descrição:** Ferramentas para análise e hacking de hardware

**Ferramentas principais:**
- `arduino-ide`
- `platformio`
- `minicom`
- `screen`
- `picocom`
- `cutecom`
- `gtkterm`
- `putty`
- `buspirate`
- `openocd`
- ... e mais 37 ferramentas


**Localização:** `/opt/securityforge/tools/hardware/`  
**Comando rápido:** `secforge-hardware`

### DEVELOPMENT (45 ferramentas)
**Prioridade:** MEDIUM  
**Descrição:** IDEs e ferramentas de desenvolvimento para segurança

**Ferramentas principais:**
- `vscode`
- `code`
- `vim`
- `neovim`
- `emacs`
- `nano`
- `gedit`
- `kate`
- `sublime-text`
- `atom`
- ... e mais 35 ferramentas


**Localização:** `/opt/securityforge/tools/development/`  
**Comando rápido:** `secforge-development`

### MONITORING (53 ferramentas)
**Prioridade:** HIGH  
**Descrição:** Ferramentas de monitoramento, SIEM e análise de logs

**Ferramentas principais:**
- `elk-stack`
- `elasticsearch`
- `logstash`
- `kibana`
- `beats`
- `filebeat`
- `metricbeat`
- `heartbeat`
- `auditbeat`
- `packetbeat`
- ... e mais 43 ferramentas


**Localização:** `/opt/securityforge/tools/monitoring/`  
**Comando rápido:** `secforge-monitoring`


## 💻 Requisitos do Sistema

### Requisitos Mínimos
- **Processador:** x86_64 (64-bit)
- **RAM:** 4 GB
- **Armazenamento:** 5 GB livres
- **Rede:** Conexão com internet (para atualizações)

### Requisitos Recomendados
- **Processador:** Multi-core x86_64 (4+ cores)
- **RAM:** 8 GB ou mais
- **Armazenamento:** 50+ GB SSD
- **Rede:** Conexão banda larga
- **Virtualização:** Suporte a VT-x/AMD-V

### Compatibilidade
- **Hardware:** Laptops, desktops, servidores
- **Virtualização:** VMware, VirtualBox, KVM, Hyper-V
- **Cloud:** AWS, Azure, Google Cloud, DigitalOcean

## 🚀 Instalação

### Opção 1: ISO Bootável
1. **Download:** Baixe a ISO mais recente
2. **Gravação:** Use Rufus, Etcher ou dd para criar USB bootável
3. **Boot:** Inicialize pelo USB/DVD
4. **Instalação:** Siga o assistente de instalação

```bash
# Criar USB bootável no Linux
sudo dd if=SecurityForge-Linux-3.1.0-amd64.iso of=/dev/sdX bs=4M status=progress
```

### Opção 2: Máquina Virtual
1. **Criar VM:** Configure VM com requisitos mínimos
2. **Anexar ISO:** Configure ISO como dispositivo de boot
3. **Instalar:** Execute instalação normal
4. **Guest Additions:** Instale ferramentas de integração

### Opção 3: Build Personalizado
```bash
# Clonar repositório
git clone https://github.com/securityforge/securityforge-linux.git
cd securityforge-linux

# Executar builder
sudo node setup-distro-linux.js

# Criar ISO
sudo bash scripts/admin/create-iso.sh
```

## 🔑 Credenciais Padrão

### Usuário Principal
- **Usuário:** `secforge`
- **Senha:** `SecurityForge2024!`
- **Privilégios:** sudo para ferramentas de segurança

### Usuário Root
- **Usuário:** `root`
- **Senha:** (definir durante instalação)

> ⚠️ **Importante:** Altere as senhas padrão na primeira inicialização!

## 🎮 Primeiros Passos

### 1. Login Inicial
```bash
# Fazer login
Username: secforge
Password: SecurityForge2024!

# Verificar sistema
neofetch
secforge-status
```

### 2. Atualização do Sistema
```bash
# Atualizar tudo
sudo secforge-update

# Ou manualmente
sudo apt update && sudo apt upgrade -y
sudo /opt/securityforge/scripts/update-tools.sh
```

### 3. Configuração Inicial
```bash
# Configurar firewall
sudo /opt/securityforge/scripts/configure-ultra-firewall.sh

# Executar auditoria
sudo secforge-audit

# Fazer backup inicial
sudo secforge-backup
```

## 📚 Guias de Uso

### Reconhecimento e OSINT
```bash
# Suite de reconhecimento
secforge-reconnaissance

# Scan básico de rede
nmap -sn 192.168.1.0/24

# Enumerar subdomínios
subfinder -d target.com
amass enum -d target.com

# OSINT básico
sherlock username
theharvester -d target.com -b google
```

### Web Application Testing
```bash
# Suite de testes web
secforge-web_testing

# Burp Suite
burpsuite &

# Scan de vulnerabilidades web
nikto -h http://target.com
sqlmap -u "http://target.com/page?id=1"

# Directory bruteforce
gobuster dir -u http://target.com -w $WORDLISTS/web-directories.txt
```

### Wireless Security
```bash
# Suite wireless
secforge-wireless

# Monitorar redes
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon

# Capturar handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Crack WPA/WPA2
aircrack-ng -w $WORDLISTS/rockyou.txt capture-01.cap
```

### Password Cracking
```bash
# Suite de passwords
secforge-crypto_passwords

# John the Ripper
john --wordlist=$WORDLISTS/rockyou.txt hashes.txt

# Hashcat
hashcat -m 0 -a 0 hashes.txt $WORDLISTS/rockyou.txt

# Hydra
hydra -l admin -P $WORDLISTS/common-passwords.txt ssh://target.com
```

## 🔧 Comandos Úteis

### Navegação Rápida
```bash
# Ir para diretórios principais
cdtools          # /opt/securityforge/tools
cdwordlists      # /opt/securityforge/wordlists
cdworkspace      # /opt/securityforge/workspace
cdreports        # /opt/securityforge/reports
```

### Ferramentas de Sistema
```bash
# Status do sistema
secforge-status

# Atualizar ferramentas
secforge-update

# Auditoria de segurança
secforge-audit

# Backup do sistema
secforge-backup

# Monitorar firewall
sudo /opt/securityforge/scripts/firewall-monitor.sh
```

### Docker e Containers
```bash
# Container Kali Linux
docker run --rm -it -v $(pwd):/data kalilinux/kali-rolling

# Container Metasploit
docker run --rm -it -p 4444-4460:4444-4460 metasploitframework/metasploit-framework

# Container OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://target.com
```

## 🏗️ Estrutura de Diretórios

```
/opt/securityforge/
├── tools/              # Ferramentas organizadas por categoria
│   ├── reconnaissance/
│   ├── web_testing/
│   ├── exploitation/
│   └── ...
├── wordlists/          # Wordlists e dicionários
│   ├── rockyou.txt
│   ├── seclists/
│   └── ...
├── scripts/            # Scripts de automação
│   ├── admin/
│   ├── security/
│   └── ...
├── workspace/          # Área de trabalho
│   ├── pentest/
│   ├── forensics/
│   └── ...
├── reports/            # Relatórios gerados
├── configs/            # Configurações
└── docs/               # Documentação
```

## 🔒 Configurações de Segurança

### Firewall (UFW)
- **Status:** Ativo por padrão
- **Política:** Deny all incoming, allow outgoing
- **SSH:** Porta 2222 (personalizada)
- **Rate limiting:** Ativo para serviços críticos

### Fail2Ban
- **Status:** Ativo
- **Proteção:** SSH, HTTP, FTP, e outros serviços
- **Ban time:** 24 horas (progressivo)

### Kernel Hardening
- **ASLR:** Ativado (nível 2)
- **KASLR:** Ativado
- **SMEP/SMAP:** Ativado quando suportado
- **Proteção:** Stack canaries, NX bit

### AppArmor
- **Status:** Ativo
- **Profiles:** Ferramentas de segurança confinadas
- **Modo:** Enforce para serviços críticos

## 🎓 Laboratórios e Treinamento

### Ambientes de Prática
- **DVWA:** Damn Vulnerable Web Application
- **bWAPP:** buggy Web Application
- **WebGoat:** OWASP WebGoat
- **Metasploitable:** VM vulnerável para testes

### Cenários de CTF
- **OverTheWire:** Wargames online
- **VulnHub:** VMs vulneráveis
- **TryHackMe:** Plataforma de aprendizado
- **HackTheBox:** Laboratórios virtuais

## 🚨 Aviso Legal e Ética

> ⚠️ **IMPORTANTE:** Este sistema é destinado exclusivamente para:
> - Testes autorizados em sistemas próprios
> - Ambientes de laboratório controlados
> - Fins educacionais e de pesquisa
> - Avaliações de segurança com autorização

### Responsabilidades do Usuário
1. **Autorização:** Obter permissão explícita antes de testar qualquer sistema
2. **Legalidade:** Conhecer e respeitar as leis locais e internacionais
3. **Ética:** Seguir princípios de hacking ético
4. **Responsabilidade:** Usar conhecimento para melhorar a segurança

### Disclaimer
Os desenvolvedores do SecurityForge Linux não se responsabilizam pelo uso inadequado das ferramentas incluídas. O usuário é totalmente responsável por suas ações e deve garantir conformidade com todas as leis aplicáveis.

## 🤝 Comunidade e Suporte

### Recursos Oficiais
- **Website:** https://securityforge.org
- **Documentação:** https://docs.securityforge.org
- **GitHub:** https://github.com/securityforge/securityforge-linux
- **Discord:** https://discord.gg/securityforge

### Suporte Técnico
- **Issues:** GitHub Issues para bugs e solicitações
- **Discussions:** GitHub Discussions para dúvidas
- **Email:** security@securityforge.org

### Contribuições
Contribuições são bem-vindas! Veja nosso [Guia de Contribuição](CONTRIBUTING.md).

## 📈 Roadmap

### Versão Atual (3.1.0)
- ✅ 938+ ferramentas integradas
- ✅ Sistema ultra-hardened
- ✅ Documentação completa
- ✅ ISO bootável

### Próximas Versões
- 🔄 Interface gráfica aprimorada
- 🔄 Mais automação de testes
- 🔄 Integração com clouds
- 🔄 Mobile testing framework

## 📊 Estatísticas

- **Versão:** 3.1.0
- **Codinome:** CyberNinja
- **Base:** Ubuntu 22.04 LTS
- **Kernel:** Linux 5.15+
- **Categorias:** 15
- **Ferramentas:** 938+
- **Tamanho ISO:** ~4-6 GB
- **Instalação:** ~15-25 GB

---

**SecurityForge Linux 3.1.0** - Sua plataforma completa de segurança cibernética.

*"Forjando a segurança do futuro, uma linha de código por vez."*
