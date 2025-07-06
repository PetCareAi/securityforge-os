# ⚡ SecurityForge Linux - Guia Rápido

## 🚀 Início Imediato

### Login
```
Usuário: secforge
Senha: SecurityForge2024!
```

### Comandos Essenciais
```bash
# Status do sistema
neofetch
secforge-status

# Atualizar tudo
sudo secforge-update

# Auditoria de segurança
sudo secforge-audit

# Ver ferramentas por categoria
secforge-reconnaissance
secforge-web_testing
secforge-exploitation
```

## 🎯 Testes Rápidos

### Scan de Rede
```bash
# Descobrir hosts
nmap -sn 192.168.1.0/24

# Scan rápido
nmap -F target.com

# Scan completo
nmap -A -T4 target.com
```

### Web Testing
```bash
# Burp Suite
burpsuite &

# Nikto scan
nikto -h http://target.com

# Directory scan
gobuster dir -u http://target.com -w $WORDLISTS/web-directories.txt
```

### OSINT
```bash
# Subdomínios
subfinder -d target.com

# Informações de email
theharvester -d target.com -b google

# Usuário em redes sociais
sherlock username
```

## 📁 Localização das Ferramentas

```
/opt/securityforge/tools/     # Todas as ferramentas
/opt/securityforge/wordlists/ # Wordlists e dicionários
/opt/securityforge/workspace/ # Área de trabalho
```

## 🔑 Aliases Úteis

```bash
cdtools         # Ir para ferramentas
cdwordlists     # Ir para wordlists
cdworkspace     # Ir para workspace
ll              # ls -alF
```

## ⚠️ Importante

1. **Altere a senha padrão** na primeira inicialização
2. **Execute secforge-update** após instalação
3. **Use apenas em sistemas autorizados**
4. **Leia a documentação completa** em docs/README.md
