# 🛡️ NETWATCH — Central de Monitoramento de Rede
### Sistema Profissional de Segurança de Redes v2.0

> Desenvolvido para ambientes de segurança pública, forças policiais e órgãos de segurança.

---

## 📋 Visão Geral

O **NetWatch** é uma central de monitoramento de rede local com interface tática profissional, projetada para:

- **Descoberta e inventário** de todos os dispositivos na rede
- **Classificação de ameaças** com scoring automático de risco
- **Gestão de dispositivos** (Conhecido / Suspeito / Bloqueado)
- **Log de eventos** com níveis CRÍTICO / ALTO / MÉDIO / BAIXO / INFO
- **Scan de portas e serviços** com identificação de vulnerabilidades
- **Relatórios PDF oficiais** com dados da organização
- **Exportação CSV/JSON** para integração com outros sistemas

---

## ⚙️ Instalação

### Pré-requisitos

```bash
# Arch Linux
sudo pacman -S nmap python python-pip

# Ubuntu/Debian
sudo apt install nmap python3 python3-pip python3-venv
```

### Configurar ambiente

```bash
mkdir -p ~/netwatch && cd ~/netwatch

# Copie app.py e requirements.txt para este diretório

python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Executar

```bash
source .venv/bin/activate
streamlit run app.py --server.port 8501 --server.address localhost
```

Acesse em: **http://localhost:8501**

---

## 🗂️ Estrutura de Arquivos

```
~/netwatch/
├── app.py                   # Aplicação principal
├── requirements.txt         # Dependências
├── netwatch_db.json         # Banco de dados de dispositivos (gerado automaticamente)
├── netwatch_events.json     # Log de eventos (gerado automaticamente)
├── netwatch_config.json     # Configurações (gerado automaticamente)
└── README.md
```

---

## 🖥️ Funcionalidades por Aba

### ⬡ Dashboard
- Métricas em tempo real (Online, Desconhecidos, Suspeitos, Bloqueados)
- Tabela de dispositivos ativos com classificação de risco
- Distribuição visual de níveis de ameaça
- Feed de eventos recentes
- Mapa de vendors detectados

### 🖥 Dispositivos
- Gerenciamento completo de cada dispositivo
- Classificação: Conhecido / Suspeito / Bloqueado
- Categorização (Servidor, Câmera IP, IoT, etc.)
- Notas por operador com timestamp
- Scan de portas individual por dispositivo
- Risk score automático (0–100)

### 🚨 Eventos
- Log completo com filtros por nível
- Exportação CSV
- Contagem por categoria de ameaça

### 🔌 Portas & Serviços
- Inventário completo de portas abertas em toda a rede
- Identificação de serviços de risco (Telnet, RDP, SMB, etc.)
- Gráfico de portas mais frequentes

### 📋 Relatórios
- **Relatório PDF oficial** com dados da organização
- Exportação CSV/JSON de dispositivos
- Backup completo do banco de dados
- Checklist de hardening de rede (14 itens)

### ⚙ Configurações
- Dados da organização e operador (usados no PDF)
- Configurações de alertas
- Informações do sistema
- Reset de dados

---

## 🔐 Segurança e Uso Ético

**IMPORTANTE:** Este sistema deve ser utilizado **exclusivamente em redes de propriedade ou sob responsabilidade legal da organização operadora**.

- Execute scans somente em redes autorizadas
- Documente o uso conforme procedimentos internos
- Proteja os arquivos de dados gerados (contêm informações sensíveis)
- Restrinja o acesso ao servidor Streamlit (não exponha na internet)

Para uso em produção, recomenda-se:
```bash
# Restringir acesso somente ao localhost
streamlit run app.py --server.address 127.0.0.1

# Ou configurar via SSH tunnel para acesso remoto seguro
ssh -L 8501:localhost:8501 usuario@servidor-seguro
```

---

## 🚀 Roadmap de Melhorias Futuras

| Feature | Descrição | Prioridade |
|---|---|---|
| Integração OpenVAS | Scan de CVEs via Greenbone | Alta |
| Notificações Telegram/Email | Alertas em tempo real | Alta |
| Timeline gráfica | Histórico visual de presença | Média |
| Detecção de ARP Spoofing | Identificação de man-in-the-middle | Alta |
| Mapa de topologia visual | Grafo de conexões com D3.js | Média |
| Integração SNMP | Polling de switches/roteadores | Média |
| API REST | Integração com SIEM externo | Baixa |
| Autenticação de operadores | Login multi-usuário | Alta |
| Modo quiosque | Dashboard somente leitura para monitores | Baixa |

---

## 📞 Suporte

Para dúvidas sobre configuração ou uso em ambiente institucional, consulte o responsável técnico de segurança da informação da sua organização.

---

*NetWatch v2.0 — Sistema de uso institucional — Todos os scans são registrados*
