# 🛡️ NETWATCH — Central de Monitoramento de Rede
### Sistema Profissional de Segurança de Redes v2.1

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B.svg)](https://streamlit.io/)
[![Firebase](https://img.shields.io/badge/Firebase-FCM-orange.svg)](https://firebase.google.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

> **NetWatch** é uma solução tática avançada para monitoramento, inventário e segurança de redes locais, agora com integração nativa para notificações push via Android.

---

## 📋 Visão Geral

Projetado para ambientes de alta criticidade, o NetWatch oferece uma visão 360° da infraestrutura de rede, permitindo identificar ameaças em tempo real e gerir dispositivos com precisão cirúrgica.

### Principais Diferenciais:
- **Monitoramento Ativo:** Descoberta contínua com `nmap`.
- **Inteligência de Risco:** Scoring automático baseado em comportamento e portas abertas.
- **Alertas Móveis:** Integração com Firebase (FCM) para notificações instantâneas em dispositivos Android.
- **Relatórios Executivos:** Geração de PDFs oficiais para auditoria e conformidade.

---

## 🚀 Novidades na v2.1
- **Módulo de Mensageria:** Suporte a Firebase Cloud Messaging.
- **Client Android (Beta):** Service worker em Kotlin para recebimento de alertas críticos no celular.
- **Interface Tática:** Refinamento dos dashboards de segurança.

---

## ⚙️ Instalação e Setup

### 1. Requisitos do Sistema
```bash
# Arch Linux
sudo pacman -S nmap python python-pip

# Ubuntu/Debian
sudo apt install nmap python3 python3-pip python3-venv
```

### 2. Ambiente Python
```bash
# Criar e ativar ambiente
python -m venv .venv
source .venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

### 3. Configuração do Firebase (Opcional para Alertas)
1. Crie um projeto no [Firebase Console](https://console.firebase.google.com/).
2. Vá em **Configurações do Projeto > Contas de Serviço**.
3. Gere uma nova chave privada JSON.
4. Salve o arquivo como `firebase-credentials.json` na raiz deste projeto.

### 4. Execução
```bash
streamlit run app.py
```

---

## 📱 Integração Android
O projeto inclui componentes para um aplicativo Android que recebe os alertas do NetWatch:
- `NetwatchFCMService.kt`: Serviço de background para processar notificações.
- `AndroidManifest.xml.example`: Configurações de permissões e serviços.
- `build.gradle.kts.example`: Dependências necessárias para o build Android.

---

## 🗂️ Estrutura do Projeto
```text
.
├── app.py                  # Dashboard Principal (Streamlit)
├── messaging.py            # Motor de notificações (Firebase FCM)
├── netwatch_config.json    # Configurações de sistema e org
├── requirements.txt        # Dependências Python
├── NetwatchFCMService.kt   # Implementação Android (Kotlin)
├── AndroidManifest.xml.example
├── README.md               # Você está aqui
└── .gitignore              # Proteção de dados sensíveis e envs
```

---

## 🛠️ Tecnologias Utilizadas
- **Backend/UI:** Streamlit & Python
- **Network Engine:** Nmap (via subprocess/python-nmap)
- **Data:** Pandas para processamento de logs
- **Mobile:** Kotlin & Firebase Cloud Messaging
- **Reports:** ReportLab (PDF Generation)

---

## 🔐 Segurança e Uso Ético
**IMPORTANTE:** O uso deste software em redes de terceiros sem autorização explícita é ilegal. O desenvolvedor não se responsabiliza por usos indevidos. Este sistema foi criado para auditoria e proteção de infraestrutura própria.

---

## 🏆 Créditos e Desenvolvimento

Este projeto é mantido e desenvolvido por:

*   **Willian Albarellos** ([@walbarellos](https://github.com/walbarellos)) — *Arquiteto de Soluções & Lead Developer*

### Colaboradores e Inspirações:
- Equipe de Segurança de Redes - Central de Monitoramento
- Comunidade Open Source (Nmap, Streamlit, Firebase)

---

## 📞 Contato
Para suporte institucional ou parcerias, entre em contato via repositório oficial no GitHub.

*NetWatch v2.1 — Security & Intelligence*
