🛡️ InsiderShield: Threat Hunting & Resposta a Ameaças Internas com Wazuh

🚀 Monitoramento Avançado para Segurança Corporativa

🔍 Detecção de ameaças internas, movimentação lateral e abuso de privilégios em tempo real.

📌 Visão Geral

O InsiderShield é um projeto de Threat Hunting focado na detecção e resposta a ameaças internas dentro de um ambiente corporativo. Ele utiliza o Wazuh como SIEM, integrado a Sysmon e YARA, para fornecer uma análise detalhada dos eventos do sistema e detectar atividades maliciosa.


```bash
📦 InsiderShield
## 📦 Arquivos do Projeto

| Arquivo               | Tipo            | Descrição                                                                                          |
|-----------------------|-----------------|--------------------------------------------------------------------------------------------------|
| 🛡️ `auto-isolate.ps1` | Script PowerShell| Script para isolar automaticamente máquinas comprometidas, ativando resposta rápida.             |
| 📘 `local_rules.xml`   | Configuração    | Regras personalizadas do Wazuh focadas na detecção de ameaças internas e atividades suspeitas.   |
| 🖥️ `yara.bat`          | Script Batch    | Script para executar as regras YARA no ambiente de monitoramento local.                          |
| 🔍 `yara-rules.yar`    | Regras YARA     | Regras avançadas para identificar malwares fileless, scripts maliciosos e ataques sofisticados. |

```



| Ferramenta        | Função                                          |
|-------------------|-------------------------------------------------|
| 🔹 Wazuh         | SIEM para monitoramento e resposta a incidentes  |
| 🔹 Sysmon        | Coleta e análise detalhada de eventos no Windows |
| 🔹 YARA          | Regras para detecção de malware                  |
| 🔹 ELK Stack     | Visualização e análise dos alertas               |





Este projeto combina técnicas avançadas de detecção, correlação de eventos e automação de respostas para fortalecer a segurança corporativa.

## 🎯 Objetivos do Projeto

- Criar um framework de Threat Hunting para identificar ameaças internas  
- Implementar regras YARA para detecção em tempo real de malwares fileless  
- Automatizar respostas a incidentes isolando máquinas comprometidas  

📊 Monitoramento com Sysmon
O Sysmon captura atividades detalhadas do sistema, permitindo a identificação de comportamentos suspeitos.

Instalação do malware para dectecção com o sysmon

### Exemplo: Instalação do malware para teste de detecção

```powershell
cd C:\Users\Administrator\Downloads

Invoke-WebRequest -Uri https://github.com/NextronSystems/APTSimulator/archive/refs/heads/master.zip -OutFile APTSimulator.zip

cd .\APTSimulator\APTSimulator-master\

.\APTSimulator.bat
```


📌 Exemplo de evento detectado pelo Sysmon:

```bash
{ 
  "event_id": "1", 
  "image": "C:\\Windows\\System32\\PING.EXE", 
  "command_line": "C:\\Windows\\system32\\cmd.exe /c \"C:\\Users\\Administrator\\Downloads\\APTSimulator\\APTSimulator-master\\APTSimulator.bat\"", 
  "user": "Administrator",
  "rule.mitre.id": ["T1087", "T1059.003"]
}

```


🔍 Detecção Avançada com YARA
YARA é uma ferramenta essencial para análise de ameaças, permitindo a criação de regras personalizadas para detectar malwares fileless e scripts maliciosos, funcionando de forma offline e gratuita.


📌 Fluxo de detecção com YARA:
<img src="wazuh-imgs/wazuh-yara-events-flow1.png" alt="Fluxo de detecção com YARA" style="max-width: 100%;">



Teste de detecção com YARA - Malware EICAR


```bash
cd ~

Invoke-WebRequest -Uri https://secure.eicar.org/eicar_com.zip -OutFile eicar.zip

Expand-Archive .\eicar.zip

Copy-Item .\eicar\eicar.com C:\Users\Administrator\Downloads

```

<img src="wazuh-imgs/eicar01.png" alt="Detecção de Malware com YARA" style="max-width: 100%;">

<img src="wazuh-imgs/eicar02.png"> 


📝 Observações
Este projeto integra técnicas avançadas de detecção, correlação de eventos e automação para fortalecer a segurança contra ameaças internas em ambientes Windows.




 


 
