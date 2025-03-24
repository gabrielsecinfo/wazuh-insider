🛡️ InsiderShield: Threat Hunting & Resposta a Ameaças Internas com Wazuh

🚀 Monitoramento Avançado para Segurança Corporativa

🔍 Detecção de ameaças internas, movimentação lateral e abuso de privilégios em tempo real.

📌 Visão Geral

O InsiderShield é um projeto de Threat Hunting focado na detecção e resposta a ameaças internas dentro de um ambiente corporativo. Ele utiliza o Wazuh como SIEM, integrado a Sysmon e YARA, para fornecer uma análise detalhada dos eventos do sistema e detectar atividades maliciosas como:


```bash
📦 InsiderShield
 ┣ 📂 configs
 ┃ ┣ 📜 local_rules.xml          # Regras customizadas para insider threats
 ┃ ┣ 📜 sysmonconfig-export.xml  # Configuração detalhada do Sysmon
 ┃ ┣ 📜 yara-rules.yar           # Regras YARA para detectar malware fileless
 ┣ 📂 scripts
 ┃ ┣ 📜 auto-isolate.ps1      # Script para isolar máquina comprometida
 ┃ ┣ 📜 yara-scan.ps1          # Rodar YARA na memória RAM
```



| Ferramenta        | Função                                          |
|-------------------|-------------------------------------------------|
| 🔹 Wazuh         | SIEM para monitoramento e resposta a incidentes  |
| 🔹 Sysmon        | Coleta e análise detalhada de eventos no Windows |
| 🔹 YARA          | Regras para detecção de malware                  |
| 🔹 ELK Stack     | Visualização e análise dos alertas               |





Este projeto combina técnicas avançadas de detecção, correlação de eventos e automação de respostas para fortalecer a segurança corporativa.

🎯 Objetivos do Projeto

✔️ Criar um framework de Threat Hunting para detecção de ameaças internas

✔️ Implementar regras YARA para identificar malwares em tempo real

✔️ Automatizar respostas a incidentes, isolando máquinas comprometidas

📊 Monitoramento com Sysmon
O Sysmon permite capturar atividades detalhadas do sistema.

Instalação do malware para dectecção com o sysmon

```bash
> cd C:\Users\Administrator\Downloads

> Invoke-WebRequest -Uri https://github.com/NextronSystems/APTSimulator/archive/refs/heads/master.zip -OutFile APTSimulator.zip

>cd .\APTSimulator\APTSimulator-master\

> .\APTSimulator.bat

```


📌 Exemplo de Detecção:

```bash
{ 
  "event_id": "1", 
  "image": "C:\\Windows\\System32\\PING.EXE", 
  "command_line": C:\\Windows\\system32\\cmd.exe /c \"\"C:\\Users\\Administrator\\Downloads\\APTSimulator\\APTSimulator-master\\APTSimulator.bat\"\", 
  "user": "Administrator" 
  rule.mitre.id:T1087 T1059.003
}

```


📌 Arquivo de Configuração:
O Sysmon está configurado para capturar atividades maliciosas. Veja o arquivo de configuração completo aqui.










🔍 Detecção Avançada com YARA
O YARA é uma ferramenta essencial para análise de ameaças, permitindo a criação de regras customizadas para detecção de malware fileless, scripts maliciosos e ataques sofisticados. Diferente do VirusTotal, o YARA é 100% gratuito, funcionando de maneira similar, mas permitindo a análise offline.

📌 Processo do YARA:
<img src="wazuh-imgs/wazuh-yara-events-flow1.png" alt="Fluxo de detecção com YARA" style="max-width: 100%;">



Instalação de Malware para Validar o Monitoramento do YARA: 


Agora instalação de malware para validar o monitoramento do YARA.

```bash
 cd ~

> Invoke-WebRequest -Uri https://secure.eicar.org/eicar_com.zip -OutFile eicar.zip

> Expand-Archive .\eicar.zip

> cp .\eicar\eicar.com C:\Users\Administrator\Downloads

```

<img src="wazuh-imgs/eicar01.png" alt="Detecção de Malware com YARA" style="max-width: 100%;">

<img src="wazuh-imgs/eicar02.png"> 





 


 
