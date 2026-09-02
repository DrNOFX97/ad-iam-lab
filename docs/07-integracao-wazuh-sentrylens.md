# Integração Wazuh -> SentryLens: visão geral e diagnóstico

## 1. Objetivo deste documento

Este documento descreve o caminho completo de um evento de segurança desde
que é gerado no controlador de domínio `NORTADA-DC01` até aparecer no
dashboard do SentryLens, regista uma limitação conhecida do ruleset base do
Wazuh que afeta vários Event IDs relevantes para o AD, e fornece um guia de
diagnóstico passo a passo para quando um evento esperado não chega ao
dashboard.

Não cobre a criação de regras Wazuh personalizadas nem o excerto de
configuração do agente Windows para o canal Security: isso é trabalho de um
passo posterior, ver secção 4.

Os factos de arquitetura usados aqui (IPs, portas, nomes de VM) seguem
exatamente o que está definido em
[`01-arquitetura.md`](01-arquitetura.md) e não são repetidos com
variações: `NORTADA-DC01` (192.168.1.150), Wazuh Manager em 192.168.1.143
(API de gestão na porta 55000, portas de agente 1514 e 1515), Wazuh
Indexer/OpenSearch na mesma VM .143 (porta 9200), backend do SentryLens no
Windows anfitrião na porta 8001, dashboard estático `index.html`.

## 2. O caminho completo do evento

```
1. NORTADA-DC01 (192.168.1.150)
   Windows Security Event Log
   |
   | evento gerado (ex.: logon, criação de conta, alteração de grupo)
   v
2. Agente Wazuh instalado no DC
   le o Security Event Log e envia para o Manager
   |
   | portas 1514 (dados) / 1515 (registo do agente)
   v
3. Wazuh Manager (192.168.1.143)
   avalia o evento contra o ruleset (regras base + eventuais regras locais)
   API de gestao na porta 55000
   |
   | se alguma regra corresponder, gera um alerta e indexa
   v
4. Wazuh Indexer / OpenSearch (192.168.1.143, porta 9200)
   guarda o alerta no indice wazuh-alerts-*
   |
   | consulta HTTP
   v
5. Backend SentryLens (Windows anfitriao, porta 8001)
   scripts/wazuh_client.py: WazuhManagerClient fala com a API 55000
   (agentes, estado do manager); WazuhIndexerClient faz _search a
   wazuh-alerts-* na porta 9200 (alertas recentes, estatisticas)
   scripts/event_catalog.py classifica o win_event_id de cada alerta
   devolvido (nome, severidade, recomendacao)
   |
   | endpoints REST, ex.: GET /api/alerts, GET /api/agents, GET /api/stats
   v
6. Dashboard SentryLens (index.html)
   consome os endpoints do backend e apresenta os paineis ao utilizador
```

Ponto crítico deste caminho: o passo 3 é um filtro, não uma passagem
direta. Um evento só chega ao Indexer (passo 4) se alguma regra do
ruleset do Wazuh Manager disparar sobre ele. Um evento que existe no
Security Event Log do DC e chega ao Manager mas para o qual não há regra
correspondente é descartado nesse ponto: nunca é indexado, nunca aparece
na API 9200, e portanto nunca chega ao backend do SentryLens nem ao
dashboard, mesmo que a auditoria do Windows no DC esteja corretamente
configurada.

## 3. Limitação conhecida: cobertura do ruleset base para eventos de AD

O ruleset base que acompanha uma instalação padrão do Wazuh foi desenhado
para cobrir os cenários mais comuns (logon falhado, escalada de
privilégios, alterações de política) mas não tem regra própria para todos
os Event IDs de auditoria de objetos do Active Directory. Sem uma regra
que corresponda ao Event ID (e tipicamente ao decoder correto para o
formato do Windows Eventlog), o Wazuh Manager recebe o evento, não o
associa a nenhuma regra, e não gera alerta: o evento não é indexado.

Event IDs relevantes para o laboratório de AD que estão em risco de não
ter regra própria no ruleset base (a confirmar caso a caso; a lista
definitiva de quais já têm cobertura e quais não faz parte do trabalho
futuro descrito na secção 4):

- `4720` - criação de conta de utilizador
- `4722` - ativação de conta de utilizador
- `4723` - tentativa de alteração de password
- `4724` - tentativa de reset de password
- `4725` - desativação de conta de utilizador
- `4728` - membro adicionado a grupo global
- `4729` - membro removido de grupo global
- `4732` - membro adicionado a grupo local
- `4733` - membro removido de grupo local
- `4738` - alteração de conta de utilizador
- `4740` - bloqueio de conta (account lockout)
- `4756` - membro adicionado a grupo universal
- `4757` - membro removido de grupo universal
- `4767` - desbloqueio de conta de utilizador

Além destes, alguns comportamentos específicos de `4624` (logon com
sucesso), `4672` (atribuição de privilégios especiais), `4688` (criação de
processo) e `4698` (criação de tarefa agendada) também podem não ter regra
correspondente consoante o contexto exato em que ocorrem, mesmo que estes
Event IDs, de um modo geral, tenham cobertura mais provável no ruleset
base do que os de gestão de contas e grupos listados acima.

Nota sobre o código do SentryLens: `scripts/event_catalog.py` já contém
lógica de classificação (nome, severidade, recomendação) para vários
destes Event IDs, incluindo `4720`, `4722`, `4723`, `4724`, `4728`, `4732`
e `4738`. Isto significa que o backend e o dashboard já sabem o que fazer
com um alerta destes tipos se ele chegar, mas essa classificação só é
executada sobre alertas que já existem no índice `wazuh-alerts-*`. Se o
Wazuh Manager nunca gerar o alerta por falta de regra, o `classify_alert`
correspondente nunca é chamado, o alerta nunca aparece em
`GET /api/alerts`, e o dashboard não mostra nada, mesmo que o evento
tenha ocorrido e esteja registado no Security Event Log do DC.

A causa raiz desta limitação não é a auditoria do Windows nem o backend do
SentryLens: é a ausência de regras específicas no Wazuh Manager para estes
Event IDs.

## 4. Diagnóstico: onde procurar quando um evento esperado não aparece

Percorrer as etapas pela ordem do caminho do evento (secção 2), a começar
na origem. Parar na primeira etapa onde o evento não é encontrado: essa é
a etapa com o problema.

### 4.1 Confirmar que o evento existe no DC (Event Viewer)

No `NORTADA-DC01`, verificar o Security log para o Event ID esperado:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 20
```

Ou, para uma janela temporal específica:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=(Get-Date).AddHours(-1)}
```

Se o evento **não aparece aqui**, o problema é a Advanced Audit Policy no
DC: a subcategoria de auditoria relevante (ex.: "Audit User Account
Management" para 4720/4722/4738, "Audit Security Group Management" para
4728/4732/4756) não está ativada, ou a GPO que a define não foi aplicada.
Confirmar com:

```powershell
auditpol /get /category:*
```

### 4.2 Confirmar que o serviço do agente Wazuh está a correr no DC

```powershell
Get-Service WazuhSvc
```

Se o serviço não está `Running`, o agente não está a ler nem a enviar
nada, independentemente de o evento existir no Event Viewer. Verificar
também o log do agente
(`C:\Program Files (x86)\ossec-agent\ossec.log`) para erros de ligação ao
Manager.

### 4.3 Confirmar que o agente está ativo no Wazuh Manager

Na VM Wazuh (192.168.1.143), via SSH:

```bash
/var/ossec/bin/agent_control -l
```

ou, se a versão instalada usar o binário mais recente:

```bash
/var/ossec/bin/manage_agents -l
```

Alternativamente, consultar a lista de agentes no próprio Wazuh Dashboard
(secção Agents) ou o endpoint `GET /api/agents` do backend do SentryLens
(porta 8001), que consulta a API de gestão do Manager na porta 55000.

Se o evento aparece no Event Viewer (4.1) mas o agente não aparece como
`Active` aqui, o problema é de rede, porta ou registo do agente: confirmar
que as portas 1514 e 1515 estão acessíveis do DC (192.168.1.150) até
192.168.1.143 (ex.: `Test-NetConnection 192.168.1.143 -Port 1514` a partir
do DC) e que o agente foi corretamente registado no Manager.

### 4.4 Confirmar se o evento chegou ao Indexer

Consulta direta à API do Indexer (porta 9200) na VM Wazuh, filtrando por
Event ID e janela temporal:

```bash
curl -k -u <utilizador>:<password> \
  "https://192.168.1.143:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 10,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {
      "bool": {
        "must": [
          {"match": {"data.win.system.eventID": "4720"}},
          {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]
      }
    }
  }'
```

Se o agente está `Active` no Manager (4.3) mas o evento **não aparece
aqui**, o problema é, muito provavelmente, falta de regra no ruleset para
esse Event ID: exatamente a limitação descrita na secção 3. Confirmar
consultando as regras carregadas no Manager (ex.:
`/var/ossec/bin/ossec-logtest` com uma amostra do evento, ou inspeção dos
ficheiros de regras em `/var/ossec/ruleset/rules/`) para verificar se
existe alguma regra que cubra o Event ID em causa.

### 4.5 Confirmar que o backend do SentryLens obtém o dado

Com o backend a correr no Windows anfitrião (porta 8001):

```bash
curl "http://localhost:8001/api/alerts?hours=1"
```

ou, para verificar primeiro que o backend está de pé e a falar com o
Wazuh:

```bash
curl "http://localhost:8001/api/health"
curl "http://localhost:8001/api/agents"
```

Se o evento está confirmado no Indexer (4.4) mas não aparece na resposta
de `/api/alerts`, o problema está na consulta feita por
`scripts/wazuh_client.py` (ex.: janela `hours` demasiado curta, filtro
`min_level` a excluir o alerta, nome de índice incorreto) ou num erro de
autenticação/ligação entre o backend e o Indexer, visível nos logs do
próprio backend.

### 4.6 Confirmar no frontend

Com o backend a responder corretamente em `/api/alerts` (4.5), abrir
`index.html` e verificar se o evento aparece no painel correspondente. Se
não aparecer aqui apesar de a API responder com o dado, o problema é do
lado do frontend (filtros aplicados na interface, erro de JavaScript ao
consumir a resposta, cache do browser): inspecionar a consola do browser e
os pedidos de rede feitos a `http://localhost:8001`.

### 4.7 Resumo do diagnóstico

| Etapa | Se falhar aqui, o problema é |
|---|---|
| 4.1 Event Viewer do DC | Advanced Audit Policy / GPO de auditoria não aplicada |
| 4.2 Serviço `WazuhSvc` no DC | Agente Wazuh parado ou mal instalado no DC |
| 4.3 Agente ativo no Manager | Rede, porta (1514/1515) ou registo do agente no Manager |
| 4.4 Evento no Indexer (porta 9200) | Falta de regra no ruleset do Wazuh Manager para o Event ID (ver secção 3) |
| 4.5 Backend SentryLens (`/api/alerts`) | Parâmetros da consulta em `wazuh_client.py` ou ligação backend-Indexer |
| 4.6 Frontend (`index.html`) | Lógica de apresentação ou consumo da API no dashboard |

## 5. O que fica pendente para um passo posterior

Este documento cobre apenas a visão geral do caminho ponta a ponta e o
guia de diagnóstico. Ficam explicitamente fora de âmbito, para um passo
posterior deste mesmo repositório:

- As regras Wazuh personalizadas (`wazuh/local_rules.xml`, ainda não
  existe) necessárias para cobrir os Event IDs de gestão de contas e
  grupos do AD listados na secção 3, que não têm regra própria garantida
  no ruleset base.
- O excerto de configuração do agente Windows (`wazuh/ossec-agent-windows.conf`,
  ainda não existe) para garantir a recolha correta do canal Security no
  agente instalado em `NORTADA-DC01`.
- A lista definitiva e verificada, Event ID a Event ID, de quais já têm
  cobertura no ruleset base do Wazuh instalado em 192.168.1.143 e quais
  precisam efetivamente de regra personalizada. A lista da secção 3 é uma
  lista de risco baseada em conhecimento geral do ruleset base do Wazuh,
  não uma verificação feita contra a instalação real desta VM.

Até essas regras serem escritas e validadas contra o Manager real, a
limitação descrita na secção 3 deve ser considerada ativa: é expectável
que criações de conta, alterações de grupo e outras operações de gestão
de identidades no AD gerem eventos no DC que não chegam a aparecer no
dashboard do SentryLens, apesar de a arquitetura de rede e a auditoria do
Windows estarem corretamente configuradas.
