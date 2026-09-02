# Integração Wazuh -> SentryLens: visão geral e diagnóstico

## 1. Objetivo deste documento

Este documento descreve o caminho completo de um evento de segurança desde
que é gerado no controlador de domínio `NORTADA-DC01` até aparecer no
dashboard do SentryLens, regista uma limitação conhecida do ruleset base do
Wazuh que afeta vários Event IDs relevantes para o AD, e fornece um guia de
diagnóstico passo a passo para quando um evento esperado não chega ao
dashboard.

As regras Wazuh personalizadas e o excerto de configuração do agente
Windows para o canal Security já foram escritos, em
`wazuh/local_rules.xml` e `wazuh/ossec-agent-windows.conf` respetivamente
(ver secção 5 para o detalhe e para o que fica pendente); este documento
mantém-se focado na visão geral do caminho do evento e no guia de
diagnóstico.

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

Este ponto foi investigado até ao fim, por inspeção direta ao código-fonte
oficial do Wazuh (branch `4.14.9` do repositório `wazuh/wazuh`, ficheiros
`ruleset/rules/0580-win-security_rules.xml` e
`ruleset/rules/0955-WEF-baseline_rules.xml`), com verificação independente
por grep direto ao XML real feita por dois agentes distintos. Conclusão:
dos 19 Event IDs relevantes para este laboratório de AD, 17 já têm regra
própria no ruleset base e não precisam de qualquer regra local:

- `4720`/`4722` - criação/ativação de conta de utilizador -> regra `60109`
- `4725`/`4726` - desativação/eliminação de conta de utilizador -> regra `60111`
- `4728` - membro adicionado a grupo global -> regras `60141`/`60113`
- `4729` - membro removido de grupo global -> regras `60142`/`60113`
- `4732` - membro adicionado a grupo local -> regras `60144`/`60113`
- `4733` - membro removido de grupo local -> regras `60145`/`60113`
- `4738` - alteração de conta de utilizador -> regra `60110`
- `4740` - bloqueio de conta (account lockout) -> regra `60115`
- `4756` - membro adicionado a grupo universal -> regra `60151`
- `4757` - membro removido de grupo universal -> regra `60152`
- `4767` - desbloqueio de conta de utilizador -> regra `60133`
- `4624` - logon com sucesso -> regra `60106` (e outras)
- `4672` - atribuição de privilégios especiais -> regra `67028`
- `4688` - criação de processo -> regra `67027`
- `4698` - criação de tarefa agendada -> regra `60228`

Apenas dois Event IDs ficaram confirmados sem qualquer regra no ruleset
base, por grep exaustivo aos dois ficheiros acima:

- `4723` - tentativa de alteração de password pelo próprio utilizador
- `4724` - reset de password de outra conta feito por um administrador

Para cobrir exclusivamente estes dois casos foram escritas as regras
locais `100723` e `100724` (nível 3, a herdar de `if_sid 60103`, o mesmo
ponto da árvore de decisão onde estão penduradas as regras irmãs já
confirmadas no ruleset base acima), em `wazuh/local_rules.xml`. Sem essas
duas regras, um evento `4723` ou `4724` chega ao Wazuh Manager, não
corresponde a nenhuma regra existente, e é descartado antes do Indexer,
exatamente pela lógica descrita no parágrafo anterior.

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

A causa raiz desta limitação, hoje confirmada, restringe-se aos Event IDs
`4723` e `4724`: enquanto as regras `100723`/`100724` de
`wazuh/local_rules.xml` não estiverem aplicadas no Wazuh Manager real, a
ausência de regra (não a auditoria do Windows nem o backend do
SentryLens) é a causa de esses dois eventos não chegarem ao Indexer nem ao
dashboard. Para os restantes 17 Event IDs listados acima, esta causa não
se aplica: já têm regra própria garantida no ruleset base instalado por
omissão.

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
Manager, e confirmar que o `ossec.conf` do agente inclui o bloco de
`wazuh/ossec-agent-windows.conf` (canal `Security` com
`log_format eventchannel`): sem esse bloco, o agente pode estar `Running`
mas não estar a recolher o Security Event Log de todo.

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
aqui**, a interpretação depende do Event ID em causa, conforme a secção 3:

- Se for `4723` ou `4724`, a causa mais provável é a falta das regras
  `100723`/`100724` de `wazuh/local_rules.xml` no Manager: confirmar que o
  ficheiro foi copiado para `/var/ossec/etc/rules/local_rules.xml` e que o
  serviço `wazuh-manager` foi reiniciado depois disso.
- Se for um dos outros 17 Event IDs (todos já com regra própria
  confirmada no ruleset base), a falta de regra deixa de ser explicação
  plausível: a causa está noutro ponto, tipicamente rede, agente ou
  auditoria do Windows não corretamente aplicada, apesar de esta etapa vir
  depois de 4.1-4.3 já terem sido confirmados.

Em qualquer dos casos, é possível confirmar diretamente as regras
carregadas no Manager (ex.: `/var/ossec/bin/ossec-logtest` com uma amostra
do evento, ou inspeção dos ficheiros de regras em
`/var/ossec/ruleset/rules/` e `/var/ossec/etc/rules/local_rules.xml`) para
verificar se existe alguma regra que cubra o Event ID em causa.

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
| 4.4 Evento no Indexer (porta 9200) | Para `4723`/`4724`, `wazuh/local_rules.xml` não aplicado no Manager; para os outros 17 Event IDs (já cobertos no ruleset base), outra causa (rede, agente, auditoria) - ver secção 3 |
| 4.5 Backend SentryLens (`/api/alerts`) | Parâmetros da consulta em `wazuh_client.py` ou ligação backend-Indexer |
| 4.6 Frontend (`index.html`) | Lógica de apresentação ou consumo da API no dashboard |

## 5. O que fica pendente para um passo posterior

Este documento cobre a visão geral do caminho ponta a ponta, o
diagnóstico, e a investigação da secção 3. As regras Wazuh personalizadas
e o excerto de configuração do agente Windows já existem neste
repositório:

- `wazuh/local_rules.xml` - as duas regras locais `100723` e `100724`
  (nível 3, `if_sid 60103`) que cobrem os únicos dois Event IDs (`4723` e
  `4724`) sem regra própria no ruleset base, conforme a investigação da
  secção 3. O próprio ficheiro documenta, em comentário de topo, a
  investigação, a justificação do nível escolhido e o caminho de
  instalação.
- `wazuh/ossec-agent-windows.conf` - o bloco `<localfile>` com
  `log_format eventchannel` para o canal `Security`, a acrescentar ao
  `ossec.conf` do agente instalado em `NORTADA-DC01`, necessário para que
  os campos estruturados do evento (`TargetUserName`, `SubjectUserName`,
  etc.) cheguem com fiabilidade suficiente para as regras locais os
  usarem.

O que fica pendente é apenas a aplicação real destes dois ficheiros contra
um Wazuh Manager e um agente reais, nomeadamente:

- Copiar `wazuh/local_rules.xml` para
  `/var/ossec/etc/rules/local_rules.xml` no Wazuh Manager (192.168.1.143)
  e reiniciar o serviço (`systemctl restart wazuh-manager`) para as regras
  serem carregadas.
- Acrescentar o bloco de `wazuh/ossec-agent-windows.conf` ao `ossec.conf`
  do agente em `NORTADA-DC01` e reiniciar o serviço (`Restart-Service
  -Name WazuhSvc`).
- Gerar eventos de teste `4723` e `4724` reais (alteração de password
  pelo próprio utilizador e reset de password por um administrador) e
  validar, seguindo o guia da secção 4, que ambos aparecem no Indexer
  (`wazuh-alerts-*`) e no dashboard do SentryLens.

Nenhum destes três passos foi ainda executado: os ficheiros `wazuh/` têm
apenas sintaxe verificada localmente, não comportamento validado contra
uma instalação real. Até essa validação ser feita, `4723` e `4724`
continuam sujeitos à mesma limitação descrita na secção 3 caso as regras
locais não sejam efetivamente aplicadas no Manager. Os restantes 17 Event
IDs listados na secção 3 não dependem deste passo: já têm regra própria no
ruleset base instalado por omissão.
