# Política de auditoria avançada (Advanced Audit Policy)

## 1. Objetivo

Este documento descreve a Advanced Audit Policy a ativar no Controlador de
Domínio `NORTADA-DC01`, pelo script futuro `05-Set-AuditPolicy.ps1`. O
propósito desta política não é genérico: é gerar, no Windows Security
Event Log, exatamente os eventos que o agente Wazuh já instalado neste DC
vai recolher e enviar para o Wazuh Manager (192.168.1.143), para que o
SentryLens tenha eventos reais de gestão de identidades para apresentar
(criação de utilizadores, alterações a grupos, logons falhados, bloqueios
de conta, elevação de privilégios).

Sem esta política ativada, o Windows regista por omissão um subconjunto
muito mais pequeno de eventos de segurança, insuficiente para os cenários
de deteção que o SentryLens se propõe a demonstrar.

## 2. Categorias e subcategorias a ativar

O script `05-Set-AuditPolicy.ps1` configura, no mínimo, as seguintes
subcategorias da Advanced Audit Policy (via `auditpol /set`), todas ao
nível do DC (aplicam-se também por GPO de Default Domain Controllers
Policy, para garantir que a configuração sobrevive a uma eventual
reconstrução do DC):

| Categoria | Subcategoria | Sucesso | Falha | Motivo |
|---|---|---|---|---|
| Account Management | User Account Management | Sim | Sim | Cobre criação, modificação, ativação/desativação e eliminação de contas de utilizador (Event IDs 4720 criação, 4722 ativação, 4723/4724 alteração de password, 4725 desativação, 4726 eliminação, 4738 alteração de atributos). Central para os processos de onboarding e offboarding descritos em `05-onboarding-offboarding.md`. |
| Account Management | Security Group Management | Sim | Sim | Cobre criação de grupos e alterações de pertença (Event IDs 4727/4731 criação de grupo, 4728/4732 adição de membro, 4729/4733 remoção de membro, 4730/4734 eliminação de grupo). Essencial para detetar desvios de privilégios face ao modelo RBAC descrito em `06-rbac.md`, por exemplo uma adição não autorizada a `Domain Admins`. |
| Logon/Logoff | Logon | Sim | Sim | Cobre logons bem-sucedidos (Event ID 4624) e falhados (Event ID 4625), a base de qualquer deteção de força bruta ou tentativas de acesso não autorizado. |
| Logon/Logoff | Special Logon | Sim | Não aplicável | Cobre logons que usam privilégios especiais (Event ID 4672), relevante para detetar quando uma conta administrativa (`adm.primeiro.ultimo`) efetivamente inicia sessão com privilégios elevados. |
| Logon/Logoff | Account Lockout | Sim | Não aplicável | Cobre bloqueios de conta por tentativas de password incorretas repetidas (Event ID 4740), sinal direto de possível ataque de força bruta em curso. |
| Object Access | Other Object Access Events | Sim | Não | Cobre, entre outros, a criação, modificação e eliminação de tarefas agendadas (Event IDs 4698, 4699, 4700, 4701, 4702), um vetor de persistência comum que interessa ao SentryLens detetar. |
| Detailed Tracking | Process Creation | Sim | Não aplicável | Cobre a criação de novos processos (Event ID 4688), que dá visibilidade sobre execução de ferramentas administrativas ou scripts no DC. |

Notas sobre a tabela:

- "Não aplicável" nas colunas de Falha significa que essa subcategoria, na
  prática do Windows Auditing, não distingue Sucesso/Falha de forma
  significativa (por exemplo, Special Logon e Account Lockout são, por
  natureza, eventos de um único sentido) ou que ativar Falha não gera sinal
  adicional relevante e apenas aumentaria o volume de eventos sem
  benefício de deteção.
- Estas sete subcategorias são o mínimo que o script `05-Set-AuditPolicy.ps1`
  garante. Nada impede alargar a política mais tarde (por exemplo,
  Directory Service Changes para auditoria detalhada de alterações a
  objetos do AD), mas essa extensão fica fora do âmbito definido para a
  primeira versão do script.

## 3. Comandos previstos (referência, não é o script)

O script usa `auditpol /set /subcategory:"<nome>" /success:enable
/failure:enable` (ou só `/success:enable` onde a falha não se aplica) para
cada uma das subcategorias acima. Exemplos de subcategorias pelo nome
exato reconhecido por `auditpol` em Windows Server 2022 em português:
"Gestão de Contas de Utilizador", "Gestão de Grupos de Segurança", "Início
de Sessão", "Início de Sessão Especial", "Bloqueio de Conta", "Outros
Eventos de Acesso a Objetos", "Criação de Processo" (os nomes exatos em
português dependem da instalação; o script deve confirmar os nomes reais
disponíveis com `auditpol /list /subcategory:*` antes de os aplicar, para
não falhar silenciosamente por incompatibilidade de idioma).

## 4. Aumento do log de Segurança para pelo menos 512 MB

O script também aumenta o tamanho máximo do Windows Security Event Log
(`wevtutil sl Security /ms:<bytes>`) para, no mínimo, **512 MB**
(536.870.912 bytes), acima do valor por omissão do Windows Server 2022
(tipicamente 128 MB ou menos, dependendo da imagem).

### Porquê 512 MB

- Com as sete subcategorias acima ativadas (em particular Logon e Process
  Creation, tipicamente as de maior volume), o log de Segurança cresce mais
  depressa do que com a política por omissão. Um log pequeno satura e
  começa a sobrescrever eventos antigos antes de o agente Wazuh os ter lido
  e enviado, o que resulta em perda de eventos, silenciosa e difícil de
  detetar depois do facto.
- O agente Wazuh não lê o Event Log em tempo real evento a evento de forma
  garantida sob qualquer condição (por exemplo, se o serviço `WazuhSvc` for
  reiniciado, ou durante uma janela de indisponibilidade de rede até ao
  Manager em 192.168.1.143). Um log de Segurança com retenção suficiente
  (512 MB dá margem para uma quantidade considerável de eventos mesmo com
  as subcategorias mais verbosas ativas) garante que, mesmo numa
  interrupção temporária de recolha, os eventos continuam disponíveis no
  log até o agente retomar a leitura, em vez de serem perdidos por
  sobrescrita.
- 512 MB é um valor conservador para um único DC de laboratório com poucos
  utilizadores e baixo volume de autenticações por hora; num ambiente de
  produção com muito mais atividade, este valor teria de ser recalculado
  em função do volume real de eventos por dia.

## 5. Confirmação final da política aplicada

No final da execução, o script `05-Set-AuditPolicy.ps1` corre
`auditpol /get /category:*` (ou `/get /subcategory:<nome>` para cada
subcategoria configurada) e compara o resultado com o que foi pedido, para
confirmar que a política ficou efetivamente aplicada e não apenas emitida
sem erro aparente. Discrepâncias entre o pedido e o estado real (por
exemplo, uma GPO de nível superior a repor um valor diferente) são
reportadas na consola no final da execução.

Este documento não antecipa o resultado dessa confirmação: fica pendente
de execução real do script contra o DC `NORTADA-DC01` e de validação pelo
utilizador, incluindo a confirmação de que os Event IDs esperados chegam
efetivamente ao Wazuh Manager e ficam visíveis no SentryLens.

## 6. Relação com os outros documentos

- Os Event IDs de gestão de contas e de grupos aqui listados são os que os
  processos descritos em `05-onboarding-offboarding.md` vão gerar na
  prática (criação, alteração de grupos, desativação).
- A subcategoria Security Group Management é a base técnica que permite ao
  SentryLens, no futuro, detetar desvios face à baseline de RBAC descrita
  em `06-rbac.md` (por exemplo, alertar quando uma conta é adicionada a um
  grupo crítico como `Domain Admins` fora do processo formal).
