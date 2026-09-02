#Requires -Version 5.1
<#
.SYNOPSIS
    Cria os grupos de seguranca do dominio nortada.local segundo o modelo
    AGDLP, de forma idempotente.

.DESCRIPTION
    Implementa o modelo de grupos descrito em docs/03-estrutura-ou-grupos.md,
    seccao 3, sob o Controlador de Dominio NORTADA-DC01, depois de a arvore
    de OUs (script 01-New-OuStructure.ps1) ja existir.

    Cria dois tipos de grupos, ambos em OU=Seguranca,OU=Grupos,OU=NORTADA:

    - Grupos globais (prefixo "GG-"), um por departamento/funcao, que
      representam "quem" o utilizador e na organizacao:
        GG-Direcao, GG-Financeira, GG-RH, GG-IT-Suporte, GG-Marketing,
        GG-Operacoes, e o grupo administrativo GG-IT-Admins.

    - Grupos de dominio local (prefixo "DL-"), associados a um recurso
      concreto, que representam "o que" pode ser acedido: pelo menos um
      grupo de leitura por departamento (por exemplo
      DL-Partilha-Financeira-Leitura, DL-Partilha-RH-Leitura).

    Depois de criar cada par GG/DL correspondente a um departamento, o
    script adiciona o grupo global como membro do grupo de dominio local de
    leitura, para materializar a cadeia AGDLP completa descrita em
    docs/03-estrutura-ou-grupos.md, seccao 3 (Account -> Global ->
    Domain Local -> Permission).

    O script e idempotente: antes de criar qualquer grupo verifica a sua
    existencia com Get-ADGroup, e antes de adicionar uma pertenca verifica
    se o membro ja pertence ao grupo.

.PARAMETER DomainDN
    Distinguished Name da raiz do dominio. Por omissao,
    "DC=nortada,DC=local", derivado do dominio nortada.local.

.PARAMETER GruposOuPath
    Distinguished Name relativo (sem o DomainDN) da OU onde os grupos de
    seguranca sao criados. Por omissao, "OU=Seguranca,OU=Grupos,OU=NORTADA",
    conforme docs/03-estrutura-ou-grupos.md, seccao 3.2.

.EXAMPLE
    .\02-New-SecurityGroups.ps1

    Cria (ou confirma a existencia de) todos os grupos GG- e DL- descritos
    acima, sob DC=nortada,DC=local.

.EXAMPLE
    .\02-New-SecurityGroups.ps1 -WhatIf

    Mostra que grupos seriam criados e que pertencas seriam adicionadas, sem
    alterar o dominio.

.NOTES
    Porque AGDLP em vez de permissoes diretas em utilizadores (resumo de
    docs/03-estrutura-ou-grupos.md, seccao 3.1):
    - Manutencao centralizada: mudar um colaborador de departamento resume-se
      a mudar a sua pertenca de grupo global, em vez de localizar e revogar
      permissoes diretas espalhadas por varios recursos.
    - Auditoria simples: "quem tem acesso a este recurso" responde-se
      diretamente pelos membros do grupo de dominio local, sem inspecionar o
      ACL de cada recurso.
    - Menos entradas de controlo de acesso (ACEs): um recurso com AGDLP tem
      uma unica ACE (o grupo de dominio local), em vez de uma por
      utilizador.
    - Separacao entre "quem" (grupo global, funcao/departamento) e "o que"
      (grupo de dominio local, recurso), permitindo reutilizar o mesmo grupo
      global em varios grupos de dominio local diferentes.
    - Coerencia com o menor privilegio e com PAM: as contas administrativas
      (adm.primeiro.ultimo) tem os seus proprios grupos (GG-IT-Admins), nunca
      partilhando a pertenca aos grupos globais de departamento das contas
      normais equivalentes.
    - Os grupos de dominio local criados aqui sao um conjunto de exemplo
      minimo (leitura por departamento); a matriz completa de permissoes por
      funcao fica fora do ambito deste script (ver docs/06-rbac.md).
    - Este script nunca correu contra um dominio real; qualquer resumo ou
      resultado apresentado reflete apenas o que uma execucao concreta
      viesse a encontrar e criar, nunca um resultado inventado antecipadamente.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DomainDN = "DC=nortada,DC=local",

    [Parameter()]
    [string]$GruposOuPath = "OU=Seguranca,OU=Grupos,OU=NORTADA"
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path -Path $logDir -ChildPath ("02-new-security-groups-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Write-Log {
    param(
        [string]$Mensagem,
        [ValidateSet("INFO", "AVISO", "ERRO")]
        [string]$Nivel = "INFO"
    )
    $linha = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Nivel, $Mensagem
    Add-Content -Path $logFile -Value $linha
    switch ($Nivel) {
        "ERRO"  { Write-Error $Mensagem }
        "AVISO" { Write-Warning $Mensagem }
        default { Write-Host $linha }
    }
}

Write-Log "Inicio da execucao do script 02-New-SecurityGroups.ps1."

$dnGrupos = "$GruposOuPath,$DomainDN"
Write-Log "Parametros: DomainDN=$DomainDN GruposOuPath=$GruposOuPath (OU efetiva de destino: $dnGrupos)"

$script:contadorCriados = 0
$script:contadorExistentes = 0
$script:contadorMembrosAdicionados = 0
$script:contadorMembrosExistentes = 0

# ---------------------------------------------------------------------------
# Funcao auxiliar idempotente: garante que um grupo de seguranca existe.
# ---------------------------------------------------------------------------

function Confirm-GrupoExiste {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nome,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Global", "DomainLocal")]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$Descricao,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $grupoExistente = Get-ADGroup -Filter "Name -eq '$Nome'" -SearchBase $Path -SearchScope OneLevel -ErrorAction Stop

        if ($grupoExistente) {
            Write-Log "Grupo '$Nome' ja existe em '$Path'. Nada a fazer."
            $script:contadorExistentes++
            return $grupoExistente.DistinguishedName
        }

        if ($PSCmdlet.ShouldProcess("$Nome,$Path", "Criar grupo de seguranca ($Scope)")) {
            Write-Log "Grupo '$Nome' nao encontrado em '$Path'. A criar (Scope=$Scope)..."
            $novoGrupo = New-ADGroup -Name $Nome -GroupScope $Scope -GroupCategory Security `
                -Path $Path -Description $Descricao -PassThru -ErrorAction Stop
            Write-Log "Grupo '$Nome' criado com sucesso: $($novoGrupo.DistinguishedName)."
            $script:contadorCriados++
            return $novoGrupo.DistinguishedName
        }
        else {
            Write-Log "ShouldProcess indicou -WhatIf: grupo '$Nome' nao foi criado."
            return "CN=$Nome,$Path"
        }
    }
    catch {
        Write-Log "Falha ao verificar/criar o grupo '$Nome' em '$Path': $($_.Exception.Message)" -Nivel "ERRO"
        throw
    }
}

# ---------------------------------------------------------------------------
# Funcao auxiliar idempotente: garante que um grupo global e membro de um
# grupo de dominio local, materializando a cadeia AGDLP.
# ---------------------------------------------------------------------------

function Confirm-MembroDeGrupo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GrupoMembroDN,

        [Parameter(Mandatory = $true)]
        [string]$GrupoDestinoDN
    )

    try {
        $membrosAtuais = Get-ADGroupMember -Identity $GrupoDestinoDN -ErrorAction Stop
        $jaEhMembro = $membrosAtuais | Where-Object { $_.DistinguishedName -eq $GrupoMembroDN }

        if ($jaEhMembro) {
            Write-Log "'$GrupoMembroDN' ja e membro de '$GrupoDestinoDN'. Nada a fazer."
            $script:contadorMembrosExistentes++
            return
        }

        if ($PSCmdlet.ShouldProcess($GrupoDestinoDN, "Adicionar '$GrupoMembroDN' como membro")) {
            Add-ADGroupMember -Identity $GrupoDestinoDN -Members $GrupoMembroDN -ErrorAction Stop
            Write-Log "'$GrupoMembroDN' adicionado como membro de '$GrupoDestinoDN'."
            $script:contadorMembrosAdicionados++
        }
        else {
            Write-Log "ShouldProcess indicou -WhatIf: pertenca de '$GrupoMembroDN' em '$GrupoDestinoDN' nao foi alterada."
        }
    }
    catch {
        Write-Log "Falha ao verificar/adicionar a pertenca de '$GrupoMembroDN' em '$GrupoDestinoDN': $($_.Exception.Message)" -Nivel "ERRO"
        throw
    }
}

# ---------------------------------------------------------------------------
# Criacao dos grupos
# ---------------------------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Log "Nao foi possivel importar o modulo ActiveDirectory: $($_.Exception.Message)" -Nivel "ERRO"
    throw "O modulo ActiveDirectory (RSAT) tem de estar disponivel para correr este script."
}

try {
    # Mapa de departamentos: nome do grupo global, nome do grupo de dominio
    # local de leitura, e descricao legivel para cada um.
    $departamentos = @(
        @{ GG = "GG-Direcao";     DL = "DL-Partilha-Direcao-Leitura";     Desc = "Direcao" }
        @{ GG = "GG-Financeira";  DL = "DL-Partilha-Financeira-Leitura";  Desc = "Financeira" }
        @{ GG = "GG-RH";          DL = "DL-Partilha-RH-Leitura";          Desc = "Recursos Humanos" }
        @{ GG = "GG-IT-Suporte";  DL = "DL-Partilha-IT-Leitura";          Desc = "IT (Suporte)" }
        @{ GG = "GG-Marketing";   DL = "DL-Partilha-Marketing-Leitura";   Desc = "Marketing" }
        @{ GG = "GG-Operacoes";   DL = "DL-Partilha-Operacoes-Leitura";   Desc = "Operacoes" }
    )

    foreach ($departamento in $departamentos) {
        $dnGG = Confirm-GrupoExiste -Nome $departamento.GG -Scope "Global" `
            -Descricao "Grupo global (AGDLP) dos colaboradores do departamento $($departamento.Desc)." `
            -Path $dnGrupos

        $dnDL = Confirm-GrupoExiste -Nome $departamento.DL -Scope "DomainLocal" `
            -Descricao "Grupo de dominio local (AGDLP) com permissao de leitura sobre a partilha do departamento $($departamento.Desc)." `
            -Path $dnGrupos

        Confirm-MembroDeGrupo -GrupoMembroDN $dnGG -GrupoDestinoDN $dnDL
    }

    # Grupo administrativo, separado dos grupos de departamento (principio de
    # PAM: contas adm.primeiro.ultimo nunca partilham grupos com as contas
    # normais equivalentes).
    Confirm-GrupoExiste -Nome "GG-IT-Admins" -Scope "Global" `
        -Descricao "Grupo global das contas administrativas (adm.primeiro.ultimo) de IT, separado dos grupos de departamento (PAM)." `
        -Path $dnGrupos | Out-Null

    Write-Log "Criacao de grupos de seguranca concluida."
}
catch {
    Write-Log "Execucao interrompida devido a um erro na criacao dos grupos de seguranca: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------

$resumo = "Resumo: $script:contadorCriados grupo(s) criado(s), $script:contadorExistentes grupo(s) ja existente(s); " +
    "$script:contadorMembrosAdicionados pertenca(s) de grupo adicionada(s), $script:contadorMembrosExistentes pertenca(s) ja existente(s)."
Write-Log $resumo
Write-Host $resumo

Write-Log "Fim da execucao do script 02-New-SecurityGroups.ps1. Log completo em: $logFile"
