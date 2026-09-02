#Requires -Version 5.1
<#
.SYNOPSIS
    Cria a arvore completa de Unidades Organizacionais (OUs) do dominio
    nortada.local, de forma idempotente.

.DESCRIPTION
    Implementa a estrutura de OUs descrita em docs/03-estrutura-ou-grupos.md,
    seccao 2, sob o Controlador de Dominio NORTADA-DC01 (ja promovido pelo
    script 00-Install-DomainController.ps1). Arvore criada:

        OU=NORTADA
          OU=Utilizadores
            OU=Direcao
            OU=Financeira
            OU=RecursosHumanos
            OU=IT
            OU=Marketing
            OU=Operacoes
          OU=Contas-Administrativas
          OU=Grupos
            OU=Seguranca
            OU=Distribuicao
          OU=Computadores
            OU=Servidores
            OU=Estacoes
          OU=Contas-Servico
          OU=Contas-Desativadas

    O script e idempotente: antes de criar cada OU verifica a sua existencia
    com Get-ADOrganizationalUnit -Filter dentro do SearchBase do respetivo
    pai, e so invoca New-ADOrganizationalUnit quando a OU nao existe. A
    arvore e criada de cima para baixo, porque cada nivel depende do
    DistinguishedName do nivel anterior para servir de SearchBase da proxima
    verificacao (ver docs/03-estrutura-ou-grupos.md, seccao 2.2).

    No fim, o script apresenta um resumo com o numero de OUs criadas e o
    numero de OUs que ja existiam.

.PARAMETER DomainDN
    Distinguished Name da raiz do dominio, onde a arvore de OUs e ancorada.
    Por omissao, "DC=nortada,DC=local", derivado do dominio nortada.local
    definido em docs/01-arquitetura.md.

.EXAMPLE
    .\01-New-OuStructure.ps1

    Cria a arvore de OUs completa sob DC=nortada,DC=local (valor por
    omissao), ou reporta as OUs que ja existem numa segunda execucao.

.EXAMPLE
    .\01-New-OuStructure.ps1 -DomainDN "DC=nortada,DC=local" -WhatIf

    Mostra que OUs seriam criadas, sem alterar o dominio.

.NOTES
    Decisao de arquitetura:
    - Todas as OUs ficam sob uma OU de topo unica, OU=NORTADA, em vez de
      diretamente sob a raiz do dominio, para isolar os objetos geridos por
      este laboratorio dos contentores nativos do AD (Users, Computers) e
      simplificar a aplicacao de GPOs e uma eventual remocao completa da
      estrutura (docs/03-estrutura-ou-grupos.md, seccao 2).
    - A separacao de OU=Utilizadores por departamento permite GPOs e
      delegacao de permissoes administrativas granulares por departamento.
    - OU=Contas-Administrativas fica separada das contas normais como base
      do principio de PAM (Privileged Access Management).
    - Idempotencia deliberada: o script pode ter de ser corrido novamente
      depois de ajustes a outros scripts do laboratorio, sem risco de
      duplicar objetos ou interromper a execucao com erros de objeto
      duplicado.
    - Este script nunca correu contra um dominio real; o resumo final
      reflete apenas o que a execucao concreta encontrou e criou nessa
      execucao, nunca um resultado inventado antecipadamente.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DomainDN = "DC=nortada,DC=local"
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path -Path $logDir -ChildPath ("01-new-ou-structure-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

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

Write-Log "Inicio da execucao do script 01-New-OuStructure.ps1."
Write-Log "Parametro: DomainDN=$DomainDN"

# Contadores para o resumo final
$script:contadorCriadas = 0
$script:contadorExistentes = 0

# ---------------------------------------------------------------------------
# Funcao auxiliar idempotente: garante que uma OU existe sob um determinado
# SearchBase, criando-a apenas se ainda nao existir.
# ---------------------------------------------------------------------------

function Confirm-OuExiste {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nome,

        [Parameter(Mandatory = $true)]
        [string]$SearchBase
    )

    try {
        $ouExistente = Get-ADOrganizationalUnit -Filter "Name -eq '$Nome'" -SearchBase $SearchBase -SearchScope OneLevel -ErrorAction Stop

        if ($ouExistente) {
            Write-Log "OU '$Nome' ja existe em '$SearchBase'. Nada a fazer."
            $script:contadorExistentes++
            return $ouExistente.DistinguishedName
        }

        if ($PSCmdlet.ShouldProcess("$Nome,$SearchBase", "Criar Unidade Organizacional")) {
            Write-Log "OU '$Nome' nao encontrada em '$SearchBase'. A criar..."
            $novaOu = New-ADOrganizationalUnit -Name $Nome -Path $SearchBase -ProtectedFromAccidentalDeletion $true -PassThru -ErrorAction Stop
            Write-Log "OU '$Nome' criada com sucesso: $($novaOu.DistinguishedName)."
            $script:contadorCriadas++
            return $novaOu.DistinguishedName
        }
        else {
            Write-Log "ShouldProcess indicou -WhatIf: OU '$Nome' nao foi criada."
            return "OU=$Nome,$SearchBase"
        }
    }
    catch {
        Write-Log "Falha ao verificar/criar a OU '$Nome' em '$SearchBase': $($_.Exception.Message)" -Nivel "ERRO"
        throw
    }
}

# ---------------------------------------------------------------------------
# Construcao da arvore, de cima para baixo
# ---------------------------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Log "Nao foi possivel importar o modulo ActiveDirectory: $($_.Exception.Message)" -Nivel "ERRO"
    throw "O modulo ActiveDirectory (RSAT) tem de estar disponivel para correr este script."
}

try {
    # Nivel 1: OU de topo
    $dnNortada = Confirm-OuExiste -Nome "NORTADA" -SearchBase $DomainDN

    # Nivel 2: contentores diretos sob OU=NORTADA
    $dnUtilizadores = Confirm-OuExiste -Nome "Utilizadores" -SearchBase $dnNortada
    $dnContasAdmin = Confirm-OuExiste -Nome "Contas-Administrativas" -SearchBase $dnNortada
    $dnGrupos = Confirm-OuExiste -Nome "Grupos" -SearchBase $dnNortada
    $dnComputadores = Confirm-OuExiste -Nome "Computadores" -SearchBase $dnNortada
    $dnContasServico = Confirm-OuExiste -Nome "Contas-Servico" -SearchBase $dnNortada
    $dnContasDesativadas = Confirm-OuExiste -Nome "Contas-Desativadas" -SearchBase $dnNortada

    # Nivel 3: sub-OUs de Utilizadores, uma por departamento
    $departamentos = @("Direcao", "Financeira", "RecursosHumanos", "IT", "Marketing", "Operacoes")
    foreach ($departamento in $departamentos) {
        Confirm-OuExiste -Nome $departamento -SearchBase $dnUtilizadores | Out-Null
    }

    # Nivel 3: sub-OUs de Grupos
    Confirm-OuExiste -Nome "Seguranca" -SearchBase $dnGrupos | Out-Null
    Confirm-OuExiste -Nome "Distribuicao" -SearchBase $dnGrupos | Out-Null

    # Nivel 3: sub-OUs de Computadores
    Confirm-OuExiste -Nome "Servidores" -SearchBase $dnComputadores | Out-Null
    Confirm-OuExiste -Nome "Estacoes" -SearchBase $dnComputadores | Out-Null

    Write-Log "Construcao da arvore de OUs concluida."
}
catch {
    Write-Log "Execucao interrompida devido a um erro na construcao da arvore de OUs: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------

$resumo = "Resumo: $script:contadorCriadas OU(s) criada(s), $script:contadorExistentes OU(s) ja existente(s)."
Write-Log $resumo
Write-Host $resumo

Write-Log "Fim da execucao do script 01-New-OuStructure.ps1. Log completo em: $logFile"
