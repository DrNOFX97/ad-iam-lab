#Requires -Version 5.1
<#
.SYNOPSIS
    Ativa a Advanced Audit Policy minima exigida pelo laboratorio no
    Controlador de Dominio NORTADA-DC01 e aumenta o log de Seguranca.

.DESCRIPTION
    Implementa docs/04-politica-auditoria.md: ativa, via "auditpol /set", as
    sete subcategorias que geram os eventos de que o agente Wazuh instalado
    no DC precisa para alimentar o SentryLens (gestao de contas, gestao de
    grupos, logons, logons especiais, bloqueios de conta, acesso a outros
    objetos e criacao de processos):

        Categoria             | Subcategoria                    | Sucesso | Falha
        ----------------------|----------------------------------|---------|------
        Account Management    | User Account Management          | Sim     | Sim
        Account Management    | Security Group Management        | Sim     | Sim
        Logon/Logoff           | Logon                            | Sim     | Sim
        Logon/Logoff           | Special Logon                    | Sim     | Nao
        Logon/Logoff           | Account Lockout                  | Sim     | Nao
        Object Access           | Other Object Access Events       | Sim     | Nao
        Detailed Tracking       | Process Creation                 | Sim     | Nao

    Antes de aplicar qualquer alteracao, o script corre
    "auditpol /list /subcategory:*" e confirma que os nomes de subcategoria
    esperados existem no sistema, para nao falhar silenciosamente por
    diferenca de idioma na instalacao do Windows (nota explicita em
    docs/04-politica-auditoria.md, seccao 3). O script tenta o nome em
    portugues de Portugal e, se nao encontrado, tenta o nome equivalente em
    ingles, antes de desistir dessa subcategoria com um aviso.

    Depois disso, aumenta o tamanho maximo do log de Seguranca com
    "wevtutil sl Security /ms:<bytes>" para, no minimo, 512 MB
    (536.870.912 bytes), para reduzir o risco de perda de eventos por
    sobrescrita antes de o agente Wazuh os conseguir ler (justificacao
    completa em docs/04-politica-auditoria.md, seccao 4).

    No fim, corre "auditpol /get /category:*" e compara subcategoria a
    subcategoria o que foi pedido com o que ficou efetivamente aplicado,
    reportando qualquer discrepancia (por exemplo, uma GPO de nivel superior
    a repor um valor diferente).

    Este script nunca correu contra um DC real. As mensagens de progresso
    descrevem o comportamento previsto; os resultados da confirmacao final
    ficam pendentes de execucao real e validacao pelo utilizador.

.PARAMETER LogSizeBytes
    Tamanho maximo, em bytes, a definir para o log de Seguranca do Windows.
    Por omissao, 536870912 (512 MB), conforme docs/04-politica-auditoria.md,
    seccao 4.

.EXAMPLE
    .\05-Set-AuditPolicy.ps1

    Ativa as sete subcategorias da Advanced Audit Policy e aumenta o log de
    Seguranca para 512 MB (valores por omissao).

.EXAMPLE
    .\05-Set-AuditPolicy.ps1 -LogSizeBytes 1073741824

    Usa o mesmo conjunto de subcategorias, mas aumenta o log de Seguranca
    para 1 GB em vez dos 512 MB por omissao.

.NOTES
    Decisao de arquitetura e seguranca:
    - Estas sete subcategorias sao o minimo definido para que o SentryLens
      tenha eventos reais de gestao de identidades para apresentar (criacao
      de utilizadores, alteracoes a grupos, logons falhados, bloqueios de
      conta, elevacao de privilegios). Sem esta politica, o Windows regista
      por omissao um subconjunto muito mais pequeno de eventos de seguranca.
    - A confirmacao previa dos nomes de subcategoria com
      "auditpol /list /subcategory:*" existe porque o comando "auditpol /set"
      falha (ou e ignorado) silenciosamente quando o nome da subcategoria
      nao corresponde exatamente ao idioma da instalacao do Windows.
    - O log de Seguranca e aumentado para 512 MB porque a ativacao destas
      subcategorias (em particular Logon e Process Creation) aumenta
      significativamente o volume de eventos gerados; um log pequeno satura
      e comeca a sobrescrever eventos antes de o agente Wazuh os ler,
      resultando em perda silenciosa de eventos.
    - O script e idempotente: corre "auditpol /set" sobre o estado desejado
      e confirma o resultado no final, pelo que pode ser corrido varias
      vezes sem efeitos colaterais negativos.
    - Esta e a politica minima definida para a primeira versao do
      laboratorio; alargar a subcategorias adicionais (por exemplo
      Directory Service Changes) fica fora do ambito deste script (ver
      docs/04-politica-auditoria.md, seccao 2).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1048576, [long]::MaxValue)]
    [long]$LogSizeBytes = 536870912
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path -Path $logDir -ChildPath ("05-set-audit-policy-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

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

Write-Log "Inicio da execucao do script 05-Set-AuditPolicy.ps1."
Write-Log "Parametro: LogSizeBytes=$LogSizeBytes"

# ---------------------------------------------------------------------------
# Verificacao de privilegios de Administrador
# ---------------------------------------------------------------------------

try {
    $identidadeAtual = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identidadeAtual)
    $ehAdministrador = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $ehAdministrador) {
        Write-Log "O script nao esta a correr com privilegios elevados." -Nivel "ERRO"
        throw "E necessario correr este script numa sessao PowerShell como Administrador."
    }
    Write-Log "Privilegios de Administrador confirmados."
}
catch {
    Write-Log "Falha na verificacao de privilegios: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# Definicao das subcategorias pedidas: nome em portugues de Portugal (o
# nome tipico numa instalacao PT-PT do Windows Server) com equivalente em
# ingles como alternativa, e se Sucesso/Falha se aplicam.
# ---------------------------------------------------------------------------

$subcategoriasPedidas = @(
    [PSCustomObject]@{ NomePt = "Gestao de Contas de Utilizador";      NomeEn = "User Account Management";        Sucesso = $true;  Falha = $true  }
    [PSCustomObject]@{ NomePt = "Gestao de Grupos de Seguranca";       NomeEn = "Security Group Management";      Sucesso = $true;  Falha = $true  }
    [PSCustomObject]@{ NomePt = "Inicio de Sessao";                    NomeEn = "Logon";                          Sucesso = $true;  Falha = $true  }
    [PSCustomObject]@{ NomePt = "Inicio de Sessao Especial";           NomeEn = "Special Logon";                  Sucesso = $true;  Falha = $false }
    [PSCustomObject]@{ NomePt = "Bloqueio de Conta";                   NomeEn = "Account Lockout";                Sucesso = $true;  Falha = $false }
    [PSCustomObject]@{ NomePt = "Outros Eventos de Acesso a Objetos";  NomeEn = "Other Object Access Events";     Sucesso = $true;  Falha = $false }
    [PSCustomObject]@{ NomePt = "Criacao de Processo";                 NomeEn = "Process Creation";                Sucesso = $true;  Falha = $false }
)

# ---------------------------------------------------------------------------
# Confirmar que os nomes de subcategoria existem no sistema antes de aplicar
# qualquer alteracao, para nao falhar silenciosamente por diferenca de
# idioma (docs/04-politica-auditoria.md, seccao 3).
# ---------------------------------------------------------------------------

try {
    Write-Log "A obter a lista de subcategorias existentes com 'auditpol /list /subcategory:*'..."
    $listaSubcategorias = auditpol /list /subcategory:* 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Log "'auditpol /list /subcategory:*' terminou com codigo de saida $LASTEXITCODE." -Nivel "ERRO"
        throw "Nao foi possivel listar as subcategorias de auditoria do sistema."
    }

    # Normaliza a saida para uma lista de linhas sem espacos extra, para
    # comparacao por correspondencia parcial (case-insensitive).
    $linhasSubcategorias = $listaSubcategorias | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

    foreach ($subcategoria in $subcategoriasPedidas) {
        $encontradaPt = $linhasSubcategorias | Where-Object { $_ -match [regex]::Escape($subcategoria.NomePt) }
        $encontradaEn = $linhasSubcategorias | Where-Object { $_ -match [regex]::Escape($subcategoria.NomeEn) }

        if ($encontradaPt) {
            $subcategoria | Add-Member -NotePropertyName "NomeResolvido" -NotePropertyValue $subcategoria.NomePt -Force
            Write-Log "Subcategoria confirmada (PT): '$($subcategoria.NomePt)'."
        }
        elseif ($encontradaEn) {
            $subcategoria | Add-Member -NotePropertyName "NomeResolvido" -NotePropertyValue $subcategoria.NomeEn -Force
            Write-Log "Subcategoria confirmada (EN, fallback): '$($subcategoria.NomeEn)'."
        }
        else {
            $subcategoria | Add-Member -NotePropertyName "NomeResolvido" -NotePropertyValue $null -Force
            Write-Log "Subcategoria '$($subcategoria.NomePt)' / '$($subcategoria.NomeEn)' nao encontrada em 'auditpol /list /subcategory:*'. Sera ignorada." -Nivel "AVISO"
        }
    }
}
catch {
    Write-Log "Falha na confirmacao previa das subcategorias: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# Aplicar auditpol /set para cada subcategoria confirmada
# ---------------------------------------------------------------------------

$discrepancias = New-Object System.Collections.Generic.List[string]

foreach ($subcategoria in $subcategoriasPedidas) {
    if (-not $subcategoria.NomeResolvido) {
        $discrepancias.Add("Subcategoria '$($subcategoria.NomePt)' nao existe no sistema; politica nao aplicada.")
        continue
    }

    try {
        $flagSucesso = if ($subcategoria.Sucesso) { "enable" } else { "disable" }
        $flagFalha = if ($subcategoria.Falha) { "enable" } else { "disable" }

        Write-Log "A aplicar auditpol /set para '$($subcategoria.NomeResolvido)' (Sucesso=$flagSucesso, Falha=$flagFalha)..."
        $saidaSet = auditpol /set /subcategory:"$($subcategoria.NomeResolvido)" /success:$flagSucesso /failure:$flagFalha 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Log "auditpol /set falhou para '$($subcategoria.NomeResolvido)' (codigo $LASTEXITCODE): $saidaSet" -Nivel "ERRO"
            $discrepancias.Add("Falha ao aplicar '$($subcategoria.NomeResolvido)': codigo de saida $LASTEXITCODE.")
            continue
        }
        Write-Log "Subcategoria '$($subcategoria.NomeResolvido)' aplicada com sucesso."
    }
    catch {
        Write-Log "Excecao ao aplicar '$($subcategoria.NomeResolvido)': $($_.Exception.Message)" -Nivel "ERRO"
        $discrepancias.Add("Excecao ao aplicar '$($subcategoria.NomeResolvido)': $($_.Exception.Message)")
    }
}

# ---------------------------------------------------------------------------
# Aumentar o log de Seguranca
# ---------------------------------------------------------------------------

try {
    Write-Log "A aumentar o tamanho maximo do log de Seguranca para $LogSizeBytes bytes..."
    $saidaWevtutil = wevtutil sl Security "/ms:$LogSizeBytes" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Log "'wevtutil sl Security /ms:$LogSizeBytes' falhou (codigo $LASTEXITCODE): $saidaWevtutil" -Nivel "ERRO"
        $discrepancias.Add("Falha ao aumentar o log de Seguranca para $LogSizeBytes bytes: codigo de saida $LASTEXITCODE.")
    }
    else {
        Write-Log "Log de Seguranca configurado para o maximo de $LogSizeBytes bytes."
    }
}
catch {
    Write-Log "Excecao ao aumentar o log de Seguranca: $($_.Exception.Message)" -Nivel "ERRO"
    $discrepancias.Add("Excecao ao aumentar o log de Seguranca: $($_.Exception.Message)")
}

# ---------------------------------------------------------------------------
# Confirmacao final: corre auditpol /get e compara com o que foi pedido
# ---------------------------------------------------------------------------

try {
    Write-Log "A confirmar o estado final da politica com 'auditpol /get /category:*'..."
    $estadoFinal = auditpol /get /category:* 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Log "'auditpol /get /category:*' terminou com codigo de saida $LASTEXITCODE." -Nivel "AVISO"
    }

    $linhasEstadoFinal = $estadoFinal | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

    foreach ($subcategoria in $subcategoriasPedidas) {
        if (-not $subcategoria.NomeResolvido) {
            continue
        }

        $linhaEncontrada = $linhasEstadoFinal | Where-Object { $_ -match [regex]::Escape($subcategoria.NomeResolvido) } | Select-Object -First 1

        if (-not $linhaEncontrada) {
            Write-Log "Nao foi possivel localizar '$($subcategoria.NomeResolvido)' na saida de 'auditpol /get /category:*' para confirmacao." -Nivel "AVISO"
            $discrepancias.Add("Nao foi possivel confirmar o estado de '$($subcategoria.NomeResolvido)' apos aplicacao.")
            continue
        }

        $sucessoEsperadoTexto = if ($subcategoria.Sucesso) { "Sucesso" } else { "Nao" }
        $falhaEsperadaTexto = if ($subcategoria.Falha) { "Falha" } else { "Nao" }

        Write-Log "Estado reportado para '$($subcategoria.NomeResolvido)': $linhaEncontrada"
        Write-Log "Estado esperado para '$($subcategoria.NomeResolvido)': Sucesso=$sucessoEsperadoTexto Falha=$falhaEsperadaTexto"

        # Comparacao textual simples: confirma que a linha contem referencia
        # a "Sucesso" e/ou "Falha" (ou "Success"/"Failure") conforme
        # esperado. Uma comparacao mais rigorosa dependeria do formato exato
        # da saida no idioma da instalacao, que so e conhecido em execucao
        # real.
        $contemSucesso = $linhaEncontrada -match "Sucesso|Success"
        $contemFalha = $linhaEncontrada -match "Falha|Failure"

        if ($subcategoria.Sucesso -and -not $contemSucesso) {
            $discrepancias.Add("'$($subcategoria.NomeResolvido)': Sucesso esperado mas nao encontrado na saida de auditpol /get.")
        }
        if ($subcategoria.Falha -and -not $contemFalha) {
            $discrepancias.Add("'$($subcategoria.NomeResolvido)': Falha esperada mas nao encontrada na saida de auditpol /get.")
        }
    }
}
catch {
    Write-Log "Falha na confirmacao final da politica: $($_.Exception.Message)" -Nivel "ERRO"
    $discrepancias.Add("Excecao durante a confirmacao final: $($_.Exception.Message)")
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------

if ($discrepancias.Count -eq 0) {
    $resumo = "Resumo: todas as subcategorias pedidas foram aplicadas e confirmadas sem discrepancias detetadas, e o log de Seguranca foi configurado para $LogSizeBytes bytes."
    Write-Log $resumo
    Write-Host $resumo
}
else {
    $resumo = "Resumo: foram detetadas $($discrepancias.Count) discrepancia(s) entre o pedido e o estado confirmado:"
    Write-Log $resumo -Nivel "AVISO"
    Write-Host $resumo
    foreach ($discrepancia in $discrepancias) {
        Write-Log " - $discrepancia" -Nivel "AVISO"
        Write-Host " - $discrepancia"
    }
}

Write-Log "Fim da execucao do script 05-Set-AuditPolicy.ps1. Log completo em: $logFile"
