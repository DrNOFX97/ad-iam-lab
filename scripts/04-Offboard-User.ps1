#Requires -Version 5.1
<#
.SYNOPSIS
    Processa o offboarding em lote de colaboradores da Nortada Logistica no
    dominio nortada.local, a partir de data/saidas.csv, seguindo a ordem de
    seguranca definida em docs/05-onboarding-offboarding.md, seccao 3.2.

.DESCRIPTION
    Para cada saida (linha de data/saidas.csv, colunas Nome, Apelido,
    DataSaida, Motivo, ou um unico utilizador indicado via -Utilizador), o
    script executa, por esta ordem deliberada, os passos descritos em
    docs/05-onboarding-offboarding.md, seccao 3.2:

    1. Desativa a conta imediatamente (Disable-ADAccount), antes de qualquer
       outra alteracao, para impedir novos logons a partir do momento em que
       o script corre.
    2. Repoe a password para um valor aleatorio gerado como SecureString
       (Set-ADAccountPassword), para revogar credenciais em cache e
       sessoes/tokens que ainda dependam da password antiga.
    3. Remove a conta de todos os grupos de seguranca a que pertence
       (exceto o grupo primario, "Domain Users", que o AD nao permite
       remover sem antes trocar o grupo primario da conta), registando a
       lista completa de grupos num CSV de auditoria separado por
       utilizador: scripts/logs/offboarding-<utilizador>-<data>.csv.
    4. Move a conta para OU=Contas-Desativadas,OU=NORTADA.
    5. Marca a descricao da conta (Description) com a data de saida, o
       motivo e a referencia ao ficheiro de log do passo 3.

    O script nunca elimina a conta processada (nunca chama Remove-ADUser
    nem Remove-ADObject sobre ela); ver .NOTES para a justificacao completa,
    resumida de docs/05-onboarding-offboarding.md, seccao 3.3.

    Alem da conta normal (primeiro.ultimo) correspondente ao Nome/Apelido da
    linha, o script verifica tambem se existe uma conta administrativa
    associada a mesma pessoa (adm.primeiro.ultimo) e, se existir, processa-a
    da mesma forma: uma saida da empresa tem de revogar todas as contas da
    pessoa, nao apenas a conta do dia-a-dia (ver .NOTES).

    O script e idempotente: se a conta ja estiver desativada e a Description
    ja tiver a marca de saida deste processo, os passos destrutivos (nova
    password aleatoria, remocao de grupos) nao sao repetidos numa segunda
    execucao, a menos que -Forcar seja indicado explicitamente.

.PARAMETER CaminhoSaidas
    Caminho para o ficheiro data/saidas.csv. Por omissao,
    "..\data\saidas.csv", relativo a pasta scripts/ onde este script reside.
    Ignorado quando -Utilizador e indicado.

.PARAMETER Utilizador
    SamAccountName de um unico utilizador a processar (por exemplo
    "ana.pereira"), para uso pontual fora do ciclo normal do CSV de saidas.
    Quando indicado, data/saidas.csv nao e lido e apenas esta conta (mais a
    sua eventual conta administrativa associada) e processada.

.PARAMETER DomainDN
    Distinguished Name da raiz do dominio. Por omissao,
    "DC=nortada,DC=local".

.PARAMETER Forcar
    Forca a repeticao dos passos destrutivos (reposicao de password,
    remocao de grupos) mesmo que a conta ja esteja desativada e ja tenha
    sido marcada como offboarded numa execucao anterior. Sem este parametro,
    uma conta ja offboarded e apenas confirmada com um aviso, sem qualquer
    alteracao adicional.

.EXAMPLE
    .\04-Offboard-User.ps1 -WhatIf

    Mostra, para cada linha de data/saidas.csv, que contas seriam
    desativadas, que grupos seriam removidos e para onde seriam movidas, sem
    alterar de facto o Active Directory.

.EXAMPLE
    .\04-Offboard-User.ps1

    Processa em lote todas as saidas de data/saidas.csv com os caminhos por
    omissao.

.EXAMPLE
    .\04-Offboard-User.ps1 -Utilizador "sofia.carvalho"

    Processa o offboarding pontual de uma unica conta, sem depender do CSV
    de saidas (por exemplo, uma saida urgente ainda nao registada no CSV).

.EXAMPLE
    .\04-Offboard-User.ps1 -Utilizador "sofia.carvalho" -Forcar

    Repete os passos destrutivos (nova password, remocao de grupos) sobre
    uma conta que ja tinha sido offboarded anteriormente.

.NOTES
    Porque a conta nunca e eliminada (resumo de
    docs/05-onboarding-offboarding.md, seccao 3.3):
    - Retencao forense: a conta (mesmo desativada) preserva o SID e a
      associacao a eventos historicos ja registados no SentryLens, caso
      surja mais tarde uma necessidade de investigacao sobre a atividade
      passada desse utilizador.
    - Preservacao de propriedade de ficheiros e caixa de correio: no
      Windows a propriedade de objetos e associada ao SID, nao ao nome;
      eliminar a conta transforma esses registos num SID orfao, dificultando
      a reatribuicao de ficheiros ou o acesso administrativo a uma caixa de
      correio antiga. Manter a conta desativada preserva essa referencia
      resolvel.
    - Reversibilidade: reverter uma desativacao e imediato (Enable-ADAccount
      mais a reposicao dos grupos a partir do CSV de auditoria do passo 3),
      enquanto reverter uma eliminacao de conta e, na pratica, impossivel
      sem uma restauracao de tombstone, desproporcionado para corrigir um
      erro de processo (por exemplo, um CSV de saidas com uma linha
      incorreta).
    - A eliminacao definitiva de contas antigas em OU=Contas-Desativadas,
      se alguma vez necessaria por politica de retencao de dados, e uma
      decisao de negocio distinta, tomada e executada manualmente e fora do
      ambito automatizado deste script.

    Porque tambem se processa a eventual conta administrativa associada:
    - Em data/colaboradores.csv ha pessoas com duas contas (uma "normal" e
      uma "administrativa", por exemplo adm.rui.pinto para Rui Pinto).
      Desativar apenas a conta do dia-a-dia e deixar a conta administrativa
      ativa seria uma falha grave de offboarding: a conta com privilegios
      elevados (por exemplo membro de GG-IT-Admins ou Domain Admins) ficaria
      utilizavel depois de a pessoa deixar a organizacao. O script procura
      sempre "adm.<utilizador>" e, se existir, aplica-lhe exatamente os
      mesmos 5 passos, na mesma ordem.

    Sobre a password gerada no passo 2:
    - Tal como no onboarding, a password aleatoria e criada diretamente como
      SecureString (RandomNumberGenerator) e a variavel de texto simples
      intermedia, inevitavel para construir o SecureString em PowerShell, e
      limpa da memoria logo a seguir a ser usada; nunca e escrita em
      qualquer ficheiro de log.

    Este script nunca correu contra um dominio real; qualquer resumo ou
    resultado apresentado reflete apenas o que uma execucao concreta viesse
    a encontrar e alterar, nunca um resultado inventado antecipadamente.

    Limitacoes conhecidas:
    - A deteccao de "ja offboarded" e baseada em a conta estar desativada e
      a Description conter o prefixo "Saida em "; uma Description alterada
      manualmente depois do offboarding pode impedir esta deteccao.
    - O grupo primario da conta (normalmente "Domain Users") nunca e
      removido, porque o AD nao permite remover o grupo primario de uma
      conta sem antes lhe atribuir outro grupo primario; essa troca esta
      fora do ambito deste script e o grupo primario fica registado no CSV
      de auditoria como "mantido (grupo primario)".
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$CaminhoSaidas,

    [Parameter()]
    [string]$Utilizador,

    [Parameter()]
    [string]$DomainDN = "DC=nortada,DC=local",

    [Parameter()]
    [switch]$Forcar
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($CaminhoSaidas)) {
    $CaminhoSaidas = Join-Path -Path $scriptDir -ChildPath "..\data\saidas.csv"
}

$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$dataExecucao = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path -Path $logDir -ChildPath ("04-offboard-user-{0}.log" -f $dataExecucao)

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

Write-Log "Inicio da execucao do script 04-Offboard-User.ps1."
Write-Log "Parametros: CaminhoSaidas=$CaminhoSaidas Utilizador=$Utilizador DomainDN=$DomainDN Forcar=$($Forcar.IsPresent)"

# ---------------------------------------------------------------------------
# Funcao auxiliar: remove acentos e normaliza para minusculas (identica a
# usada em 03-Onboard-Users.ps1, para gerar o mesmo SamAccountName a partir
# do Nome/Apelido de data/saidas.csv).
# ---------------------------------------------------------------------------

function ConvertTo-NomeUtilizador {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Texto
    )
    if ([string]::IsNullOrWhiteSpace($Texto)) {
        return ""
    }
    $normalizado = $Texto.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($caractere in $normalizado.ToCharArray()) {
        $categoria = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($caractere)
        if ($categoria -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($caractere)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC).ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# Funcao auxiliar: gera uma password aleatoria criptograficamente segura,
# devolvida diretamente como SecureString (identica a de 03-Onboard-Users.ps1).
# ---------------------------------------------------------------------------

function New-PasswordAleatoriaSegura {
    param(
        [int]$Comprimento = 20
    )
    $carateres = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
    $bytesAleatorios = New-Object byte[] $Comprimento
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytesAleatorios)
    $passwordTexto = -join ($bytesAleatorios | ForEach-Object { $carateres[$_ % $carateres.Length] })
    $passwordSegura = ConvertTo-SecureString -String $passwordTexto -AsPlainText -Force
    $passwordTexto = $null
    return $passwordSegura
}

# ---------------------------------------------------------------------------
# Funcao principal: aplica os 5 passos de offboarding a uma conta concreta.
# ---------------------------------------------------------------------------

function Invoke-OffboardConta {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sam,

        [Parameter(Mandatory = $true)]
        [string]$DataSaida,

        [Parameter(Mandatory = $true)]
        [string]$Motivo
    )

    $conta = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -Properties Enabled, Description, PrimaryGroupID -ErrorAction SilentlyContinue
    if (-not $conta) {
        Write-Log "Conta '$Sam' nao encontrada no AD. Nada a fazer." -Nivel "AVISO"
        return "Conta nao encontrada"
    }

    # Deteccao de idempotencia: conta ja desativada e ja marcada como
    # offboarded por uma execucao anterior deste script.
    $jaOffboarded = ($conta.Enabled -eq $false) -and ($conta.Description -like "Saida em *")
    if ($jaOffboarded -and -not $Forcar) {
        Write-Log "Conta '$Sam' ja esta desativada e marcada como offboarded (Description: '$($conta.Description)'). Nenhum passo destrutivo repetido (usar -Forcar para reprocessar)." -Nivel "AVISO"
        return "Ignorado (ja offboarded)"
    }
    if ($jaOffboarded -and $Forcar) {
        Write-Log "Conta '$Sam' ja estava offboarded, mas -Forcar foi indicado: a repetir todos os passos." -Nivel "AVISO"
    }

    # Passo 1: desativar a conta imediatamente, antes de qualquer outra alteracao.
    if ($PSCmdlet.ShouldProcess($Sam, "Passo 1: Desativar conta (Disable-ADAccount)")) {
        try {
            Disable-ADAccount -Identity $Sam -ErrorAction Stop
            Write-Log "Passo 1/5 concluido: conta '$Sam' desativada."
        }
        catch {
            Write-Log "Falha no passo 1 (desativar) para '$Sam': $($_.Exception.Message)" -Nivel "ERRO"
            throw
        }
    }

    # Passo 2: repor a password para um valor aleatorio (revogacao de credenciais).
    if ($PSCmdlet.ShouldProcess($Sam, "Passo 2: Repor password aleatoria (Set-ADAccountPassword)")) {
        try {
            $passwordSegura = New-PasswordAleatoriaSegura
            Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $passwordSegura -ErrorAction Stop
            Write-Log "Passo 2/5 concluido: password de '$Sam' reposta para um valor aleatorio desconhecido."
        }
        catch {
            Write-Log "Falha no passo 2 (repor password) para '$Sam': $($_.Exception.Message)" -Nivel "ERRO"
            throw
        }
    }

    # Passo 3: remover de todos os grupos de seguranca, com log CSV dedicado.
    $logCsvUtilizador = Join-Path -Path $logDir -ChildPath ("offboarding-{0}-{1}.csv" -f $Sam, (Get-Date -Format "yyyyMMdd"))
    if ($PSCmdlet.ShouldProcess($Sam, "Passo 3: Remover de todos os grupos de seguranca")) {
        try {
            $grupos = Get-ADPrincipalGroupMembership -Identity $Sam -ErrorAction Stop
            $registoGrupos = @()

            foreach ($grupo in $grupos) {
                $ehGrupoPrimario = $grupo.SID -and $conta.PrimaryGroupID -and ($grupo.SID.Value -match "-$($conta.PrimaryGroupID)$")
                if ($grupo.Name -eq "Domain Users" -or $ehGrupoPrimario) {
                    Write-Log "Grupo '$($grupo.Name)' e o grupo primario de '$Sam'; mantido (o AD nao permite remove-lo sem trocar antes o grupo primario)."
                    $registoGrupos += [PSCustomObject]@{
                        DataHora   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Utilizador = $Sam
                        Grupo      = $grupo.Name
                        Acao       = "Mantido (grupo primario)"
                    }
                    continue
                }

                try {
                    Remove-ADGroupMember -Identity $grupo.DistinguishedName -Members $Sam -Confirm:$false -ErrorAction Stop
                    Write-Log "Utilizador '$Sam' removido do grupo '$($grupo.Name)'."
                    $registoGrupos += [PSCustomObject]@{
                        DataHora   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Utilizador = $Sam
                        Grupo      = $grupo.Name
                        Acao       = "Removido"
                    }
                }
                catch {
                    Write-Log "Falha ao remover '$Sam' do grupo '$($grupo.Name)': $($_.Exception.Message)" -Nivel "ERRO"
                    $registoGrupos += [PSCustomObject]@{
                        DataHora   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Utilizador = $Sam
                        Grupo      = $grupo.Name
                        Acao       = "Erro ao remover: $($_.Exception.Message)"
                    }
                }
            }

            if ($registoGrupos.Count -gt 0) {
                $registoGrupos | Export-Csv -Path $logCsvUtilizador -NoTypeInformation -Encoding UTF8
            }
            else {
                # Sem qualquer pertenca de grupo alem do primario: ainda assim
                # criamos o ficheiro de log, vazio de linhas de grupo, para
                # que a referencia no passo 5 seja sempre valida.
                [PSCustomObject]@{
                    DataHora   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Utilizador = $Sam
                    Grupo      = ""
                    Acao       = "Sem grupos de seguranca alem do primario"
                } | Export-Csv -Path $logCsvUtilizador -NoTypeInformation -Encoding UTF8
            }

            Write-Log "Passo 3/5 concluido: grupos de '$Sam' processados. Detalhe em '$logCsvUtilizador'."
        }
        catch {
            Write-Log "Falha no passo 3 (remover grupos) para '$Sam': $($_.Exception.Message)" -Nivel "ERRO"
            throw
        }
    }

    # Passo 4: mover a conta para OU=Contas-Desativadas,OU=NORTADA.
    $ouDestino = "OU=Contas-Desativadas,OU=NORTADA,$DomainDN"
    if ($PSCmdlet.ShouldProcess($Sam, "Passo 4: Mover para $ouDestino")) {
        try {
            Move-ADObject -Identity $conta.DistinguishedName -TargetPath $ouDestino -ErrorAction Stop
            Write-Log "Passo 4/5 concluido: conta '$Sam' movida para '$ouDestino'."
        }
        catch {
            Write-Log "Falha no passo 4 (mover para Contas-Desativadas) para '$Sam': $($_.Exception.Message)" -Nivel "ERRO"
            throw
        }
    }

    # Passo 5: marcar a descricao da conta com a data de saida e a referencia ao log do passo 3.
    $novaDescricao = "Saida em $DataSaida ($Motivo). Ver $(Split-Path -Leaf $logCsvUtilizador)."
    if ($PSCmdlet.ShouldProcess($Sam, "Passo 5: Atualizar Description para '$novaDescricao'")) {
        try {
            Set-ADUser -Identity $Sam -Description $novaDescricao -ErrorAction Stop
            Write-Log "Passo 5/5 concluido: Description de '$Sam' atualizada."
        }
        catch {
            Write-Log "Falha no passo 5 (atualizar Description) para '$Sam': $($_.Exception.Message)" -Nivel "ERRO"
            throw
        }
    }

    return "Sucesso"
}

# ---------------------------------------------------------------------------
# Import-Module ActiveDirectory
# ---------------------------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Log "Nao foi possivel importar o modulo ActiveDirectory: $($_.Exception.Message)" -Nivel "ERRO"
    throw "O modulo ActiveDirectory (RSAT) tem de estar disponivel para correr este script."
}

# ---------------------------------------------------------------------------
# Construcao da lista de saidas a processar
# ---------------------------------------------------------------------------

$saidas = @()

if (-not [string]::IsNullOrWhiteSpace($Utilizador)) {
    Write-Log "Modo de utilizador unico: -Utilizador '$Utilizador' indicado; data/saidas.csv nao sera lido."
    $saidas += [PSCustomObject]@{
        Sam       = $Utilizador
        DataSaida = (Get-Date -Format "yyyy-MM-dd")
        Motivo    = "Offboarding pontual via parametro -Utilizador"
    }
}
else {
    if (-not (Test-Path -Path $CaminhoSaidas)) {
        Write-Log "Ficheiro de saidas nao encontrado: $CaminhoSaidas" -Nivel "ERRO"
        throw "Ficheiro de saidas nao encontrado: $CaminhoSaidas"
    }

    try {
        $linhasSaidas = Import-Csv -Path $CaminhoSaidas -Encoding UTF8
    }
    catch {
        Write-Log "Falha ao ler o CSV de saidas '$CaminhoSaidas': $($_.Exception.Message)" -Nivel "ERRO"
        throw
    }

    foreach ($linha in $linhasSaidas) {
        if ([string]::IsNullOrWhiteSpace($linha.Nome) -or [string]::IsNullOrWhiteSpace($linha.Apelido)) {
            Write-Log "Linha de saidas sem Nome/Apelido valido, a ignorar: $($linha | Out-String)" -Nivel "ERRO"
            continue
        }
        $samCalculado = "$(ConvertTo-NomeUtilizador -Texto $linha.Nome).$(ConvertTo-NomeUtilizador -Texto $linha.Apelido)"
        $saidas += [PSCustomObject]@{
            Sam       = $samCalculado
            DataSaida = $linha.DataSaida
            Motivo    = $linha.Motivo
        }
    }
}

# ---------------------------------------------------------------------------
# Processamento de cada saida (conta normal e, se existir, conta administrativa)
# ---------------------------------------------------------------------------

$script:contadorSucesso = 0
$script:contadorIgnorados = 0
$script:contadorErros = 0

foreach ($saida in $saidas) {

    # Conta normal (ou a conta indicada explicitamente via -Utilizador).
    try {
        $resultado = Invoke-OffboardConta -Sam $saida.Sam -DataSaida $saida.DataSaida -Motivo $saida.Motivo
        switch -Wildcard ($resultado) {
            "Sucesso"  { $script:contadorSucesso++ }
            "Ignorado*" { $script:contadorIgnorados++ }
            default    { $script:contadorErros++ }
        }
    }
    catch {
        Write-Log "Offboarding de '$($saida.Sam)' interrompido por erro: $($_.Exception.Message)" -Nivel "ERRO"
        $script:contadorErros++
        continue
    }

    # Conta administrativa associada (adm.<utilizador>), se existir, apenas
    # quando a saida veio do CSV em lote (Nome/Apelido resolvido) ou quando o
    # proprio -Utilizador indicado nao ja comeca por "adm.".
    if (-not $saida.Sam.StartsWith("adm.")) {
        $samAdmin = "adm.$($saida.Sam)"
        $contaAdmin = Get-ADUser -Filter "SamAccountName -eq '$samAdmin'" -ErrorAction SilentlyContinue
        if ($contaAdmin) {
            Write-Log "Encontrada conta administrativa associada '$samAdmin' para '$($saida.Sam)'. A aplicar o mesmo processo de offboarding."
            try {
                $resultadoAdmin = Invoke-OffboardConta -Sam $samAdmin -DataSaida $saida.DataSaida -Motivo $saida.Motivo
                switch -Wildcard ($resultadoAdmin) {
                    "Sucesso"  { $script:contadorSucesso++ }
                    "Ignorado*" { $script:contadorIgnorados++ }
                    default    { $script:contadorErros++ }
                }
            }
            catch {
                Write-Log "Offboarding da conta administrativa '$samAdmin' interrompido por erro: $($_.Exception.Message)" -Nivel "ERRO"
                $script:contadorErros++
                continue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------

$resumo = "Resumo: $script:contadorSucesso conta(s) offboarded com sucesso, $script:contadorIgnorados conta(s) ja offboarded ignorada(s), $script:contadorErros erro(s)."
Write-Log $resumo
Write-Host $resumo

Write-Log "Fim da execucao do script 04-Offboard-User.ps1. Log completo em: $logFile"
