@{
    # PSScriptAnalyzer rules for Windows Security Audit Framework
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPlainTextForPassword',
        'PSShouldProcess',
        'PSUseDeclaredVarsMoreThanAssignments'
    )
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',      # Write-Host is intentionally used for styled CLI output
        'PSAvoidUsingInvokeExpression' # Used safely where required
    )
}
