$repoRoot = 'c:\Users\OLUDEMI JOSHUA\Downloads\AD_PS-master\AD_PS-master'
$files = Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } | Sort-Object FullName
$parseErrors = @()
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $parseErrors += "$($file.FullName): $($errors | ForEach-Object { $_.Message } | Select-Object -First 3 | Join-String '; ')"
    }
}
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_ }
    exit 1
}
Write-Host "PowerShell syntax OK: $($files.Count) files parsed without errors."
