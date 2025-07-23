### (Hopefully) can be run from any domain-joined endpoint
### No idea if this will even work

$creds = Get-Credential -Message "Enter credentials for remote access"
$cas = Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -Properties dNSHostName, name

foreach($ca in $cas) {
    $caServer = $ca.dNSHostName
    $caName = $ca.name
    Write-Host "Checking CA: $caName on $caServer"
    
    try {
        $result = Invoke-Command -ComputerName $caServer -Credential $creds -ScriptBlock {
        param($caName)
        $vulnerable = $false
        $policyModulesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules"
        
        $policyModules = Get-ChildItem -Path $policyModulesPath -ErrorAction SilentlyContinue
        
        if($policyModules) {
            foreach($module in $policyModules) {
                $moduleName = $module.PSChildName
                
                $disabled = Get-ItemProperty -Path $module.PSPath -Name "DisableExtensionList" -ErrorAction SilentlyContinue
                if($disabled.DisableExtensionList -like "*1.3.6.1.4.1.311.25.2*") {
                    Write-Host "      [VULNERABLE] Security Extension disabled in $moduleName"
                    $vulnerable = $true
                } else {
                    Write-Host "      [SAFE] Security Extension enabled in $moduleName"
                }
            }
        } else {
            Write-Host "    No policy modules found or access denied"
        }
        
        return $vulnerable
    } -ArgumentList $caName -ErrorAction Stop
}

### StrongCertificateBindingEnforcement section

$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
$weakBindingDCs = @()

foreach($dc in $dcs) {
    try {
        $bindingValue = Invoke-Command -ComputerName $dc -Credential $creds -ScriptBlock {
            $value = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -ErrorAction SilentlyContinue
            if($value) { return $value.StrongCertificateBindingEnforcement } else { return $null }
        } -ErrorAction SilentlyContinue
        
        if($bindingValue -ne 2) {
            $weakBindingDCs += "$dc (Value: $bindingValue)"
        } else {
            Write-Host "$dc - Full Enforcement (Value: 2)"
        }
    } catch {
        Write-Host "? $dc - Cannot access (Error: $($_.Exception.Message))"
    }
}

if($weakBindingDCs.Count -gt 0) {
    Write-Host "`n[WEAK BIND] DCs not in Full Enforcement mode:"
    foreach($dc in $weakBindingDCs) {
        Write-Host "  - $dc"
    }
} else {
    Write-Host "`nAll DCs in Full Enforcement mode"
}
