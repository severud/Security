$ntfsBackup = "$env:WinDir\Temp\ntfspermsConfigDir.txt"
$ntfsLog = "$env:WinDir\Temp\ntfspermsConfigLog.txt"

write-Output "$env:ComputerName - cve-2021-36934 vulnerability mitigation" | Out-File -FilePath $ntfsLog -Force 

$ErrorActionPreference = "SilentlyContinue" ;
if ((get-acl C:\windows\system32\config\sam).Access |
Where-Object IdentityReference -match 'BUILTIN\\Users' |
Select-Object -expandproperty filesystemrights |
select-string 'Read'){
    write-Output "System appears vulnerable" | Out-File -FilePath $ntfsLog -Append 
    icacls $env:windir\system32\config\*.* /save $icaclBackup  /t /c
    icacls $env:windir\system32\config\*.* /inheritance:e

    if ((get-acl C:\windows\system32\config\sam).Access |
        Where-Object IdentityReference -match 'BUILTIN\\Users' |
        Select-Object -expandproperty filesystemrights |
        select-string 'Read'){
            write-Output "System was not fixed" | Out-File -FilePath $ntfsLog -Append 
    }else{
        write-Output "System permissions mitigated" | Out-File -FilePath $ntfsLog -Append 
    }

    if( (vssadmin list shadows /for=c:).count -gt 4 ){
        write-Output "System shadow copies found" | Out-File -FilePath $ntfsLog -Append 
        vssadmin delete shadows /for=c: /all /quiet
        write-Output "System shadow copies deleted" | Out-File -FilePath $ntfsLog -Append
    }

    if( (vssadmin list shadows /for=c:).count -gt 4 ){
        write-Output "System shadow copies still exist" | Out-File -FilePath $ntfsLog -Append
    }else{
        write-Output "System shadow copies Removed" | Out-File -FilePath $ntfsLog -Append 
    }

    #icacls $env:windir\system32\config\ /restore $ntfsBackup

}else { 
    write-Output "System does not seem to be vulnerable, SAM permissions are fine" | Out-File -FilePath $ntfsLog -Append 
}
