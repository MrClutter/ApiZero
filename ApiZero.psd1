@{

    RootModule = 'ApiZero.psm1'
    ModuleVersion = '0.1.1'
    CompatiblePSEditions = 'Desktop', 'Core'
    GUID = '3dcce418-ec4c-4f52-9f30-a1a960ce4465'
    Author = 'MrClutter'
    CompanyName = '---'
    Copyright = '(c) 2024 MrClutter. All rights reserved.'
    Description = 'ApiZero'
    FunctionsToExport = @(
        'Edit-ApiZeroConfiguration',
        'Get-AbuseIPInfo',
        'Get-VirusTotalFileInfo',
        'Invoke-AbuseIPCheck',
        'Invoke-Comcert',
        'Invoke-SiteCheck',
        'Invoke-UrlscanScan',
        'Invoke-VirusTotalUrlScan'        
        )
    CmdletsToExport = @('')
    VariablesToExport = @('')
    AliasesToExport = @('')
    PrivateData = @{
        PSData = @{}
    }
}
