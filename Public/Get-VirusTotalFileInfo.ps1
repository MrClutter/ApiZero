<#
.SYNOPSIS
    Query MD5, SHA1 or SHA256 in VirusTotal
.DESCRIPTION
    Query MD5, SHA1 or SHA256 in VirusTotal
    Attempts to use $env:VirusTotal_API_Key if -ApiKey is not provided
.EXAMPLE
	Get-VirusTotalFileInfo b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff
	Get-VirusTotalFileInfo b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff'
#>
function Get-VirusTotalFileInfo {    
  
    [CmdletBinding()]
    param (
        [Parameter(possition=0, mandatory=$true)]
        [string]$Hash,
        [Parameter(position=1, mandatory=$false)]
        [String]$ApiKey
    )

    Begin{
        if (!$ApiKey) { $ApiKey = $env:VirusTotal_API_Key}
	    if ($ApiKey.Length -ne 64){ throw 'Incorrect -ApiKey and $env:VirusTotal_API_Key does not exist or is incorrect' }
	    if ($Hash.Length -notin 32,40,64){ throw 'Incorrect hash value' }

        $VirusTotalUrl = "https://www.virustotal.com/api/v3/files/$Hash"
        $headers = @{ "apikey" = $ApiKey }
    }

    Process{
        $response = Invoke-RestMethod -Method GET -Uri $VirusTotalUrl -Headers $headers
        return $response.data.attributes
    }

    End{}
}