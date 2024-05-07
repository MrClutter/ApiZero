<#
.SYNOPSIS
    Query IP addresses in AbuseIPDB
.DESCRIPTION
    Query IP addresses in AbuseIPDB
    Attempts to use $env:AbuseIPDB_API_Key if -ApiKey is not provided
.EXAMPLE
	Get-AbuseIPInfo 1.1.1.1 -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049c4c48098d3049c4cffffffffff'
	Get-AbuseIPInfo 1.1.1.1, 8.8.8.8, 1.123.123.123 -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049c4c48098d3049c4cffffffffff'
#>
function Get-AbuseIPInfo {

    [CmdletBinding()]
    param (
        [Parameter(position=0, mandatory=$true, ValueFromPipeline=$true)]
        [IPAddress[]]$IPAddresses,
        [Parameter(position=1, mandatory=$false)]
        [String]$ApiKey
    )

    Begin{
        if (!$ApiKey){ $ApiKey = $env:AbuseIPDB_API_Key }
        if (!$ApiKey){ $ApiKey = $(Import-ApiZeroConfiguration).ApiKey.AbuseIPDB }
        if ($ApiKey.Length -ne 80){ throw 'Incorrect -ApiKey and $env:AbuseIPDB_API_Key does not exist or is incorrect' }
		
        [Uri]$ApiUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress="
        $headers = @{ 
            "Key" = $ApiKey
        }
        $params = @{
            "verbose" = $true
        }
        $results = @()
        $Proxy = $([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($ApiUrl)
    }

    Process{
        foreach ($IP in $IPAddresses) {
            [Uri]$Url = "$ApiUrl$($IP.ToString())"
            $response = Invoke-RestMethod -Uri $Url -Method Get -Headers $headers -Body $params -Proxy $Proxy -ProxyUseDefaultCredentials
            $results += $response.data
        }

        return $results
    }

    End{}
}