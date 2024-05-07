<#
.SYNOPSIS
    VirusTotal Scan URL
.DESCRIPTION
    Attempts to use $env:VirusTotal_API_Key if -ApiKey is not provided
.EXAMPLE
	Get-VirusTotalFileInfo b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff
	Get-VirusTotalFileInfo b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049ffffffffff'
#>
function Invoke-VirusTotalUrlScan {    
  
    [CmdletBinding()]
    param (
        [Parameter(position=0, mandatory=$true)]
        [Uri]$Url,
        [Parameter(position=1, mandatory=$false)]
        [String]$ApiKey
    )

    Begin{
        if (!$ApiKey) { $ApiKey = $env:VirusTotal_API_Key}
	    if ($ApiKey.Length -ne 64){ throw 'Incorrect -ApiKey and $env:VirusTotal_API_Key does not exist or is incorrect' }

        $req = @{
            apiUrl = "https://www.virustotal.com/api/v3/urls"
            headers = @{ 
                "accept"        = "application/json"
                "content-type"  = "application/x-www-form-urlencoded"
                "x-apikey"      = $ApiKey
            }
        }
    }

    Process{
        $response = Invoke-WebRequest -Method POST -Uri $req.apiUrl -Headers $req.headers -Body "url=$Url"
        $response = ($response.content | ConvertFrom-Json)
        
        Start-Sleep -Seconds 10

        $VtUrlId =  $($response.data.id).Split('-')[1]
        $reqUrl = $($req.apiUrl + "/" + $VtUrlId)
        try {
            $result = Invoke-WebRequest -Method GET -Uri $reqUrl -Headers $req.headers
        }
        catch {
            throw Write-Error $_.Exception.InnerException.Message -ErrorAction 
        }

        return $($result.content | ConvertFrom-Json).data
    }

    End{}
}