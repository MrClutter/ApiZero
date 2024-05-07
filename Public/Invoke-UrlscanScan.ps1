<#
.SYNOPSIS
    Invoke Urlscan.io Scan
.DESCRIPTION
    Uses Urlscan.io API to start scan and fetch its response  
    Attempts to use $env:Urlscan_API_Key if -ApiKey is not provided
.EXAMPLE
	Invoke-UrlscanScan "example.com/foo"
	Invoke-UrlscanScan "example.com/foo" -ApiKey '9eb95d24-cf0b-4db7-af95-ffffffffffff'
#>
function Invoke-UrlscanScan {

    [CmdletBinding()]
    param (
        [Parameter(position=0, mandatory=$true)]
        [Uri]$Url,
        [Parameter(position=1, mandatory=$false)]
        [String]$ApiKey
    )
	
    begin{
        if (!$ApiKey) { $ApiKey = $env:Urlscan_API_Key }
	    if ($ApiKey.Length -ne 36){ throw 'Incorrect -ApiKey and $env:Urlscan_API_Key does not exist or is incorrect' }
        
        $req = @{
            apiUrl          = "https://urlscan.io/api/v1/scan/"
            contentType     = "application/x-www-form-urlencoded"
            headers         = @{ 'API-Key' = $ApiKey }
            body            = @{ 'url' = $Url }
        }

        $screenshotFile = New-TemporaryFile
    }

    process{
        $res = Invoke-RestMethod  -Method Post -Uri $req.apiUrl -Headers $req.headers -Body $req.body -ContentType $req.contentType
        if( $res.message = "Submission successful" ){
            Start-Sleep -Seconds 10

            $cnt = 0
            $cntMax = 10
            do{
                $cnt++
                try{
                    $scanResult = Invoke-RestMethod -Method Get -Uri $res.api
                    Invoke-RestMethod -Method get -Uri $scanResult.task.screenshotURL -OutFile $screenshotFile.FullName
                    #Curl.exe -s -o $screenshotFile $scanResult.task.screenshotURL
                    $scanResult | Add-Member -MemberType NoteProperty -Name "screenshot" -Value $screenshotFile
                    break
                } catch {
                    if($cnt -eq 1){ Write-Error $_.Exception.InnerException.Message -ErrorAction Continue } 
                    Write-Error -NoNewline "`rFailed attempts $cnt / $cntMax"
                    if ($cnt -lt $cntMax) { Start-Sleep -Seconds 2 }
                }
            } while ($cnt -lt $cntMax)
            
            return $scanResult
        }
        throw "Taks failed: $($res.message)"
    }

    End{}
}