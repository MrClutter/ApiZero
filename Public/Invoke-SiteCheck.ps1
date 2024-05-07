
<#
.SYNOPSIS
	Performs series of api calls in order to verify whenever site is malicious
.DESCRIPTION
    Uses:
        $env:Abuseipdb_API_Key
        $env:VirusTotal_API_Key
        $env:Urlscan_API_Key
        
        edit with Windows + R 'rundll32 sysdm.cpl,EditEnvironmentVariables'
.PARAMETER URL
	ULR of malicious site
.EXAMPLE
	Invoke-SiteCheck https://your.site.test.com/asdf/xczv
	Invoke-SiteCheck https://your.site.test.com/asdf/xczv 123412341234123411234
#>

function Invoke-SiteCheck{
    [CmdletBinding()]
    param (
        [Parameter(position=0, mandatory=$true)]
        [Uri]$Url,
        [Parameter(position=1, mandatory=$false)]
        [string]$Ticket
    )

    Begin{
        if($Ticket -And (-Not ($Ticket -match '^Ticket#\d{16}$'))){
            throw "Niepoprawny nr zgloszenia"
        }
        $Config = $(Import-ApiZeroConfiguration)

        #Verify Api Tokens
	    if($Config.ApiKey.URLScanIo.Length -ne 36)      { throw 'Incorrect $env:Urlscan_API_Key does not exist or is incorrect' }
	    if($Config.ApiKey.VirusTotal.Length -ne 64)   { throw 'Incorrect $env:VirusTotal_API_Key does not exist or is incorrect' }
        
        $req = @{}
        $res = @{}
        $req.UrlScan = @{
            apiUrl          = "https://urlscan.io/api/v1/scan/"
            contentType     = "application/x-www-form-urlencoded"
            headers         = @{ 'API-Key' = $Config.ApiKey.URLScanIo }
            body            = @{ 'url' = $Url }
        }
        $screenshotFile = Get-ChildItem ([IO.Path]::GetTempFileName()) | Rename-Item -NewName { [IO.Path]::ChangeExtension($_, ".png") } -PassThru

        $req.vt = @{
            apiUrl = "https://www.virustotal.com/api/v3/urls"
            headers = @{ 
                "accept"        = "application/json"
                "content-type"  = "application/x-www-form-urlencoded"
                "x-apikey"      = $Config.ApiKey.VirusTotal
            }
        }

        $results = @{}
    }
    
    Process{
        
        #START scans
        try{
            $res.Urlscan = Invoke-RestMethod -Method Post -Uri $req.Urlscan.apiUrl -Headers $req.Urlscan.headers -Body $req.Urlscan.body -ContentType $req.Urlscan.contentType
            $res.vt = Invoke-WebRequest -Method POST -Uri $req.vt.apiUrl -Headers $req.vt.headers -Body "url=$Url"
            $res.vt = ($res.vt.content | ConvertFrom-Json)
        }catch{
            throw $_
        }

        if(-Not ($res.Urlscan.message = "Submission successful")){
            throw "URLScanIo submission failed"
        }

        #Wait for results
        Write-Host 'URLScanIo: Submission successful'
        for($i = 10; $i -gt -1; $i--){
            Write-Host -NoNewline "`rURLScanIo: Waiting for results $i "
            Start-Sleep -Seconds 1
        }

        # URLScanIo
        $cnt = 0
        $cntMax = 10
        Write-Host -NoNewline "`rURLScanIo: Downloading results        "
        Write-Host  ' '
        do{
            $cnt++
            try{
                $results.URLScan = Invoke-RestMethod -Method Get -Uri $res.Urlscan.api
                try {
                    Invoke-RestMethod -Method get -Uri $results.URLScan.task.screenshotURL -OutFile $screenshotFile.FullName
                    $results.URLScan | Add-Member -MemberType NoteProperty -Name "screenshot" -Value $screenshotFile
                }
                catch {
                    Write-Host 'URLScanIo: No Screenshot'
                }
                break
            } catch {
                # if($cnt -eq 1){ Write-Error $_.Exception.InnerException.Message -ErrorAction Continue } 
                Write-Host -NoNewline "`rFailed attempts $cnt / $cntMax"
                if ($cnt -lt $cntMax) { Start-Sleep -Seconds 2 }
            }
        } while ($cnt -lt $cntMax)

        #VirusTotal

        Write-Host "`nVirusTotal: Downloading results        "
        $VtUrlId =  $($res.vt.data.id).Split('-')[1]
        $reqUrl = $($req.vt.apiUrl + "/" + $VtUrlId)
        try {
            $result = Invoke-WebRequest -Method GET -Uri $reqUrl -Headers $req.vt.headers
        }
        catch {
            Write-Error $_.Exception.InnerException.Message -ErrorAction SilentlyContinue
        }

        $results.vt = $($result.content | ConvertFrom-Json).data

        #$results = $(Get-Content "$env:USERPROFILE\Downloads\SiteCheck_20240403T145127.json" | ConvertFrom-Json)
    }
    End{
        $OutFile = @{}
        $OutFile.Data = $($results | ConvertTo-Json)
        $OutFile.Format = '.json'

        $OutFile.Dir = $($env:USERPROFILE + '\Downloads\')
        $OutFile.Name = $('SiteCheck_' + $(Get-Date -Format "yyyMMddTHHmmss") + $OutFile.Format)

        $OutFile.FullPath = [IO.Path]::GetFullPath($OutFile.Dir + $OutFile.Name)

        [IO.File]::WriteAllText($OutFile.FullPath, $OutFile.Data)

        if($Ticket){
            $Subject = $('Site check [{0}]' -f $Ticket)

            [System.Collections.ArrayList]$Body = @()
            [void]$Body.Add('<html><body><style>')
            [void]$Body.Add('TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}')
            [void]$Body.Add('TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}')
            [void]$Body.Add('TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}')
            [void]$Body.Add('</style>')
            [void]$Body.Add('<h1>' + $Subject + '</h1>')
            [void]$Body.Add('<h2>{0}</h2>' -f $($results.URLScan.page.domain -replace '\.', '[.]'))
            [void]$Body.Add('<img height="350" src="cid:{0}" /><br>' -f $screenshotFile.Name)
            [void]$Body.Add('IP: {0} ({1}: {2}) [{3}]<br>' -f @($results.URLScan.page.ip, $results.URLScan.page.country, $results.URLScan.page.city, $results.URLScan.page.asnname))
            [void]$Body.Add('URL: {0}<br>' -f $($results.URLScan.page.url -replace '\.', '[.]' -replace 'http', 'hxxp'))
            [void]$Body.Add('TLS Certificate Issued by {0} on {1} ({2} days old)<br>' -f @($results.URLScan.page.tlsIssuer, $results.URLScan.page.tlsValidFrom, $results.URLScan.page.tlsAgeDays))
            
            # 1st table
            [void]$Body.Add('<h2>urlscan.io Verdicts:</h2>')
            [void]$Body.Add('<table>')
            foreach($record in $results.URLScan.verdicts.urlscan.PsObject.Properties){
                if ($record.value -eq 0){
                    $bgColor = '#ffffff'
                }
                elseif ($record.value -gt 35){
                    $bgColor = '#ff7070'
                }
                elseif ($record.value -gt 0) {
                    $bgColor = '#ffff70'
                }
                [void]$Body.Add('<tr><td style="background-color:#cccccc; font-weight: bold">{0}</td><td style="background-color:{2};">{1}</td></tr>' -f @($record.name, $( $record.Value -join ', ' ), $bgColor))
            }
            [void]$Body.Add('</table><br>')


            
            # Table 2
            [void]$Body.Add('<h2>Virus Total Stats:</h2>')
            [void]$Body.Add('<table>')
            foreach($record in $results.vt.attributes.last_analysis_stats.PsObject.Properties){
                if ($record.value -eq 0){
                    $bgColor = '#ffffff'
                }
                elseif ($record.value -gt 35){
                    $bgColor = '#ff7070'
                }
                elseif ($record.value -gt 0) {
                    $bgColor = '#ffff70'
                }
                [void]$Body.Add('<tr><td style="background-color:#cccccc; font-weight: bold">{0}</td><td style="background-color:{2};">{1}</td></tr>' -f @($record.name, $( $record.Value -join ', ' ), $bgColor))
            }
            [void]$Body.Add('</table><br>')

            [void]$Body.Add('<table>')
            foreach($record in $results.vt.attributes.last_analysis_results.PsObject.Properties){
                if($record.Value.category -match 'harmless' -or $record.Value.category -match 'undetected'){
                    continue
                }
                [void]$Body.Add('<tr><td style="background-color:#cccccc; font-weight: bold">{0}</td><td style="background-color:{3};">{1} {2}</td></tr>' -f @($record.name, $record.Value.category,  $record.Value.result,  $bgColor))
            }
            [void]$Body.Add('</table><br>')

            [void]$Body.Add('</body></html>')

            Send-MailMessage `
                -SmtpServer $Config.Mail.SmtpServer `
                -From       $Config.Mail.Sender `
                -To         $Config.Mail.Recipient `
                -cc         $Config.Mail.cc `
                -Subject    $Subject `
                -encoding   $Config.Mail.Encoding `
                -Body       $($Body -join '')`
                -BodyAsHtml `
                -Attachments $OutFile.FullPath, $screenshotFile.FullName
        }
        return $results
    }
}
