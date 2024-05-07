<#
.SYNOPSIS
    Query IP addresses in AbuseIPDB
.DESCRIPTION
    Query IP addresses in AbuseIPDB
    Attempts to use $env:AbuseIPDB_API_Key if -ApiKey is not provided
.EXAMPLE
	Invoke-AbuseIPCheck 1.1.1.1 -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049c4c48098d3049c4cffffffffff'
	Invoke-AbuseIPCheck 1.1.1.1, 8.8.8.8, 1.123.123.123 -ApiKey 'b029393ea7b7cf644fb1c9f984f57c1980077562ee2e15d0ffd049c4c48098d3049c4cffffffffff'
#>
function Invoke-AbuseIPCheck {

    [CmdletBinding()]
    param (
        [Parameter(position=0, mandatory=$true, ValueFromPipeline=$true)]
        [IPAddress[]]$IPAddresses,
        [Parameter(position=1, mandatory=$false)]
        [String]$Ticket,
        [Parameter(position=2, mandatory=$false)]
        [String]$ApiKey
    )

    Begin{
        if($Ticket -And (-Not ($Ticket -match '^Ticket#\d{16}$'))){
            throw "Niepoprawny nr zgloszenia"
        }
        $Config = $(Import-ApiZeroConfiguration)
        [System.Collections.ArrayList]$results = @()
		
		Write-Host 'Weryfikowanie IP:'
        $i = 0
    }

    Process{
        foreach($IP in $IPAddresses){
            $i++
            Write-Host -NoNewline "`r                                                 "
            Write-Host -NoNewline "`r($i) $IP"
            [void]$results.Add( $(Get-AbuseIPInfo -IPAddresses $IP -ApiKey $ApiKey) )
        }
    <# 
        $a = $(Get-Content 'C:\Users\\Downloads\AbuseIP_20240505T132758.json' | ConvertFrom-Json)
        foreach($_ in $a){
            [void]$results.Add($_)
        }  #>

    }

    End{
        $results = $results | Sort-Object -Property abuseConfidenceScore -Descending

        $OutFile = @{}
        $OutFile.Data = $($results | ConvertTo-Json -Depth 5)
        $OutFile.Format = '.json'

        $OutFile.Dir = $($env:USERPROFILE + '\Downloads\')
        $OutFile.DateTime = $(Get-Date -Format "yyyMMddTHHmmss")
        $OutFile.Name = $('AbuseIP_' + $OutFile.DateTime + $OutFile.Format)

        $OutFile.FullPath = [IO.Path]::GetFullPath($OutFile.Dir + $OutFile.Name)

        [IO.File]::WriteAllText($OutFile.FullPath, $OutFile.Data)

        if ($Ticket){
            $Subject = $('AbuseIP check [{0}]' -f $Ticket)
        }else{
            $Subject = 'AbuseIP check'
        }

        [System.Collections.ArrayList]$Body = @()
        [void]$Body.Add('<html><body><style>')
        [void]$Body.Add('TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}')
        [void]$Body.Add('TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}')
        [void]$Body.Add('TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}')
        [void]$Body.Add('</style><h1>' + $Subject + '</h1><br>')

        # 1st table
        [void]$Body.Add('<table>')
        [void]$Body.Add('<tr style="background-color:#cccccc; font-weight: bold"><td>' + 'IP Address' `
                        + '</td><td>' + 'Country Code' `
                        + '</td><td>' + 'ISP' `
                        + '</td><td>' + 'Domain' `
                        + '</td><td>' + 'Hostnames' `
                        + '</td><td>' + 'Abuse Score' `
                        + '</td><td>' + 'Raports / Distinct Users' `
                        + '</td></tr>')

        foreach($record in $results){
            if ($record.abuseConfidenceScore -eq 0){
                $bgColor = '#70ff70'
            }
            elseif ($record.abuseConfidenceScore -ge 25){
                $bgColor = '#ff7070'
            }
            else {
                $bgColor = '#ffff70'
            }

            $Tor = ''
            if($record.isTor){ $Tor = ' (Tor)' }
            [void]$Body.Add('<tr style="background-color:{0};"><td>' -f $bgColor + $record.ipAddress `
                            + '</td><td>' + $record.countryCode `
                            + '</td><td>' + $record.isp `
                            + '</td><td>' + $record.domain `
                            + '</td><td>' + $($record.hostnames -join '<br>') `
                            + '</td><td>' + $record.abuseConfidenceScore `
                            + '</td><td>' + @($record.totalReports, "/", $record.numDistinctUsers, $Tor) -join ' '    `
                            + '</td></tr>')
        }
        [void]$Body.Add('</table><br>')
        
        <# 
        # 2nd table; dont append individual records if there is more than 5 of them 
        if($results.length -lt 6){
            foreach($record in $results){
                [void]$Body.Add('<hr><br><table>')
                    foreach($field in $record.PsObject.Properties){ 
                        [void]$Body.Add('<tr><td>' + $field.Name + '</td><td>' + $( $field.Value -join ', ' ) + '</td></tr>')
                    }
                [void]$Body.Add('</table><br>')
            }
        } #>
        
        [void]$Body.Add('</body></html>')

        if($Ticket){ $To = $Config.Mail.Recipient }
        else{ $To = $Config.Mail.Sender }

        Send-MailMessage `
            -SmtpServer $Config.Mail.SmtpServer `
            -From       $Config.Mail.Sender `
            -To         $To `
            -cc         $Config.Mail.cc `
            -Subject    $Subject `
            -encoding   $Config.Mail.Encoding `
            -Body       $($Body -join '')`
            -BodyAsHtml `
            -Attachments $OutFile.FullPath


        [System.Collections.ArrayList]$Html = @()
        [void]$Html.Add(
            '<!DOCTYPE html>
            <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
                <style>
                    .collapsible {
                        background-color: #777;
                        color: white;
                        cursor: pointer;
                        padding: 18px;
                        width: 100%;
                        border: none;
                        text-align: left;
                        outline: none;
                        font-size: 15px;
                    }
        
                    .active, .collapsible:hover {
                        background-color: #ddd;
                    }
        
                    .content {
                        padding: 0 18px;
                        max-height: 0;
                        overflow: hidden;
                        transition: max-height 0.2s ease-out;
                        background-color: #f1f1f1;
                    }
                    .clean{
                        background-color: rgb(60, 255, 109);
                        color: #333;
                    }
                    .suspicious{
                        background-color: rgb(255, 240, 103);
                        color: #333;
                    }
                    .malicious{
                        background-color: rgb(255, 113, 113);
                        color: #333;
                    }
                </style>
            </head>'
        )
        [void]$Html.Add('<body>
        <div class="w3-container">
            <h1>AbuseIPDB Check</h1>
        </div>
    
        <div class="w3-row">
            <div class="table w3-third w3-container">
                <h2>Table</h2>
                <table id="ipSummaryTable" class="w3-table-all">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Country</th>
                            <th>ISP</th>
                            <th>Abuse Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Summary rows will be added here dynamically -->
                    </tbody>
                </table>
            </div>
            <div class="table w3-twothird w3-container" id="detailSections">
            <h1>Details</h1>
                <!-- Collapsible sections will be added here dynamically -->
            </div>
        </div>
        
            
        <script>
            document.addEventListener("DOMContentLoaded", function() {
        ')

        [void]$Html.Add(@('const ipData = ', $OutFile.Data) -join '')

            
        [void]$Html.Add('   
                const summaryTableBody = document.getElementById("ipSummaryTable").getElementsByTagName("tbody")[0];
                const detailContainer = document.getElementById("detailSections");
            
                ipData.forEach(ip => {
                    // Adding row to summary table
                    const row = summaryTableBody.insertRow();
                    row.insertCell(0).textContent = ip.ipAddress;
                    row.insertCell(1).textContent = ip.reporterCountryCode;
                    row.insertCell(2).textContent = ip.isp;
                    row.insertCell(3).textContent = ip.abuseConfidenceScore;
            
                    // Setting row color based on abuse score
                    const score = parseInt(ip.abuseConfidenceScore);
                    if (score === 0) {
                        row.style.backgroundColor = "lightgreen";
                    } else if (score > 0 && score < 100) {
                        row.style.backgroundColor = "yellow";
                    } else if (score === 100) {
                        row.style.backgroundColor = "rgb(255, 155, 155)";
                    }
            
                    // Creating collapsible sections for detailed reports
                    const button = document.createElement("button");
            
                    if (score === 0) {
                        button.className = "collapsible clean";
                    } else if (score > 0 && score < 100) {
                        button.className = "collapsible suspicious";
                    } else if (score === 100) {
                        button.className = "collapsible malicious";
                    }
                    
                    button.textContent = "[" + ip.totalReports +"] " + ip.ipAddress + " (Score: " + ip.abuseConfidenceScore + ") " + ip.countryName +  " [" + ip.isp + " | " + ip.usageType + "] " ;
                    detailContainer.appendChild(button);
            
                    const contentDiv = document.createElement("div");
                    contentDiv.className = "content";
                    detailContainer.appendChild(contentDiv);
            
                    const table = document.createElement("table");
                    table.className = "w3-table-all";
                    contentDiv.appendChild(table);
            
                    // Header for detailed reports table
                    const thead = table.createTHead();
                    const headerRow = thead.insertRow();
                    const headers = ["Date", "Comment", "Reporter ID", "Country"];
                    headers.forEach(text => headerRow.insertCell().textContent = text);
            
                    // Inserting detailed report data into table
                    const tbody = table.createTBody();
                    ip.reports.forEach(report => {
                        const detailRow = tbody.insertRow();
                        detailRow.insertCell().textContent = report.reportedAt;
                        detailRow.insertCell().textContent = report.comment;
                        detailRow.insertCell().textContent = report.reporterId;
                        detailRow.insertCell().textContent = report.reporterCountryName;
                    });
                });
            
                // Collapsible logic
                const coll = document.getElementsByClassName("collapsible");
                for (let i = 0; i < coll.length; i++) {
                    coll[i].addEventListener("click", function() {
                        this.classList.toggle("active");
                        const content = this.nextElementSibling;
                        if (content.style.maxHeight){
                            content.style.maxHeight = null;
                        } else {
                            content.style.maxHeight = content.scrollHeight + "px";
                        } 
                    });
                }
            });
            </script>
            
            
                </body>
            </html>'
            ) 
        
        $OutFile.Name = $('AbuseIP_' + $OutFile.DateTime + '.html')
        $OutFile.FullPath = [IO.Path]::GetFullPath($OutFile.Dir + $OutFile.Name)
        
        [IO.File]::WriteAllText($OutFile.FullPath, $($Html -join "`r`n"))

        . $OutFile.FullPath
    } 
}