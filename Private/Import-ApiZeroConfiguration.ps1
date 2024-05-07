function Import-ApiZeroConfiguration {
    [CmdletBinding()]
    param()
    begin{
        $Config = @{}
        $Config.File = @{}
        $Config.File.Dir = [IO.Path]::GetFullPath($env:APPDATA + "\WindowsPowerShell\ApiZero\")
        $Config.File.json = [IO.Path]::GetFullPath($($Config.File.Dir + "\ApiZero.json"))
        
    }
    
    process{
        try {
            $Config.data = $([IO.File]::ReadAllLines($Config.File.json) | ConvertFrom-Json)
            $Config.data.mail.encoding = New-Object System.Text.utf8encoding
        }
        catch {
            Edit-ApiZeroConfiguration -NewConfiguration
        }
        return $Config.data
    }

    end{}
}
