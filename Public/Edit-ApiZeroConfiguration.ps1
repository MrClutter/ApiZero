<#
.SYNOPSIS
    Edits configuration of ApiZero
.DESCRIPTION
    Edits configuration of ApiZero
    To create new configuration or overwrite old one use [-NewConfiguration] it creates new configu out of Prototype 
.EXAMPLE
	Edit-ApiZeroConfiguration
	Edit-ApiZeroConfiguration -NewConfiguration
#>
function Edit-ApiZeroConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(position=0)]
        [switch]$NewConfiguration
    )
    begin{
        $Config = @{}
        $Config.File = @{}
        $Config.PrototypeJson = [IO.Path]::GetFullPath($PSScriptRoot + '\Prototype\Configuration.json')
        $Config.File.Dir = [IO.Path]::GetFullPath($env:APPDATA + "\WindowsPowerShell\ApiZero\")
        $Config.File.json = [IO.Path]::GetFullPath($($Config.File.Dir + "\ApiZero.json"))
        
    }
    
    process{
        Write-Debug $('$Config.File: ' + $Config.File)
        if(-not [IO.Directory]::Exists($Config.File.Dir)){
            [IO.Directory]::CreateDirectory($Config.File.Dir)
        }
        Write-Debug $('$NewConfiguration: ' + $NewConfiguration)
        $ConfigurationExists = [IO.File]::Exists($Config.File.json)
        if($NewConfiguration -or (-Not $ConfigurationExists)){
            try{
                $Config.File.Bak = [IO.Path]::GetFullPath(@($Config.File.json, [datetime]::Now.ToFileTime(), 'bak') -join '.')
                [IO.File]::Move($Config.File.json, $Config.File.Bak)
            }catch{
                Write-Debug $('Failed to backup old configuration: ' + $_.Exception.Message)
            }
            [IO.File]::Copy($Config.PrototypeJson, $Config.File.json)
            notepad.exe $Config.File.json
        }elseif($ConfigurationExists){
            notepad.exe $Config.File.json
        }else{
            throw 'Undetermined error: All case checks failed'
        }
    }

    end{}


}