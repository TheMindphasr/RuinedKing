function B64 {
[CmdletBinding(DefaultParameterSetName="encFile")]
param(
    [Parameter(Position=0, ParameterSetName="encFile")]
    [Alias("ef")]
    [string]$encFile,

    [Parameter(Position=0, ParameterSetName="encString")]
    [Alias("es")]
    [string]$encString,

    [Parameter(Position=0, ParameterSetName="decFile")]
    [Alias("df")]
    [string]$decFile,

    [Parameter(Position=0, ParameterSetName="decString")]
    [Alias("ds")]
    [string]$decString

)

if ($psCmdlet.ParameterSetName -eq "encFile") {
		$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $encFile -Raw -Encoding UTF8)))
		return $encoded
		}

elseif ($psCmdlet.ParameterSetName -eq "encString") {
		$File = "$env:TEMP\foob64.txt"
		Set-Content -NoNewline -Path $File -Value $encString	
		$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $File -Raw -Encoding UTF8)))
		Remove-Item $File
		return  $encoded
		}

elseif ($psCmdlet.ParameterSetName -eq "decFile") {
		$data = Get-Content $decFile
		$decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data))
		return $decoded		
		}

elseif ($psCmdlet.ParameterSetName -eq "decString") {
		$File = "$env:TEMP\foob64.txt"
		Set-Content -NoNewline -Path $File -Value $decString
		$data = Get-Content $File		
		$decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data))
		Remove-Item $File
		return $decoded
		}
}

B64 -EncFile "C:\Users\remy.mauras\OneDrive - METSYS\Documents\GitHub\RuinedKing\StartGame.ps1" > encoded_StartGame.ps1