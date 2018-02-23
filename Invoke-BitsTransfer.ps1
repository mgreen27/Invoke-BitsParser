<#
.SYNOPSIS
	Invoke-BitsTransfer.ps1 carves BITS file transfers from QMGR queue and alerts on suspicious entries.

    Name: Invoke-BitsTransfer.ps1
    Version: 0.1 (POC)
    Author: Matt Green (@mgreen27)

.DESCRIPTION
    Invoke-BitsTransfer.ps1 carves BITS file transfer details from QMGR files.
    Finding XferHeaders, Invoke-BitsTransfer then searches for valid paths and outputs to stdout.
    
    QMGR files are named qmgr0.dat or qmgr1.dat and located in the folder %ALLUSERSPROFILE%\Microsoft\Network\Downloader.
    Run to carve all File transfer information - Source and Destination. Then look for unusual entries.
    Currently not supported on Windows 10 with different formatting.

.PARAMETER Path
	Use this parameter to run against a previously collected QMgr file.

.EXAMPLE
	Invoke-BitsTransfer.ps1

    Run Invoke-BitsTransfer in report all mode. Will report all Files found after carving xferheaders

.EXAMPLE
	Invoke-BitsTransfer.ps1 -Path c:\cases\bits\qmgr0.dat

    Run Invoke-BitsTransfer in offline mode

.NOTES
    Initial Python parser used as inspiration by ANSSI here - https://github.com/ANSSI-FR/bits_parser
    Invoke-BitsTransfer currently only carves XferHeaders.

    XferHeader (32): 36-DA-56-77-6F-51-5A-43-AC-AC-44-A2-48-FF-F3-4D
#>

[CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)][String]$Path="$env:ALLUSERSPROFILE\Microsoft\Network\Downloader",
        [Parameter(Mandatory = $False)][Switch]$LiveMode = $True,
        [Parameter(Mandatory = $False)][Switch]$All

)

    # Set switches
    $Verbose = $PSBoundParameters.ContainsKey("Verbose")
    If ($PSBoundParameters.ContainsKey("Path")){$LiveMode = $False}

    # Test for Elevated privilege if required
    If ($Path -eq "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader"){
        If (!(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))){
            Write-Host -ForegroundColor Red "Exiting Invoke-BitsDetect: Elevated privilege required for LiveResponse Mode"
            exit
        }
    }

    # Determine files in scope
    if(Test-Path $Path -pathType container){
        $QmgrFiles = (Get-ChildItem $Path -Filter qmgr*.dat).FullName
    }
    ElseIf(Test-Path $Path -pathType Leaf){
        $QmgrFiles = $Path
    }


   ## Regex setup
    # Chunk value for Memory optimised regex increment. Keep >= 2500
    $Chunk = 25000

    If ($Chunk -lt 25000){
        Write-Host -ForegroundColor Red "Exiting Invoke-BitsDetectr: Regex `$Chunk of $Chunk is too low!"
        exit
    }

    $XferHeader = "36DA56776F515A43ACAC44A248FFF34D"

   ## Main
    ForEach($Path in $QmgrFiles){

        # Resetting Hex stream, variables and results for each QMgrFile
        $Hex = $null
        $Position = $null
        $Output = @{}

        If ($Verbose){Write-Host -ForegroundColor Cyan "Parsing $Path"}

        # Adding QmanagerFile to a Hex Array
        $FileStream = New-Object System.IO.FileStream -ArgumentList ($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	    $BinaryReader = New-Object System.IO.BinaryReader $FileStream
        $Hex = [System.BitConverter]::ToString($BinaryReader.ReadBytes($FileStream.Length)) -replace "-",""

        # Dispose FileStreams
        $FileStream.Dispose()
        $BinaryReader.Dispose()
        [gc]::Collect()



        # Using XferHeader to find interesting BITS activity
        $XferHeaderHits = $Null
        $a = 0
        $b = $Chunk

        While ($a -lt $Hex.Length){
            [gc]::Collect()           
            $XferHeaderHits = $XferHeaderHits + [regex]::Matches(($Hex[$a..$b] -join ""),$XferHeader).Index
                
            # Adding chunk minus xferheader less 1
            $a = $a + $Chunk -31
            $b = $b + $Chunk -31
        }
        [gc]::Collect()


        # If NoXFerHeaderHits we are done
        $XferHeaderHits = $XferHeaderHits | Where-Object {$_}
        If(!$XferHeaderHits){break}


        Foreach($Hit in $XferHeaderHits){
            $Position = $Null

            # Needing to account for Regex starting from $Position previously
            $Position = $Hit + 32

            # FilesCount in 1 byte (with Endian black magic)
            $FilesCount = $null
            $FilesCount = $Hex[$Position..($Position + 7)] -join ""
            $FilesCount = $FilesCount[6..7] + $FilesCount[4..5] + $FilesCount[2..3] + $FilesCount[0..1]
            
            Try{$FilesCount = [convert]::toint16($FilesCount -join "",16)}
            Catch{$FileCount = $null}
            
            $Position = $Position + 8


            # Some Bits versions will have Jobs with no filecount and requre carving. Jumping for now.
            If($FilesCount.GetType().fullname -eq "System.Int16" -and $FilesCount -gt 0){

                # DestLength in 2 bytes (With Endian black magic)
                $DestLength = $Null
                $DestLength = $Hex[$Position..($Position + 7)] -join ""
                $DestLength = $DestLength[6..7] + $DestLength[4..5] + $DestLength[2..3] + $DestLength[0..1]
                
                Try{$DestLength = [convert]::toint16($DestLength -join "",16)}
                Catch{$DestLength = $Null}
            
                $Position = $Position + 8


                # DestPath - Parsing each character of DestPath from 1 bytes x $DestPathLength characters
                $DestPath = $Null
            
                For($Count = 0;$Count -lt ($DestLength -1);$Count++){

                        Try{$DestPath = $DestPath + ($Hex[$Position..($Position + 3)] -join "" -replace "00","" | forEach {[char]([convert]::toint16($_,16))})}
                        Catch{Continue}

                        $Position = $Position + 4
                }
            
                $Position = $Position + 4


                # SourceLength in 2 bytes (With Endian black magic)
                $SourceLength = $Null
                $SourceLength = $Hex[$Position..($Position + 7)] -join ""
                $SourceLength = $SourceLength[6..7] + $SourceLength[4..5] + $SourceLength[2..3] + $SourceLength[0..1]
                
                Try{$SourceLength = [convert]::toint16($SourceLength -join "",16)}
                Catch{$SourceLength = $Null}

            
                $Position = $Position + 8


                # SourcePath - Parsing each character of SourcePath from 1 bytes x SourceLength characters
                $SourcePath = $Null
            
                For($Count = 0;$Count -lt ($SourceLength -1);$Count++){

                        Try{$SourcePath = $SourcePath + ($Hex[$Position..($Position + 3)] -join "" -replace "00","" | forEach {[char]([convert]::toint16($_,16))})}
                        Catch{Continue}

                        $Position = $Position + 4
                }
            
                $Position = $Position + 4


                # Setting Sourcepath and Destpath to null if space characters
                If($SourcePath -ne $Null){
                    If($SourcePath.GetType().FullName -eq "System.Char"){$SourcePath = $Null}
                    Else{
                        If($SourcePath.replace(" ","") -eq $Null ){$SourcePath = $null}
                    }
                }

                If($DestPath -ne $Null){
                    If($DestPath.GetType().FullName -eq "System.Char"){$DestPath = $Null}
                    Else{
                        If($DestPath.replace(" ","") -eq $Null ){$DestPath = $null}
                    }
                }


                # IF source null or source length less than 10 (indicates miss parse) then continue to next item
                If($SourcePath -eq $Null -Or $SourcePath.length -lt 10){continue}
                
            
                # Display Results     
                $Output = [ordered] @{
                    QmgrFile = $Path
                    Source = $SourcePath
                    Destination = $DestPath
                }

                $Output | Format-Table -AutoSize -Wrap

                [gc]::Collect()
            }
        }
    }