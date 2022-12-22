
Function Initialize-7zip ($szPath){

    If ($7zPath.Length -gt 0 -and $null -ne $7zPath){
    
        try {$PathTest = Test-Path $7zPath -ErrorAction Stop; $7zPathExists = $True}
        catch {$7zPathExists = $False}

    }

    If (!($7zPathExists) -or ($7zPath.Length -eq 0 -and $null -eq $7zPath)){

        switch (Test-Path .\7-Zip\7z.exe){
    
            $False {
        
                    try {
                        
                        $7zPath = (Get-ItemProperty "HKCU:\SOFTWARE\7-Zip" -ErrorAction Stop).Path + '7z.exe'
        
                        try {$PathTest = Test-Path $7zPath -ErrorAction Stop}
                        catch {throw "Registry entry for 7-Zip exists but path $7zPath is not found"}
        
                    } #Close try
                    catch {throw "7z not installed on this computer and is not in a local directory"}
        
                  } #Close False
        
            $True {$7zPath = (Get-Location).Path + "7-Zip\7z.exe"}
        
        } #Close Switch

    }
    
    Set-Alias -Scope Global -Name 7z -Value $7zPath
    
    $Global:szPath = $7zPath

}

Function Get-AbsolutePath ($Path){
    
    $FileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    
    Try {$AbsolutePath = $FileSystemObject.GetAbsolutePathName((Get-Item $Path -ErrorAction Stop).FullName)}
    Catch {throw "$Path name or path is not valid"}
    
    Remove-Variable FileSystemObject | Out-null

    return $AbsolutePath

} #Close Function Get-AbsolutePath

Function Get-ArchiveContents {

    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile,
        [Parameter(Mandatory=$False)][Alias('TechInfo')][switch]$ShowTechnicalInfo


        )
    
    begin {
        
        #region case-correct and check ArchiveFile Path
        try {$ArchiveFile = Get-AbsolutePath $ArchiveFile}
        catch {throw "$ArchiveFile is not a valid path"}
        
        #endregion case-correct

        If ((Get-Alias 7z -ErrorAction SilentlyContinue).Count -eq 0){
        
            Try {Initialize-7zip -ErrorAction Stop}
            Catch {throw "Unable to initialize 7zip alias"}
        }
        
        #region Define 7zip parameters
        $7zParameters = ""
    
        $7zParameters += " l " + '"' + "$ArchiveFile" + '"'
        If ($ShowTechnicalInfo.IsPresent){$7zParameters += " -slt"; $Operation = "ListSLT"}
        Else {$Operation = "List"}

} #Close Begin

    process {

    $Contents = invoke-expression "7z $7zParameters -bsp1" 2>&1

    $Table = New-Object System.Collections.ArrayList

    #region $Contents Error-catching:
    $ArchiveErrors = $Contents.Where({$_.Exception.Message.Length -gt 0}).Exception.Message
    
    Switch ($ArchiveErrors.Count){
    
    0 {}
    
    1 {throw $ArchiveErrors}
    
    {$_ -gt 1}{
        $ArchiveErrors[($ArchiveErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}
        throw ($ArchiveErrors[0])
    }

    }
    #endregion TechContents Error-catching
    
    switch ($Operation){

    {$_ -eq "List"}{

        [regex]$DateTime = '(Date).+(Time)'

        #region Find the Indexes
        $HeaderIndex = $Contents.IndexOf($Contents.Where({$_ -match $DateTime}))
        $Header = $Contents[$HeaderIndex]

        $FirstBreakIndex = $HeaderIndex + 1
        $FirstBreak = $Contents[$FirstBreakIndex]

        :BreakLoop Foreach ($Index in ($Contents.GetUpperBound(0)..($FirstBreakIndex + 1))){
        
        If ($Contents[$Index] -eq $FirstBreak){$LastBreakIndex = $Index; break BreakLoop}
        
        } #Close :BreakLoop
        #endregion Find the indexes
        
        #region Create a table of start/end indexes
        $BreakTable = New-Object System.Collections.ArrayList

        $x = 0
        ($FirstBreak -split ' ').ForEach({

        If ($_ -match '-'){

            If ($x -gt 0){$x++}

            $Object = New-Object System.Object
            $Object | Add-Member -MemberType NoteProperty -Name "Name" -Value ""
            $Object | Add-Member -MemberType NoteProperty -Name "Start" -Value $x
            
            $x += ($_.Length -1)
            
            If (($FirstBreak.Length - $x) -eq 1){$x++}

            $Object | Add-Member -MemberType NoteProperty -Name "End" -Value $x
            
            $BreakTable.Add($Object) | Out-Null

            $x++;
        
        }

        Else {$x++} #If we find a space character, add 1 to the index
        
        })
        
        (0..($BreakTable.Count -1)).ForEach({
        
            $Index = $_
            $Entry = $Breaktable[$Index]
                        
            $BreakTable[$Index].Name = ($Header[($Entry.Start)..($Entry.End)] -join '').Trim()

            If ($BreakTable[$Index].Name -match $DateTime){$BreakTable[$Index].Name = "DateTime"}
        })
        #endregion Create a Table of start/end indexes
        
        #region Use the index points to parse out the -l contents        
        $Contents[($FirstBreakIndex + 1)..($LastBreakIndex - 1)].ForEach({

        $Line = $_        
        $Object = New-Object System.Object
        
        $BreakTable.ForEach({
            $Attr = $_

            If ($BreakTable.IndexOf($Attr) -eq ($BreakTable.Count - 1)){$Attr.End = $Line.Length}

            $Object | Add-Member -MemberType NoteProperty -Name ($Attr.Name) -Value (($Line[($Attr.Start)..($Attr.End)] -join '').Trim())

            })

        $Table.Add($Object) | Out-Null

        }) #Close $Contents.ForEach()
        #endregion Use the index points to parse out the -l contents

    }

    {$_ -eq "ListSLT"}{

        $HeaderBreak = $Contents.IndexOf("----------")
        $FileInfoLines = $Contents[$HeaderBreak..$Contents.GetUpperBound(0)].Count
    
        $x = $HeaderBreak + 1
        Do {  
    
            $LineLength = 1
            $y = $x
    
            Do {
    
                $LineLength = $Contents[$y].Length
                $y++
    
            }
            Until ($LineLength -eq 0)
    
            $StartIndex = $x
            $EndIndex = $y - 2 #-2 because the "Until" statement doesn't evaluate until after $y++
    
            $Object = New-Object System.Object
            $Contents[$StartIndex..$EndIndex].ForEach({
    
                $LineSplit = ($_ -split ' = ', 2).ForEach({$_.Trim()})
                $Object | Add-Member -MemberType NoteProperty -Name ($LineSplit[0]) -Value ($LineSplit[1])
    
                })
    
            $Table.Add($Object) | Out-Null
            
            $x = $y 
    
        }
        Until ($x -ge $FileInfoLines)


    }

    }

}

    end {

        #region Filter out faulty entries (from multi-volume archives)
        If ($Operation -eq "List"){
        
            [regex]$FaultyEntries = "-{2,}|[0-9]+ files|^$"

            $Table = $Table.Where({$_.Name -notmatch $FaultyEntries})

        }

        #endregion Filter out faulty entries

        return $Table
    }

} #Close Function Get-ArchiveContents

Function Extract-Archive { 
    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile,
        [Parameter(Mandatory=$True)][ValidateScript({Test-Path $_})][Alias('Dest')][string]$Destination,
        [Parameter(ParameterSetName='PW')][Alias('Pass')][string]$Password,
        [Parameter(ParameterSetName='PW')][Alias('SkipCheck')][switch]$SkipPasswordCheck,
        [Alias('Multithread')][switch]$UseMultithreading,
        [Alias('KeepLog')][switch]$KeepLogfile,
        [switch]$Quiet
        )
    begin {
        #region case-correct and check paths and aliases
        try {$ArchiveFile = Get-AbsolutePath $ArchiveFile}
        catch {throw "$ArchiveFile is not a valid path"}

        try {$Destination = Get-AbsolutePath $Destination}
        catch {throw "$Destination is not a valid path"}

        If ((Get-Alias 7z -ErrorAction SilentlyContinue).Count -eq 0){
        
            Try {Initialize-7zip -ErrorAction Stop}
            Catch {throw "Unable to initialize 7zip alias"}
        }

        $7zPath = $Global:szPath #Exported by Initialize-7Zip
        #endregion case-correct

        #region Define vars and build Params
        $Loud = !($Quiet.IsPresent)

        $7zParameters = ""
        $7zParameters += " x " + '"' + "$ArchiveFile" + '"' + " -o" + '"' + "$Destination" + '" '
        
        If ($UseMultithreading.IsPresent){
            
            try {$7zParameters += "-mmt=$((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors -1) "}
            catch {throw "Failed to enumerate number of logical processors - possibly a system permission or WMI service issue"}
        
        }
                
        If ($PSBoundParameters.ContainsKey('Password')){$7zParameters += "-p$Password "}
        
        $7zParameters += "-y"
        
        $Operation = "Extract" 

        #endregion Define vars

        $LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999)-extract.log"
        
        try {"Write test" | Out-File $LogFile -ErrorAction Stop}
        catch {throw "Unable to write data out to new logfile $LogFile"}
    
        $LogfileCleanup = {If (!($KeepLogfile.IsPresent)){Remove-Item $LogFile -ErrorAction SilentlyContinue}}
    
        #endregion Build Logfile
    
        #region Build Scriptblock
    
        $Scriptblock = {
    
            $WorkingDirectory = $args[0]
            $7zPath = $args[1]
            $7zParameters = $args[2]
            $LogFile = $args[3]
        
            try {Set-Location $WorkingDirectory -ErrorAction Stop}
            catch {throw "Job is unable to move to $WorkingDirectory"}
        
            Set-Alias -Name 7z -Value $7zPath
            
            "Parameters: $7zParameters" > $LogFile

            $RunCommand = invoke-expression "7z $7zParameters -bsp1" | Out-String -Stream 2>&1 >> $LogFile
        
            return $RunCommand
    
        }
        #endregion Build Scriptblock

        #region Build ESCAPE key Interception
        If ($Loud){
            $Global:Interrupted = $False #We have to use Global
        
            #This blocks CTRL+C and flushes the input buffer
            $InitializeInputBuffer = {
            [Console]::TreatControlCAsInput = $True
            Start-Sleep -Milliseconds 100
            $Host.UI.RawUI.FlushInputBuffer()
            }

            $InterceptEscapeKey = {
                
                If ($Host.UI.RawUI.KeyAvailable -and ($Key = $Host.UI.RawUI.ReadKey("AllowCtrlC,NoEcho,IncludeKeyUp"))) {
            
                    If ([Int]$Key.Character -eq 27) {
                    
                        Write-Warning "Escape Key detected, terminating operation (please wait)"
                        $Global:Interrupted = $True
                        [Console]::TreatControlCAsInput = $False
            
                }
            
                $Host.UI.RawUI.FlushInputBuffer()
                
            }
            
            }        

        }
    #endregion Build ESCAPE key Interception

    } #End begin

    process {

         try {$ArchiveContents = Get-ArchiveContents -ArchiveFile $ArchiveFile -ShowTechnicalInfo}
         catch {throw "Errors encountered when enumerating contents of $ArchiveContents"}

         $EncryptedTags = $ArchiveContents.Where({$_.Encrypted -eq "+"}) | Sort-Object -Unique

         If ($EncryptedTags.Count -gt 0 -and ($null -eq $Password -or $Password.Length -eq 0)){throw "Archive is encrypted, but no password was specified"}

         #region Test the Password
        If (($null -ne $Password) -and ($null -ne $EncryptedTags) -and !($SkipPasswordCheck.IsPresent)){ 
    
            $SmallestFile = $ArchiveContents.Where({$_.Encrypted -eq '+'}) | Sort-Object Size | Select-Object -First 1
            
            #There seems to be a 7zip bug where -i!\<Path> tests more than the specified file. No idea why, but it's not solvable via Powershell
            $PasswordTest = 7z t $ArchiveFile -p"$Password" -i!\$($SmallestFile.Path) -bso0 -bd 2>&1
                    
            If ($PasswordTest.Count -gt 0){$TestErrors = $PasswordTest.Where({$_.Exception.Message.Length -gt 0}).Exception.Message}
        
            Switch ($TestErrors.Count){
        
                0 {} #Do nothing
        
                1 {
                    &$LogfileCleanup
                    throw $TestErrors
                }
        
                {$_ -gt 1}{
                    &$LogfileCleanup
                    $TestErrors.ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}
                    throw ($TestErrors[0])
                }
        
                Default {
                    &$LogfileCleanup
                    throw "No idea what happened"
                }
        
                }
        
            }
            #endregion Test the Password

            #region Pre-execution clean-up
            $PreviousJobs =  Get-Job -Name "7zExtract" -ErrorAction SilentlyContinue

            If ($PreviousJobs.Count -gt 0){

                $PreviousJobs | Foreach-Object {

                    Stop-Job -Id ($_.Id) | Out-Null
                    Remove-Job -Id ($_.Id) | Out-Null

                }

            } #Close PreviousJobs.Count
            #endregion Pre-execution clean-up

            #region Heavy lifting

            $Job = Start-Job -Name "7zExtract" -ScriptBlock $ScriptBlock -ArgumentList @("$((Get-Location).Path)",$7zPath,$7zParameters,$LogFile)
                
            $Done = $False

            $FileCount = $ArchiveContents.Count
            $MoreThanOneFile = [bool]($FileCount -gt 1)

            $JobStatus = Get-Job ($Job.Id)

            If ($JobStatus.State -notmatch 'Completed|Running'){

                Stop-Job -Id ($JobStatus.Id) | Out-Null
                Remove-Job -Id ($JobStatus.Id) | Out-Null

                throw "Job stopped in state $($JobStatus.State) while running 7zip extract, terminating"

            }
            
            If ($Loud){
                &$InitializeInputBuffer
                Write-Verbose "Press ESCAPE key to interrupt extract operation" -Verbose
            }

            #Predefine variables for parsing out original file name, number of files later:
            $ExtractionBegun = $False
            $LogfileRead = $False

            Do {

                Start-Sleep -Milliseconds 100 #Sleep 1/10 of a second

                $LogLatest = (Get-Content $LogFile -Tail 6).Where({$_ -match '(\d+)%|(\bEverything is Ok\b)'}) | Select-Object -Last 1

                If (!$Loud -and [bool]($LogLatest -eq "Everything is Ok")){$Done = $True}

                If ($Loud){

                    If ($null -eq $LogLatest -or $LogLatest.Length -eq 0){
                                                Start-Sleep -Milliseconds 100
                                                $OnFile = 0
                                                $File = "-"
                                                $Percent = 0
                                            }

                    ElseIf ([bool]($LogLatest -eq "Everything is Ok")){
                                                $Done = $True
                                                $OnFile = $FileCount
                                                $File = "None (Complete)"
                                                $Percent = 100
                                            }

                    ElseIf ($LogLatest -eq '  0%'){
                                                $OnFile = 0
                                                $File = "-"
                                                $Percent = 0
                                                $ExtractionBegun = $True
                                            }

                    ElseIf (!$MoreThanOneFile){
                                                $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                $Percent = $Percent.TrimEnd('%').Trim()
                                                $OnFile = 1
                                                $ExtractionBegun = $True
                                            }

                    ElseIf ($MoreThanOneFile){
                                                $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                $Percent,$OnFile = ($Percent -split '%').Trim()
                                                $ExtractionBegun = $True
                                            }

                    #Capture the original file name, number of files from logfile for split archive:
                    If ($ExtractionBegun -and !$LogfileRead){ 
                        
                        $LogLatest = Get-Content $LogFile
                        $VolLine = $LogLatest.IndexOf($LogLatest.Where({$_ -match "Volumes ="}))
                        
                        If ($VolLine -gt 0){ #Covers '0' (returned $false in [bool]), and '-1' (returned "none" as [int])
                            
                            $ArchiveFilesCount = ($LogLatest[$VolLine] -split '=')[1].Trim()

                            Do {
                                $VolLine++
                                $LineContents = $LogLatest[$VolLine]
                            }
                            Until ($LineContents -match 'Path =')

                            $OriginalFilename = ($LineContents -split '=')[1].Trim()

                            $ArchiveFile = "$OriginalFileName ($ArchiveFilesCount files)"
                        }

                        $LogfileRead = $True

                    }

                    Write-Progress -Activity "Extracting $ArchiveFile" -Status "$OnFile of $FileCount | Extracting $File" -PercentComplete $Percent
                    &$InterceptEscapeKey
                }

            } #Close Do
            Until ($Done -eq $True -or $Global:Interrupted -eq $True)

            If ($Loud){

                Write-Progress -Activity "Extracting $ArchiveFile" -Status "Ready" -Completed

                If ($Global:Interrupted -eq $True){$Operation = "$Operation Interrupted"}

            }

            $JobStatus = Get-Job ($Job.Id)

            Switch (($JobStatus).State){

            { $_ -eq "Running"}{Stop-Job -Id ($Job.Id); Remove-Job -Id ($Job.Id); $Successful = $False}

            {$_ -eq "Completed"}{$JobContents = ($Job | Receive-Job); Remove-Job ($Job.Id); $Successful = $True}

            {$_ -eq "Failed"}{&$LogfileCleanup; $JobError = $JobStatus.Error; Remove-Job ($Job.Id); $Successful = $False}

            } #Close Switch Get-Job (ID) State

            #endregion Heavy lifting
            
    } #end process

    end {

        If ($KeepLogfile.IsPresent -and $Loud){Write-Verbose "Logfile is $LogFile" -Verbose}
    
        &$LogfileCleanup

        If ($Global:Interrupted -eq $True){throw "Operation was interrupted before completion"}

        If ($Successful -eq $False){throw "Job errored; job found in state $($JobStatus.State) after completion"}

    }

} #Close Function Extract-Archive

Function Create-Archive {
    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory=$True)][ValidateScript({Test-Path $_})][Alias('Src')][string]$Source,
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile,
        [switch]$Overwrite,
        [ValidatePattern('^[0-9]+[KkMmGg]$')][Alias('VolSize')][string]$VolumeSize,
        [Parameter(ParameterSetName='Zip')][switch]$Zip,
        [Parameter(ParameterSetName='GZip')][switch]$GZip,
        [Parameter(ParameterSetName='BZip2')][switch]$BZip2,
        [Parameter(ParameterSetName='7z')][switch]$SevenZip,
        [Parameter(ParameterSetName='Xz')][switch]$Xz,
        [Parameter(ParameterSetName='tar')][switch]$Tar,
        [Parameter(ParameterSetName='Zip')][ValidateSet("Copy","Deflate","Deflate64","BZip2","LZMA")][string]$ZipMethod,
        [Alias('Multithread')][switch]$UseMultithreading,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][Parameter(ParameterSetName='BZip2')][Parameter(ParameterSetName='7z')][ValidatePattern('[013579]')][int]$CompressionLevel,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][ValidateSet("ZipCrypto","AES128","AES192","AES256")][string]$EncryptionMethod,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][Parameter(ParameterSetName='7z')][switch]$PreserveTimestamps,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][switch]$UseLocalCodePage,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][switch]$UseUTF8ForNonASCIISymbols,
        [Parameter(ParameterSetName='Zip')][Parameter(ParameterSetName='GZip')][Parameter(ParameterSetName='BZip2')][int]$Passes,
        [Parameter(ParameterSetName='7z')][switch]$SolidModeOff,
        [Parameter(ParameterSetName='7z')][switch]$ExeCompressionOff,
        [Parameter(ParameterSetName='7z')][switch]$HeaderCompressionOff,
        [Parameter(ParameterSetName='7z')][switch]$EncryptHeaderOn,
        [Alias('Pass')][string]$Password,
        [Alias('KeepLog')][switch]$KeepLogfile,
        [switch]$Quiet
        )

    begin {
  
        #region Case-correct and check paths and aliases
        
        If (Test-Path "$ArchiveFile"){
            
            Switch ($OverWrite.IsPresent){
                $True {

                    try {$RemoveFile = Remove-Item $ArchiveFile -ErrorAction Stop}
                    catch {throw "Unable to remove $ArchiveFile"}

                }

                $False {throw "$ArchiveFile exists. Please specify a different filename, delete the file, or specify -Overwrite"}

            }
    
            }
        
        try {$Source = Get-AbsolutePath $Source}
        catch {throw "$Source is not a valid path"}

        If (($Xz.IsPresent -or $BZip2.IsPresent) -and (Get-Item $Source).PsIsContainer -eq $True){throw "$Source is a directory; XZ and BZIP2 can only compress single files. Try TARing it first"}

        If ((Get-Alias 7z -ErrorAction SilentlyContinue).Count -eq 0){
        
            Try {Initialize-7zip -ErrorAction Stop}
            Catch {throw "Unable to initialize 7zip alias"}
        }

        $7zPath = $Global:szPath #Exported by Initialize-7Zip
        #endregion Case-correct the File/Directory
        
        $Loud = !($Quiet.IsPresent)

        #region Capture Archive Type
        
        $ArchiveType = "None"
        
        If ($Zip.IsPresent){$ArchiveType = "zip"}
        ElseIf ($BZip2.IsPresent){$ArchiveType = "bzip2"}
        ElseIf ($GZip.IsPresent){$ArchiveType = "gzip"}
        ElseIf ($SevenZip.IsPresent){$ArchiveType = "7z"}
        ElseIf ($Xz.IsPresent){$ArchiveType = "xz"}
        ElseIf ($Tar.IsPresent){$ArchiveType = "tar"}
        Else {throw "Indeterminable archive type; please specify -<ArchiveType> switch parameter"}

        #endregion Capture Archive Type

        #region Define Generic/Broad Parameters

        $7zParameters = ""
        $7zParameters += " a " + '"' + "$ArchiveFile" + '" "' + "$Source" + '" ' + "-t$ArchiveType "

        If ($PSBoundParameters.ContainsKey('Password')){$7zParameters += "-p$Password "}

        If ($PSBoundParameters.ContainsKey('CompressionLevel')){$7zParameters += "-mx$CompressionLevel "}

        If ($PSBoundParameters.ContainsKey('VolumeSize')){$7zParameters += "-v$VolumeSize "}

        #endregion  Define Generic Parameters

        #region Define Archive-specific Parameters

        Switch ($ArchiveType){

        {$_ -eq "zip" -or $_ -eq "gzip"}{

            If ($PSBoundParameters.ContainsKey('Passes')){
                If ($ZipMethod -notmatch 'Deflate|Bzip2' -and $ZipMethod.Length -gt 0){throw "-Passes parameter can only be used with -ZipMethod Deflate [default] or Bzip2"}
                If (($ZipMethod -match 'Deflate' -or $ZipMethod.Length -eq 0) -and ($Passes -gt 15 -or $Passes -lt 0)){throw "-Passes parameter must be between 1 and 15 for Deflate [default]"}
                If (($ZipMethod -eq 'BZip2') -and ($Passes -lt 1 -or $Passes -gt 10)){throw "-Passes parameter must be between 1 and 10 for -ZipMethod Bzip2"}

            $7zParameters += "-mpass=$Passes "

            }

            If ($PSBoundParameters.ContainsKey('ZipMethod')){$7zParameters += "-mm=$ZipMethod "}
            If ($PSBoundParameters.ContainsKey('EncryptionMethod')){$7zParameters += "-mem=$EncryptionMethod "}
            If ($PreserveTimestamps.IsPresent){$7zParameters += "-mtc=on "}
            If ($UseLocalCodePage.IsPresent){$7zParameters += "-mcl=on "}
            If ($UseUTF8ForNonASCIISymbols.IsPresent){$7zParameters += "-mcu=on "}

        }

        {$_ -eq "bzip2"}{

            If ($PSBoundParameters.ContainsKey('Passes')){

                If ($Passes -gt 10 -or $Passes -lt 1){throw "-Passes parameter must be between 1 and 10 for Bzip2 compression"}

            $7zParameters += "-mpass=$Passes "

            }

        }
        
        {$_ -eq "7z"}{

            If ($PreserveTimestamps.IsPresent){$7zParameters += "-mtc=on "}
            If ($SolidModeOff.IsPresent){$7zParameters += "-ms=off "}
            If ($ExeCompressionOff.IsPresent){$7zParameters += "-mf=off "}
            If ($HeaderCompressionOff.IsPresent){$7zParameters += "-mhc=off "}
            If ($EncryptHeaderOn.IsPresent){$7zParameters += "-mhe=on "}
        }
        {$_ -eq "xz"}{} #Nothing to do
        {$_ -eq "tar"}{} #Nothing to do

        }

        $7zParameters = $7zParameters.TrimEnd() #Remove trailing space

        #endregion Define Specific Parameters

        $LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999)-compress.log"
        
        try {"Write test" | Out-File $LogFile -ErrorAction Stop}
        catch {throw "Unable to write data out to new logfile $LogFile"}
    
        $LogfileCleanup = {If (!($KeepLogfile.IsPresent)){Remove-Item $LogFile -ErrorAction SilentlyContinue}}
    
        #endregion Build Logfile
    
        #region Build Scriptblock
    
        $Scriptblock = {
    
            $WorkingDirectory = $args[0]
            $7zPath = $args[1]
            $7zParameters = $args[2]
            $LogFile = $args[3]
        
            try {Set-Location $WorkingDirectory -ErrorAction Stop}
            catch {throw "Job is unable to move to $WorkingDirectory"}
        
            Set-Alias -Name 7z -Value $7zPath
            
            #"Parameters: $7zParameters" > $LogFile

            $RunCommand = invoke-expression "7z $7zParameters -bsp1" | Out-String -Stream 2>&1 > $LogFile
        
            return $RunCommand
    
        }
        #endregion Build Scriptblock

        #region Build ESCAPE key Interception
        If ($Loud){
            $Global:Interrupted = $False #We have to use Global
        
            #This blocks CTRL+C and flushes the input buffer
            $InitializeInputBuffer = {
            [Console]::TreatControlCAsInput = $True
            Start-Sleep -Milliseconds 100
            $Host.UI.RawUI.FlushInputBuffer()
            }

            $InterceptEscapeKey = {
                
                If ($Host.UI.RawUI.KeyAvailable -and ($Key = $Host.UI.RawUI.ReadKey("AllowCtrlC,NoEcho,IncludeKeyUp"))) {
            
                    If ([Int]$Key.Character -eq 27) {
                    
                        Write-Warning "Escape Key detected, terminating operation (please wait)"
                        $Global:Interrupted = $True
                        [Console]::TreatControlCAsInput = $False
            
                }
            
                $Host.UI.RawUI.FlushInputBuffer()
                
            }
            
            }        

        }
    #endregion Build ESCAPE key Interception

    } #End begin

    process {

            #region Pre-execution clean-up
           $PreviousJobs =  Get-Job -Name "7zCompress" -ErrorAction SilentlyContinue

           If ($PreviousJobs.Count -gt 0){

               $PreviousJobs | Foreach-Object {

                   Stop-Job -Id ($_.Id) | Out-Null
                   Remove-Job -Id ($_.Id) | Out-Null

               }

           }
           #endregion Pre-execution clean-up

           #region Heavy lifting
           $Job = Start-Job -Name "7zCompress" -ScriptBlock $ScriptBlock -ArgumentList @("$((Get-Location).Path)",$7zPath,$7zParameters,$LogFile)
               
           $Done = $False
          
            #region Parse out number of files in archive
           [regex]$FileInfoRegex = '^((\d)+\s(folder)(s)?,\s)?(\d)+\s(file){1}(s)?\,\s(\d)+\s(bytes)\s\((\d)+\s[KMGTP]iB\)$'

           $FileCountParsed = $False
           $Counter = 0

           Do {
            Start-Sleep -Milliseconds 100 #Sleep 1/10 of a second

            try {$LogLatest = (Get-Content $LogFile -ErrorAction Stop).Where({$_ -match $FileInfoRegex}) | Select-Object -first 1}
            catch {} #Do nothing

            If ($LogLatest -match $FileInfoRegex){$FileCountParsed = $True}

            $Counter++

           }
           Until ($FileCountParsed -eq $True -or $Counter -eq 40)

           if ($FileCountParsed -eq $False -and $Counter -eq 40){

            $JobStatus = Get-Job ($Job.Id)

            Stop-Job -Id ($JobStatus.Id) | Out-Null
            Remove-Job -Id ($JobStatus.Id) | Out-Null

            throw "10 seconds elapsed without detecting a statement of folder/file counts in the log file. Something's probably wrong, stopping function."

            }

            ElseIf ($FileCountParsed -eq $True){

            Switch ([bool]($LogLatest -match "folder")){
            
                $False {$FileCountIndex = 0}
                $True {$FileCountIndex = 1}

                }

            [int]$FileCount = (($LogLatest -split ', ')[$FileCountIndex] -split ' ')[0]

            }

           #endregion Parse out number of files in archive

           $MoreThanOneFile = [bool]($FileCount -gt 1) -or [bool]($SevenZip.IsPresent) #7z format logs "#% 1 + FileName" in the output log, for some reason

           $JobStatus = Get-Job ($Job.Id)

           If ($JobStatus.State -notmatch 'Completed|Running'){

               Stop-Job -Id ($JobStatus.Id) | Out-Null
               Remove-Job -Id ($JobStatus.Id) | Out-Null

               throw "Job stopped in state $($JobStatus.State) while running 7zip compression, terminating"

           }
           
           If ($Loud){
               &$InitializeInputBuffer
               Write-Verbose "Press ESCAPE key to interrupt compression operation" -Verbose
           }


           Do {

               Start-Sleep -Milliseconds 100 #Sleep 1/10 of a second

               $LogLatest = (Get-Content $LogFile -Tail 6).Where({$_ -match '(\d+)%|(\bEverything is Ok\b)'}) | Select-Object -Last 1

               If (!$Loud -and [bool]($LogLatest -eq "Everything is Ok")){$Done = $True}

               If ($Loud){

                   If ($null -eq $LogLatest -or $LogLatest.Length -eq 0){Start-Sleep -Milliseconds 100; $OnFile = 0; $File = "-"; $Percent = 0}

                   ElseIf ([bool]($LogLatest -eq "Everything is Ok")){
                                               $Done = $True
                                               $OnFile = $FileCount
                                               $File = "None (Complete)"
                                               $Percent = 100
                                            }

                   ElseIf ($LogLatest -eq '  0%'){
                                               $OnFile = 0
                                               $File = "-"
                                               $Percent = 0

                                           }

                   ElseIf (!$MoreThanOneFile){
                       
                                               $Percent,$File = ($LogLatest -split ' \+ ').Trim()
                                               $Percent = $Percent.TrimEnd('%').Trim()
                                               $OnFile = 1

                                           }

                   ElseIf ($MoreThanOneFile){
                       
                                               $Percent,$File = ($LogLatest -split ' \+ ').Trim()
                                               $Percent,$OnFile = ($Percent -split '%').Trim()

                                           }
               
                   Write-Progress -Activity "Compressing $ArchiveFile" -Status "$OnFile of $FileCount | Compressing $File" -PercentComplete $Percent
                   &$InterceptEscapeKey
               }

           }
           Until ($Done -eq $True -or $Global:Interrupted -eq $True)

           If ($Loud){

               Write-Progress -Activity "Compressing $ArchiveFile" -Status "Ready" -Completed

               If ($Global:Interrupted -eq $True){$Operation = "$Operation Interrupted"}

           }

           $JobStatus = Get-Job ($Job.Id)

           Switch (($JobStatus).State){

           { $_ -eq "Running"}{Stop-Job -Id ($Job.Id); Remove-Job -Id ($Job.Id); $Successful = $False}

           {$_ -eq "Completed"}{$JobContents = ($Job | Receive-Job); Remove-Job ($Job.Id); $Successful = $True}

           {$_ -eq "Failed"}{&$LogfileCleanup; $JobError = $JobStatus.Error; Remove-Job ($Job.Id); $Successful = $False}

           }

           #endregion Heavy lifting
           
   } #end process
   
    end {

        If ($KeepLogfile.IsPresent -and $Loud){Write-Verbose "Logfile is $LogFile" -Verbose}
    
        &$LogfileCleanup

        If ($Global:Interrupted -eq $True){
            
            Remove-Item $ArchiveFile -ErrorAction SilentlyContinue
            throw "Operation was interrupted before completion"
        
            }

        If ($Successful -eq $False){throw "Job errored; job found in state $($JobStatus.State) after completion"}

    }

} #Close Function Extract-Archive