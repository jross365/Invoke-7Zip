
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
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile, #7z [a|e|l|x] C:\path\to\file.7z; Note: e = "extract" (all files to one dir); x = "extract to full paths" (all files with subdirs preserved)
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
    
    0 {} #Formerly $EncryptedTags =...
    
    1 {throw $ArchiveErrors}
    
    {$_ -gt 1}{
        $ArchiveErrors[($ArchiveErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}
        throw ($ArchiveErrors[0])
    }

    } #Close Switch ArchiveErrors.Count
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

            }) #Close BreakTable.ForEach

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
        [ValidateScript({$_ -le ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors -1)})][int]$CPUThreads,
        [Alias('Pass')][string]$Password,
        [ValidateScript({Test-Path $_})][Alias('Dest')][string]$Destination,
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile,
        [Alias('KeepLog')][switch]$KeepLogfile,
        [Alias('Quiet')][switch]$Silent
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
        
        $Loud = !($Silent.IsPresent)

        $7zParameters = ""
        $7zParameters += " x " + '"' + "$ArchiveFile" + '"' + " -o" + '"' + "$Destination" + '" '
        If ($null -ne $CPUThreads){$7zParameters += "-mmt$CPUThreads "}
        If ($null -ne $Password){$7zParameters += "-p$Password "}
        $7zParameters += "-y"
        
        $Operation = "Extract" 

        #endregion Define vars

        $LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999).log"
        
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

         try {$ArchiveContents = Get-ArchiveContents -ArchiveFile $ArchiveFile -ShowTechnicalInfo}
         catch {throw "Errors encountered when enumerating contents of $ArchiveContents"}

         $EncryptedTags = $ArchiveContents.Where({$_.Encrypted -eq "+"}) | Sort-Object -Unique

         If ($EncryptedTags.Count -gt 0 -and ($null -eq $Password -or $Password.Length -eq 0)){throw "Archive is encrypted, but no password was specified"}

         #region Test the Password
        If ($null -ne $Password -and $null -ne $EncryptedTags){ 
    
            #Find the smallest file to test password against
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

                Start-Sleep -Milliseconds 250 #Sleep 1/4 of a second

                $LogLatest = (Get-Content $LogFile -Tail 6).Where({$_ -match '(\d+)%|(\bEverything is Ok\b)'}) | Select-Object -Last 1

                If (!$Loud -and [bool]($LogLatest -eq "Everything is Ok")){$Done = $True}

                If ($Loud){

                    If ($null -eq $LogLatest -or $LogLatest.Length -eq 0){Start-Sleep -Milliseconds 100; $OnFile = 0; $File = "-"; $Percent = 0}

                    ElseIf ([bool]($LogLatest -eq "Everything is Ok")){$Done = $True; $OnFile = $FileCount; $File = "None (Complete)"; $Percent = 100}

                    ElseIf ($LogLatest -eq '  0%'){
                                                $OnFile = 0
                                                $File = "-"
                                                $Percent = 0
                                                $ExtractionBegun = !$ExtractionBegun

                                            }

                    ElseIf (!$MoreThanOneFile){
                        
                                                $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                $Percent = $Percent.TrimEnd('%').Trim()
                                                $OnFile = 1
                                                $ExtractionBegun = !$ExtractionBegun

                                            }

                    ElseIf ($MoreThanOneFile){
                        
                                                $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                $Percent,$OnFile = ($Percent -split '%').Trim()
                                                $ExtractionBegun = !$ExtractionBegun

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
        #[ValidateScript({$_ -le ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors -1)})][int]$CPUThreads, #-m -mmt(1-16)
        [ValidatePattern('^[0-9]+[KkMmGg]$')][Alias('VolSize')][string]$VolumeSize, #-v
        #[ValidateSet("7z","xz","zip","gzip","bzip2","tar")][Alias('Type')][string]$ArchiveType, #-tzip,-t7z,etc
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][switch]$Zip,
        [Parameter(ParameterSetName='GZip',Mandatory=$False)][switch]$GZip, #-tgzip
        [Parameter(ParameterSetName='BZip2',Mandatory=$False)][switch]$BZip2,
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$7z,
        [Parameter(ParameterSetName='xz',Mandatory=$False)][switch]$Xz,
        [Parameter(ParameterSetName='tar',Mandatory=$False)][switch]$Tar,
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][ValidateSet("Copy","Deflate","Deflate64","BZip2","LZMA")][string]$ZipMethod, #mm=Deflate
        #[Parameter(ParameterSetName='Zip',Mandatory=$False)][ValidateSet("LZMA","PPMd","BZip2","Deflate","BCJ","BCJ2","Copy")][string]$7zMethod, #
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][Parameter(ParameterSetName='BZip2',Mandatory=$False)][Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$Multithreading,
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][ValidateSet("ZipCrypto","AES128","AES192","AES256")][string]$EncryptionMethod, #mem=ZipCrypto
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][switch]$PreserveNTFSTimestamps,
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][switch]$UseLocalCodePage,
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][switch]$UseUTF8ForNonASCIISymbols,
        [Parameter(ParameterSetName='BZip2',Mandatory=$False)][ValidateSet("Normal","Maximum","Ultra")][string]$PassesMode, #-mpass 1,2,7
        [Parameter(ParameterSetName='Zip',Mandatory=$False)][Parameter(ParameterSetName='GZip',Mandatory=$False)][Parameter(ParameterSetName='7z',Mandatory=$False)][ValidatePattern('[13579]')][int]$CompressionLevel, #-m -mx(1-9)
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]]$DisableSolidMode, #ms=off
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$DisableExeCompression, #mf=off
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$DisableHeaderCompression, #mhc=off
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$EncryptHeader, #mhe=on
        [Parameter(ParameterSetName='7z',Mandatory=$False)][switch]$PreserveCreationTimestamps, #tc=on
        
        [ValidateSet()][string]$Method, # a
        [Alias('Pass')][string]$Password, #-p
        [ValidateScript({Test-Path $_})][Alias('Src')][string]$Source,
        [Parameter(Mandatory=$False)][Alias('File')][string]$ArchiveFile, #7z [a|e|l|x] C:\path\to\file.7z; Note: e = "extract" (all files to one dir); x = "extract to full paths" (all files with subdirs preserved)
        [Alias('KeepLog')][switch]$KeepLogfile,
        [Alias('Quiet')][switch]$Silent
        )

        #$7zParameters = 'a "D:\marchtest\Multifiles_test2.bzip2" "D:\multiarchive\2022-06-19 20-44-58.mkv" -mx=5 -tbzip2 -V4G -mmt=12 -y'
    begin {
  
        #region Case-correct the File/Directory (7zip is case-sensitive)
        #region case-correct and check paths and aliases
        try {$ArchiveFile = Get-AbsolutePath $ArchiveFile}
        catch {throw "$ArchiveFile is not a valid path"}

        try {$Source = Get-AbsolutePath $Source}
        catch {throw "$Source is not a valid path"}

        If ((Get-Alias 7z -ErrorAction SilentlyContinue).Count -eq 0){
        
            Try {Initialize-7zip -ErrorAction Stop}
            Catch {throw "Unable to initialize 7zip alias"}
        }

        $7zPath = $Global:szPath #Exported by Initialize-7Zip
        #endregion Case-correct the File/Directory
        
        $Loud = !($Silent.IsPresent)

        #region Handle type idiosyncracies
        #ref: https://www.scottklement.com/p7zip/MANUAL/switches/method.htm
        #bzip2:
            # - Can only do single-files
            # - accepts compression (5,7,9)

        #endregion Handle type idiosyncracies

        #region Define 7z parameters
        $7zParameters = ""
    
        $Operation = "None"
        
        $7zParameters += " a " + '"' + "$ArchiveFile" + '" "' + "$Source" + '" '
    
        $7zParameters += "-mmt=on -mx$CompressionLevel "
        
        If ($null -ne $CPUThreads){$7zParameters += "-mmt$CPUThreads "}
    
        $7zParameters += "-t$ArchiveType "
        
        If ($null -ne $VolumeSize){$7zParameters += "-v$VolumeSize "}
        If ($null -ne $Password){$7zParameters += "-p$Password "}
        
        $7zParameters += "-y"
    
        $Operation = "Add"
        #endregion Define 7z parameters

        #region Build Logfile
            
        $LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999).log"
        
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
        
            $RunCommand = invoke-expression "7z $7zParameters -bsp1" | Out-String -Stream 2>&1 > $LogFile
        
            return $RunCommand
        
            }

        
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
       If ($null -ne $Password -and $null -ne $EncryptedTags){ 
   
           #Find the smallest file to test password against
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

               Start-Sleep -Milliseconds 250 #Sleep 1/4 of a second

               $LogLatest = (Get-Content $LogFile -Tail 6).Where({$_ -match '(\d+)%|(\bEverything is Ok\b)'}) | Select-Object -Last 1

               If (!$Loud -and [bool]($LogLatest -eq "Everything is Ok")){$Done = $True}

               If ($Loud){

                   If ($null -eq $LogLatest -or $LogLatest.Length -eq 0){Start-Sleep -Milliseconds 100; $OnFile = 0; $File = "-"; $Percent = 0}

                   ElseIf ([bool]($LogLatest -eq "Everything is Ok")){$Done = $True; $OnFile = $FileCount; $File = "None (Complete)"; $Percent = 100}

                   ElseIf ($LogLatest -eq '  0%'){
                                               $OnFile = 0
                                               $File = "-"
                                               $Percent = 0
                                               $ExtractionBegun = !$ExtractionBegun

                                           }

                   ElseIf (!$MoreThanOneFile){
                       
                                               $Percent,$File = ($LogLatest -split ' - ').Trim()
                                               $Percent = $Percent.TrimEnd('%').Trim()
                                               $OnFile = 1
                                               $ExtractionBegun = !$ExtractionBegun

                                           }

                   ElseIf ($MoreThanOneFile){
                       
                                               $Percent,$File = ($LogLatest -split ' - ').Trim()
                                               $Percent,$OnFile = ($Percent -split '%').Trim()
                                               $ExtractionBegun = !$ExtractionBegun

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



    }

} #Close Function Extract-Archive

Function Invoke-7Zip {
    [CmdletBinding()] 
    param( 
        [Parameter(ParameterSetName='Add',Mandatory=$False)][switch]$Add, # a
        [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][ValidateScript({$_ -le ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors -1)})][int]$CPUThreads, #-m -mmt(1-16)
        [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidateRange(1,9)][Alias('Level')][int]$CompressionLevel, #-m -mx(1-9)
        [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidatePattern('^[0-9]+[KkMmGg]$')][Alias('VolSize')][string]$VolumeSize, #-v
        [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidateSet("7z","xz","zip","gzip","bzip2","tar")][Alias('Type')][string]$ArchiveType, #-tzip,-t7z,etc
        [Parameter(ParameterSetName='Extract',Mandatory=$False)][switch]$Extract, # x
        [Parameter(ParameterSetName='List',Mandatory=$False)][switch]$List, # l
        [Parameter(ParameterSetName='List',Mandatory=$False)][Alias('TechInfo')][switch]$ShowTechnicalInfo,
        [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][Alias('Pass')][string]$Password, #-p
        [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][ValidateScript({Test-Path $_})][string]$Target,
        [Parameter(Mandatory=$False)][Alias('File')][string]$ArchiveFile, #7z [a|e|l|x] C:\path\to\file.7z; Note: e = "extract" (all files to one dir); x = "extract to full paths" (all files with subdirs preserved)
        [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][Alias('KeepLog')][switch]$KeepLogfile,
        [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][Alias('Quiet')][switch]$Silent
        )
    
    begin {
    
    #region Case-correct the File/Directory (7zip is case-sensitive)
    $FileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    
    $ArchiveFile = $FileSystemObject.GetAbsolutePathName((Get-Item $ArchiveFile).FullName)
    
    If ($null -eq $Target -or $Target.Length -eq 0){$Target = $FileSystemObject.GetAbsolutePathName((Get-Location).Path)}
    Else {$Target = $FileSystemObject.GetAbsolutePathName($Target)}
    
    Remove-Variable FileSystemObject | Out-null
    
    #endregion Case-correct the File/Directory
    
    #region Validate File/Directory parameters, based on switches
    If ($Add.IsPresent){
    
        try {!($TestPath = Test-Path $ArchiveFile -ErrorAction Stop)}
        catch {throw "$ArchiveFile already exists, stopping"}
    
    } 
    
    If ($Extract.IsPresent -or $List.IsPresent){
    
        try {$TestPath = Test-Path $ArchiveFile -ErrorAction Stop}
        catch {throw "$ArchiveFile doesn't exist, stopping"}
    
        } 
    
    If ($Add.IsPresent -or $Extract.IsPresent){
    
        try {$TestPath = Test-Path $Target -ErrorAction Stop}
        catch {throw "$Target doesn't exist, stopping"}
    
    }
    
    $Loud = !($Silent.IsPresent)
    
    #endregion Validate Exists
    
    #region Define 7z Alias
    switch (Test-Path .\7-Zip\7z.exe){
    
        $False {
    
                try {
                    
                    $7zPath = (Get-ItemProperty "HKCU:\SOFTWARE\7-Zip" -ErrorAction Stop).Path + '7z.exe'
    
                    try {$PathTest = Test-Path $7zPath -ErrorAction Stop}
                    catch {throw "Registry entry for 7-Zip exists but path $7zPath is not found"}
    
                } #Close try
                catch {throw "7z not installed on this computer and is not in a local directory"}
    
                #Remove-Variable 7zpath,PathTest
    
            } #Close False
    
        $True {$7zPath = (Get-Location).Path + "7-Zip\7z.exe"}
    
    } #Close Switch
    
    Set-Alias -Name 7z -Value $7zPath
    
    #endregion Define 7z Alias
    
    #region Build Params
    $7zParameters = ""
    
    $Operation = "None"
    
    If ($Add.IsPresent){
    
        $7zParameters += " a " + '"' + "$ArchiveFile" + '" "' + "$Target" + '" '
    
        $7zParameters += "-m -mx$CompressionLevel "
        
        If ($null -ne $CPUThreads){$7zParameters += "-mmt$CPUThreads "}
    
        $7zParameters += "-t$ArchiveType "
        
        If ($null -ne $VolumeSize){$7zParameters += "-v$VolumeSize "}
        If ($null -ne $Password){$7zParameters += "-p$Password "}
        
        $7zParameters += "-y"
    
        $Operation = "Add"
    
    } #Close $Add.IsPresent
    
    Elseif ($Extract.IsPresent) {
    
        $7zParameters += " x " + '"' + "$ArchiveFile" + '"' + " -o" + '"' + "$Target" + '" '
        If ($null -ne $CPUThreads){$7zParameters += "-mmt$CPUThreads "}
        If ($null -ne $Password){$7zParameters += "-p$Password "}
        $7zParameters += "-y"
        
        $Operation = "Extract"
    
    } #Close $Extract.IsPresent
    
    Elseif ($List.IsPresent){
    
    $7zParameters += " l " + '"' + "$ArchiveFile" + '"'
    If ($ShowTechnicalInfo.IsPresent){$7zParameters += " -slt"; $Operation = "ListSLT"}
    Else {$Operation = "List"}
    
    } #Close $List.IsPresent
    
    Else {throw "No valid parameters were found"}
    
    <#
    For Reference:
    7z x test.7z -bsp1 -ppassword -mmt14 -bse0 2>&1 >test.txt
    Extract test.7z, Redirect Progress to Stream 1, Password "password", 14 threads, Redirect Error to Stream 0, Redirect Stream 2 to 1, Output console output to test.txt
    #>
    
    #endregion Build Params
    
    #region Build Logfile
    
    If ($Operation -eq "Add" -or $Operation -eq "Extract"){
    
        $LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999).log"
        
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
    
        $RunCommand = invoke-expression "7z $7zParameters -bsp1" | Out-String -Stream 2>&1 > $LogFile
    
        return $RunCommand
    
        }
    
    }
    
    #endregion Build Scriptblock
    
    #region Build ESCAPE key Interception
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
    
    #endregion Build ESCAPE key Interception
    
    }
    
    process {
    
    <#Explanation of the Following:
     We need the list "Technical Info" of the archive for "Extract" to determine whether
     the archive is encrypted, and to enumerate the smallest file in the archive to
     test the provided password before attempting to unpack the archive.
    
     Therefore, "-Extract" requires the "l -slt" output.
    #>
    
    If ($Operation -eq "Extract" -or $Operation -eq "ListSLT"){
        
        $TechContents = 7z l "$ArchiveFile" -slt 2>&1
        
    #region TechContents Error-catching:
        $ArchiveErrors = $TechContents.Where({$_.Exception.Message.Length -gt 0}).Exception.Message
        
        Switch ($ArchiveErrors.Count){
        
        0 {$EncryptedTags = $TechContents.Where({$_ -eq "Encrypted = +"}) | Sort-Object -Unique}
        
        1 {
            &$LogfileCleanup
            throw $ArchiveErrors
        }
        
        {$_ -gt 1}{
            &$LogfileCleanup
            $ArchiveErrors[($ArchiveErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}
            throw ($ArchiveErrors[0])
        }
        
        Default {
            &$LogfileCleanup
            throw "No idea what happened"
        }
        
        } #Close Switch ArchiveErrors.Count
    #endregion TechContents Error-catching
        
    #region Build Technical Info List, Test Password
        If ($Operation -eq "Extract" -and $EncryptedTags.Count -gt 0 -and ($null -eq $Password -or $Password.Length -eq 0)){throw "Archive is encrypted, but no password was specified"}
            
        $TechTable = New-Object System.Collections.ArrayList
    
        $HeaderBreak = $TechContents.IndexOf("----------")
        $FileInfoLines = $TechContents[$HeaderBreak..$TechContents.GetUpperBound(0)].Count
    
        $x = $HeaderBreak + 1
        Do {  
    
            $LineLength = 1
            $y = $x
    
            Do {
    
                $LineLength = $TechContents[$y].Length
                $y++
    
            }
            Until ($LineLength -eq 0)
    
            $StartIndex = $x
            $EndIndex = $y - 2 #-2 because the "Until" statement doesn't evaluate until after $y++
    
            $Object = New-Object System.Object
            $TechContents[$StartIndex..$EndIndex].ForEach({
    
                $LineSplit = ($_ -split ' = ', 2).ForEach({$_.Trim()})
                $Object | Add-Member -MemberType NoteProperty -Name ($LineSplit[0]) -Value ($LineSplit[1])
    
                })
    
            $TechTable.Add($Object) | Out-Null
            
            $x = $y 
    
        }
        Until ($x -ge $FileInfoLines)
    
        #region Test the Password
        If ($Operation -eq "Extract" -and $null -ne $Password -and $null -ne $EncryptedTags){ 
    
        #Find the smallest file to test password against
        $SmallestFile = $TechTable.Where({$_.Encrypted -eq '+'}) | Sort-Object Size | Select-Object -First 1
        
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
            
        } #Close If ($Operation -eq "Extract" -or $Operation -eq "ListSLT")
    
    #endregion Build Technical Info List, Test Password
    
    #region (Heavy-lifting)
    
    Switch ($Operation){
    
            {$_ -eq "ListSLT"}{} #Do nothing; we already did this 
        
            {$_ -eq "List"}{
    
            $ListOutput = invoke-expression "7z $7zParameters -bso0 -bd 2>&1"
            
            $ListErrors = $ListOutput.Where({$_.GetType().Name -eq "ErrorRecord"})
            
            Switch ($ListErrors.Count){
        
                0 {} #Do nothing
        
                1 {
                        &$LogfileCleanup
                        throw $ListErrors
                    }
        
                {$_ -gt 1}{
                        &$LogfileCleanup
                        $ListErrors[($ListErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}
                        throw ($ListErrors[0])
                    }
        
                Default {
                        &$LogfileCleanup
                        throw "No idea what happened"
                    }
        
            } #Close Switch TestErrors.Count
    
            $ListTable = New-Object System.Collections.ArrayList
    
            [regex]$DateTime = '(Date).+(Time)'
            #region Find the Indexes
            $HeaderIndex = $ListOutput.IndexOf($ListOutput.Where({$_ -match $DateTime}))
            $Header = $ListOutput[$HeaderIndex]
    
            $FirstBreakIndex = $HeaderIndex + 1
            $FirstBreak = $ListOutput[$FirstBreakIndex]
    
            :BreakLoop Foreach ($Index in ($ListOutput.GetUpperBound(0)..($FirstBreakIndex + 1))){
            
            If ($ListOutput[$Index] -eq $FirstBreak){$LastBreakIndex = $Index; break BreakLoop}
            
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
            $ListOutput[($FirstBreakIndex + 1)..($LastBreakIndex - 1)].ForEach({
    
            $Line = $_        
            $Object = New-Object System.Object
            
            $BreakTable.ForEach({
                $Attr = $_
    
                If ($BreakTable.IndexOf($Attr) -eq ($BreakTable.Count - 1)){$Attr.End = $Line.Length}
    
                $Object | Add-Member -MemberType NoteProperty -Name ($Attr.Name) -Value (($Line[($Attr.Start)..($Attr.End)] -join '').Trim())
    
                }) #Close BreakTable.ForEach
    
            $ListTable.Add($Object) | Out-Null
    
            }) #Close $ListOutput.ForEach()
            #endregion Use the index points to parse out the -l contents
            
            #region Filter out faulty entries (from multi-volume archives)
            [regex]$FaultyEntries = "-{2,}|[0-9]+ files|^$"
    
            $ListTable = $ListTable.Where({$_.Name -notmatch $FaultyEntries})
    
            #endregion Filter out faulty entries
    
            } #Close if $_ -eq "List"
    
            {$_ -eq "Extract"}{
                $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList @("$((Get-Location).Path)",$7zPath,$7zParameters,$LogFile)
                
                $Done = $False
    
                $FileCount = $TechTable.Count
                $MoreThanOneFile = [bool]($FileCount -gt 1)
    
                $JobStatus = Get-Job ($Job.Id)
    
                Switch ($JobStatus.State){ #Check our job state to make sure it's running
    
                {$_ -eq "Failed"}{&$LogfileCleanup; throw "Job $($JobStatus.Id) failed for 7zip extract operation"}
                {$_ -eq "Blocked"}{&$LogfileCleanup; throw "Job $($JobStatus.Id) was blocked from running 7zip extract operation"}
                {$_ -eq "Stopped"}{&$LogfileCleanup; throw "Job $($JobStatus.Id) was stopped while running 7zip extract operation"}
                {$_ -eq "Suspended"}{&$LogfileCleanup; throw "Job $($JobStatus.Id) was suspended from running 7zip extract operation"}
    
                } #Close JobStatus.State
                
                If ($Loud){
                    &$InitializeInputBuffer
                    Write-Verbose "Press ESCAPE key to interrupt extract operation" -Verbose
                }
    
                #Predefine variables for parsing out original file name, number of files later:
                $ExtractionBegun = $False
                $LogfileRead = $False
    
                Do {
    
                    Start-Sleep -Milliseconds 250 #Sleep 1/4 of a second
    
                    $LogLatest = (Get-Content $LogFile -Tail 6).Where({$_ -match '(\d+)%|(\bEverything is Ok\b)'}) | Select-Object -Last 1
    
                    If (!$Loud -and [bool]($LogLatest -eq "Everything is Ok")){$Done = $True}
    
                    If ($Loud){
    
                        If ($null -eq $LogLatest -or $LogLatest.Length -eq 0){Start-Sleep -Milliseconds 100; $OnFile = 0; $File = "-"; $Percent = 0}
    
                        ElseIf ([bool]($LogLatest -eq "Everything is Ok")){$Done = $True; $OnFile = $FileCount; $File = "None (Complete)"; $Percent = 100}
    
                        ElseIf ($LogLatest -eq '  0%'){
                                                    $OnFile = 0
                                                    $File = "-"
                                                    $Percent = 0
                                                    $ExtractionBegun = !$ExtractionBegun
    
                                                }
    
                        ElseIf (!$MoreThanOneFile){
                            
                                                    $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                    $Percent = $Percent.TrimEnd('%').Trim()
                                                    $OnFile = 1
                                                    $ExtractionBegun = !$ExtractionBegun
    
                                                }
    
                        ElseIf ($MoreThanOneFile){
                            
                                                    $Percent,$File = ($LogLatest -split ' - ').Trim()
                                                    $Percent,$OnFile = ($Percent -split '%').Trim()
                                                    $ExtractionBegun = !$ExtractionBegun
    
                                                }
    
                        #Capture the original file name, number of files from logfile for split archive:
                        If ($ExtractionBegun -and !$LogfileRead){ 
                            
                            $LogLatest = Get-Content $LogFile
                            $VolLine = $LogLatest.IndexOf($LogLatest.Where({$_ -match "Volumes ="}))
                            
                            If ("" -ne $VolLine){
                                
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
    
                {$_ -eq "Completed"}{$JobContents = ($Job | Receive-Job); $Job | Remove-Job}
    
                {$_ -eq "Failed"}{&$LogfileCleanup; $JobError = $JobStatus.Error; $Job | Remove-Job; throw "Job errored: $JobError"}
    
                #11/19 - NEED TO CHECK JOB OUTPUT HERE
    
                } #Close Switch Get-Job (ID) State
            } #Close if $_ -eq "Extract"
    
            {$_ -eq "Add"}{}
    
    } #Close switch $Operation
       
    #endregion (Heavy-lifting)
    
    } #Close Process
    
    end {
    
    [Console]::TreatControlCAsInput = $False
    
    Switch ($Operation){
    
            {$_ -match 'Interrupted'}{
                
                Get-Job | Stop-Job
                Get-Job | Remove-Job
                &$LogfileCleanup
                Write-Verbose "Operation $Operation before completing" -Verbose
            
            }
    
            {$_ -eq "ListSLT"}{return $TechTable}
    
            {$_ -eq "List"}{return $ListTable}
    
            {$_ -eq "Extract"}{
    
                If ($KeepLogfile.IsPresent -and $Loud){Write-Verbose "Logfile is $LogFile" -Verbose}
    
                &$LogfileCleanup
    
                } #Close If Eq Extract
    
            {$_ -eq "Add"}{
    
                If ($KeepLogfile.IsPresent -and $Loud){Write-Verbose "Logfile is $LogFile" -Verbose}
    
                &$LogfileCleanup
            }
    
    } #Close Switch Operation
    
    
    } #Close End
    
    } #Close Invoke-7Zip