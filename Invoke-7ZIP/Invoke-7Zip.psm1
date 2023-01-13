<#
.SYNOPSIS
Resolves the location of 7Zip.

.DESCRIPTION
Attempts to identify and store the path of 7z.exe, and stores it as a global variable for use within the Invoke-7Zip module

.PARAMETER szPath
If specified, will use the provided path as the location of the 7Zip executable.

.EXAMPLE
Initialize-7zip

.LINK
GitHub: https://github.com/jross365/Invoke-7Zip

#>
Function Initialize-7zip ($szPath){

    If ($szPath.Length -gt 0 -and $null -ne $SzPath){
    
        try {$PathTest = Test-Path $szPath -ErrorAction Stop; $7zPathExists = $True}
        catch {$7zPathExists = $False}

    }

    If (!($7zPathExists) -or ($szPath.Length -eq 0 -or $null -eq $S7zPath)){

        switch (Test-Path .\7-Zip\7z.exe){
    
            $False {
        
                    try {
                        
                        $SzPath = (Get-ItemProperty "HKCU:\SOFTWARE\7-Zip" -ErrorAction Stop).Path + '7z.exe'
        
                        try {$PathTest = Test-Path $szPath -ErrorAction Stop}
                        catch {throw "Registry entry for 7-Zip exists but path $szPath is not found"}
        
                    } #Close try
                    catch {throw "7z not installed on this computer and is not in a local directory"}
        
                  } #Close False
        
            $True {$szPath = (Get-Location).Path + "7-Zip\7z.exe"}
        
        } #Close Switch

    }
    
    Set-Alias -Scope Global -Name 7z -Value $szPath
    
    $Global:szPath = $szPath

}

<#
.SYNOPSIS
Returns the absolute path of a file or folder.

.DESCRIPTION
Provides the case-correct path of a file or folder.

.PARAMETER Path
The path of the source file or folder.

.EXAMPLE
Get-AbsolutePath -Path "c:\program files\7zip\7z.exe"

C:\Program Files\7Zip\7z.exe

.LINK
GitHub: https://github.com/jross365/Invoke-7Zip

#>
Function Get-AbsolutePath ($Path){
    
    $FileSystemObject = New-Object -ComObject Scripting.FileSystemObject
    
    Try {$AbsolutePath = $FileSystemObject.GetAbsolutePathName((Get-Item $Path -ErrorAction Stop).FullName)}
    Catch {throw "$Path name or path is not valid"}
    
    Remove-Variable FileSystemObject | Out-null

    return $AbsolutePath

} #Close Function Get-AbsolutePath

<#
.SYNOPSIS
Returns the contents of an archive.

.DESCRIPTION
Provides information about the files of a specified archive.
Returns an [arraylist] of objects.

.PARAMETER ArchiveFile
The name of the source archive file.

Path may be explicit or relative.

.PARAMETER ShowTechnicalInfo
If specified, lists the technical info of the files in an archive (equivalent to 7z l -slt).

.EXAMPLE
$ArchiveFiles = Get-ArchiveContents -ArchiveFile DoC.bz2

.EXAMPLE
$DetailedFileInfo = Get-ArchiveContents -ArchiveFile DoC.bz2 -ShowTechnicalInfo


.LINK
GitHub: https://github.com/jross365/Invoke-7Zip

#>
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

Function Test-Archive {
    param( 
        [Parameter(Mandatory=$True)][Alias('File')][string]$ArchiveFile,
        [Alias('Include')][string]$SpecificPathOrPattern,
        [Alias('Pass')][string]$Password,
        [switch]$Quiet

        )
    begin {
        #region Initialize variables
        try {$ArchiveFile = Get-AbsolutePath $ArchiveFile}
        catch {throw "$ArchiveFile is not a valid path"}

        If ((Get-Alias 7z -ErrorAction SilentlyContinue).Count -eq 0){
        
            Try {Initialize-7zip -ErrorAction Stop}
            Catch {throw "Unable to initialize 7zip alias"}
        }
        #endregion Initialize variables

        #region Evaluate whether archive is password protected
        If ($Password.Length -eq 0){
        try {$ArchiveContents = Get-ArchiveContents -ArchiveFile $ArchiveFile -ShowTechnicalInfo}
        catch {
            
            If ($Quiet.IsPresent){$SkipProcessBlockAndReturnFalse = $True}
            Else {throw "Errors encountered when enumerating contents of $ArchiveFile"}        
            
        }

        $EncryptedTags = $ArchiveContents.Where({$_.Encrypted -eq "+"}) | Sort-Object -Unique

        If ($EncryptedTags.Count -gt 0 -and $Password.Length -eq 0){
            
            If ($Quiet.IsPresent){$SkipProcessBlockAndReturnFalse = $True}
            Else {throw "Archive is password-protected, but no password was specified"}
        
            }
        
        } #Cl
        #endregion Evaluate whether archive is password protected
        
        #Not specifying a password for a password-protected archive will cause 7z to sit at a password prompt
        If ($Password.Length -eq 0){$Password = $null}
                
        $7zParameters = ""
        $7zParameters += " t " + '"' + "$ArchiveFile" + '" '
        $7zParameters += "-p" + '"' + "$Password" + '" '
        If ($PSBoundParameters.ContainsKey("SpecificPathOrPattern")){$7zParameters += "-ir!\ $SpecificPathOrPattern "}

        $7zParameters = $7zParameters.TrimEnd()

    } #Close Begin

    process {

        If (!($SkipProcessBlockAndReturnFalse)){$ArchiveTest = Invoke-Expression "7z $7zParameters -bse1 -bso0 -bd" 2>&1}

    }

    end {

        Switch ($Quiet.IsPresent){

            $true {

                If ($ArchiveTest.Count -eq 0 -and !($SkipProcessBlockAndReturnFalse)){return $True}
                Else {return $False}

            }

            $false {

                If ($ArchiveTest.Count -gt 0){
                    
                    $WrongPasswordCount = $ArchiveTest.Where({$_ -match "Wrong password"}).Count
                    
                    If ($WrongPasswordCount -gt 0){throw "Wrong password for $WrongPasswordCount files"}
                    
                    Else {throw $ArchiveTest}

                    }
                
                }
            
                }

            }

} #Close Function Test-Archive

<#
.SYNOPSIS
Extracts an archive.

.DESCRIPTION
Extracts an archive to a specified directory.

.PARAMETER ArchiveFile
The name of the source archive file.

Path may be explicit or relative.

.PARAMETER Destination
The path the archive contents are to be extracted to.

Path may be explicit or relative.

.PARAMETER Password
The password for decrypting and extracting the contents of the archive.

.PARAMETER SkipPasswordCheck
If specified, will skip password validation before attemptingd to extract the archive.

.PARAMETER UseMultithreading
If specified, 7z will attempt to enforce multithreading (not supported by all formats.)

Number of threads will always be the total cores on the system, minus 1.

.PARAMETER KeepLogfile
If specified, will preserve the 7-Zip logfile used for parsing and reporting progress.

This parameter is useful for troubleshooting, and provides the 7zip console output.

.PARAMETER Quiet
If specified, suppresses progress bar and corresponding verbose outputs (success, failure, errors).

.INPUTS
None. You cannot pipe objects to Extract-Archive.

.OUTPUTS
Default: Progress bar, verbose outputs, standard errors.

-Quiet: Boolean ($True for success, $False for failed)

.EXAMPLE
Extract-Archive -ArchiveFile D:\Resumes\Doc-Backup.7z -Destination C:\Users\User1\Desktop -Password supersecret -UseMultithreading

Extracts contents of "Doc-Backup.7z" to the user's Desktop, using the specfied password.

.EXAMPLE
Extract-Archive -ArchiveFile D:\DeityOfConflict.bz2 -Destination D:\Games\DeityOfConflict -UseMultithreading -Quiet

Extracts contents of "DeityOfConflict.bz2" to the "DeityOfConflict" folder. Console output is suppressed.


.LINK
GitHub: https://github.com/jross365/Invoke-7Zip

#>
Function Extract-Archive { 
    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory=$True,Position=0)][Alias('File')][string]$ArchiveFile,
        [Parameter(Mandatory=$True,Position=1)][ValidateScript({Test-Path $_})][Alias('Dest')][string]$Destination,
        [Parameter(Position=2)][Alias('Multithread')][switch]$UseMultithreading,
        [Parameter(Position=3)][Alias('KeepLog')][switch]$KeepLogfile,
        [Parameter(Position=4)][switch]$Quiet,
        [Parameter(ParameterSetName='PW',Position=5)][Alias('Pass')][string]$Password,
        [Parameter(ParameterSetName='PW',Position=6)][Alias('SkipCheck')][switch]$SkipPasswordCheck
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
            
            try {$PasswordTest = Test-Archive -ArchiveFile $ArchiveFile -SpecificPathOrPattern $($SmallestFile.Path) -Password $Password}
            catch {throw $Error[0].Exception.Message}
           
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
                        
                        If ($VolLine -gt 1){ #Covers '0' (returned $false in [bool]), and '-1' (returned "none" as [int]), and '1' (not sure why 1 comes back sometimes)
                            
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

<#
.SYNOPSIS
Creates an archive.

.DESCRIPTION
Creates an archive from a specified file or folder.

For details about options and their corresponding parameters, please see https://sevenzip.osdn.jp/chm/cmdline/switches/method.htm.

.PARAMETER Source
The path of the file or folder to be added to an archive.

Path may be explicit or relative.

.PARAMETER ArchiveFile
The name of the destination archive file.

Path may be explicit or relative.

.PARAMETER Password
Used with all archive formats. (May not apply to all archive formats.)

If specified, password-protects the archive contents.

.PARAMETER Overwrite
If specified and an archive file of the same name already exists, deletes the existing destination archive file.

.PARAMETER VolumeSize
If specified, breaks up the destination archive into volumes of the specified size.

Format must be an integer followed by "K" (kilobytes), "M" (megabytes) or "G" (gigabytes).

.PARAMETER Zip
If specified, destination archive will be ZIP format.

.PARAMETER GZip
If specified, destination archive will be GZIP format.

.PARAMETER BZip2
If specified, destination archive will be BZIP2 format.

.PARAMETER SevenZip
If specified, destination archive will be 7Z format.

.PARAMETER Xz
If specified, destination archive will be XZ format.

.PARAMETER Tar
If specified, destination archive will be TAR format.

.PARAMETER ZipMethod
Used with -Zip. 

If specified, sets the ZIP method. Possible values are Copy, Deflate, Deflate64, BZip2, LZMA.

If not specified, default is Deflate.

.PARAMETER UseMultithreading
If specified, 7z will attempt to enforce multithreading (not supported by all formats.)

Number of threads will always be the total cores on the system, minus 1.

.PARAMETER CompressionLevel
Used with -Zip, -GZip, -BZip2 and -SevenZip. 

If specified, sets the compression level. Possible values are odd numbers between 0 and 9.

If not specified, default is typically 5 (depending on the compression algorithm).

.PARAMETER EncryptionMethod
Used with -Zip and -GZip. 

If specified, sets the encryption level. Possible values are ZipCrypto, AES128, AES192 and AES256.

If not specified, default is ZipCrypto.

.PARAMETER PreserveTimestamps
Used with -Zip, -GZip and -SevenZip. 

If specified, retains Create, Access and Modify timestamps for archived files (where applicable).

.PARAMETER UseLocalCodePage
Used with -Zip and -GZip. 

If specified, preserves the system's locale specifics (region and character information).

.PARAMETER Use$UTF8ForNonASCIISymbols
Used with -Zip and -GZip. 

If specified, Non-ASCII symbols (in filenames) will be assigned UTF-8 equivalents.

.PARAMETER Passes
Used with -Zip, -GZip and -BZip2. 

If specified, will attempt to recompress data the designated number of times.

May or may not correspond or conflict with the -CompressionLevel parameter.

-Zip and -GZip accept a range between 1 and 10; -BZip2 accepts a range between 1 and 15.

.PARAMETER SolidModeOff
Used with -SevenZip. 

If specified, Solid Mode is disabled.

.PARAMETER ExeCompressionOff
Used with -SevenZip. 

If specified, will not attempt to compress executable files.

.PARAMETER HeaderCompressionOff
Used with -SevenZip. 

If specified, will not compress the archive header (file and archive information).

.PARAMETER EncryptHeaderOn
Used with -SevenZip. 

If specified, will encrypt header along with contents.

.PARAMETER KeepLogfile
If specified, will preserve the 7-Zip logfile used for parsing and reporting progress.

This parameter is useful for troubleshooting, and provides the 7zip console output.

.PARAMETER Quiet
If specified, suppresses progress bar and corresponding verbose outputs (success, failure, errors).

.INPUTS
None. You cannot pipe objects to Create-Archive.

.OUTPUTS
Default: Progress bar, verbose outputs, standard errors.

-Quiet: Boolean ($True for success, $False for failed)

.EXAMPLE
Create-Archive -Source D:\Games\DeityOfConflict -ArchiveFile Z:\GameBackups\DoC-Backup.7z -VolumeSize 4G -SevenZip -CompressionLevel 9

Creates an 7Z archive from the "DeityOfConflict" directory called "DoC-Backup.7z". Archive is split into 4GB volumes, using the maximum compression level.

.EXAMPLE
Create-Archive -Source .\ResumeV9-Updated.docx -ArchiveFile SecretResume.zip -Password supersecret -Zip -EncryptionMethod AES256 -Quiet

Creates a password-protected, AES-256 encrypted ZIP file from "ResumeV9-Updated.docx" using the provided password. interactive console is suppressed (-Quiet)

.LINK
GitHub: https://github.com/jross365/Invoke-7Zip

#>
Function Create-Archive {
    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory=$True,Position=0)][ValidateScript({Test-Path $_})][Alias('Src')][string]$Source,
        [Parameter(Mandatory=$True,Position=1)][Alias('File')][string]$ArchiveFile,
        [Parameter(ParameterSetName='Zip',Position=2)][switch]$Zip, #Need to enumerate the desired file type from the -ArchiveFile extension
        [Parameter(ParameterSetName='GZip',Position=2)][switch]$GZip,
        [Parameter(ParameterSetName='BZip2',Position=2)][switch]$BZip2,
        [Parameter(ParameterSetName='7z',Position=2)][switch]$SevenZip,
        [Parameter(ParameterSetName='Xz',Position=2)][switch]$Xz,
        [Parameter(ParameterSetName='tar',Position=2)][switch]$Tar,
        [Parameter(Position=3)][ValidatePattern('^[0-9]+[KkMmGg]$')][Alias('VolSize')][string]$VolumeSize,
        [Parameter(Position=4)][Alias('Pass')][string]$Password,
        [Parameter(Position=5)][Alias('Multithread')][switch]$UseMultithreading,
        [Parameter(Position=6)][switch]$Overwrite, #Need to write in accommodation of multi-volume archives
        [Parameter(Position=7)][Alias('KeepLog')][switch]$KeepLogfile,
        [Parameter(Position=8)][switch]$Quiet,
        [Parameter(ParameterSetName='Zip',Position=9)][ValidateSet("Copy","Deflate","Deflate64","BZip2","LZMA")][string]$ZipMethod,
        [Parameter(ParameterSetName='Zip',Position=10)][Parameter(ParameterSetName='GZip',Position=9)][Parameter(ParameterSetName='BZip2',Position=9)][Parameter(ParameterSetName='7z',Position=9)][ValidatePattern('[013579]')][int]$CompressionLevel,
        [Parameter(ParameterSetName='Zip',Position=11)][Parameter(ParameterSetName='GZip',Position=10)][ValidateSet("ZipCrypto","AES128","AES192","AES256")][string]$EncryptionMethod,
        [Parameter(ParameterSetName='Zip',Position=12)][Parameter(ParameterSetName='GZip',Position=11)][Parameter(ParameterSetName='7z',Position=10)][switch]$PreserveTimestamps, #Need to accommodate different defaults (on vs off)
        [Parameter(ParameterSetName='Zip',Position=13)][Parameter(ParameterSetName='GZip',Position=12)][switch]$UseLocalCodePage,
        [Parameter(ParameterSetName='Zip',Position=14)][Parameter(ParameterSetName='GZip',Position=13)][switch]$UTF8ForNonASCII,
        [Parameter(ParameterSetName='Zip',Position=15)][Parameter(ParameterSetName='GZip',Position=14)][Parameter(ParameterSetName='BZip2',Position=10)][int]$Passes, #Need to validate 1-10 (ZIP/GZIP & Deflate) and 1-15 (BZIP)
        [Parameter(ParameterSetName='7z',Position=11)][switch]$SolidModeOff,
        [Parameter(ParameterSetName='7z',Position=12)][switch]$ExeCompressionOff,
        [Parameter(ParameterSetName='7z',Position=13)][switch]$HeaderCompressionOff,
        [Parameter(ParameterSetName='7z',Position=14)][switch]$EncryptHeaderOn #Need to validate the use of "-Password" if this switch is specified
        )

    begin {
  
        #region Case-correct and check paths and aliases
        
        If (Test-Path "$ArchiveFile"){

            Switch ($OverWrite.IsPresent){

                $True {
                    
                    $FinalFileName = $ArchiveFile
                    
                    $ArchiveFile = $ArchiveFile + '.tmp'
                    
                    If (Test-Path $ArchiveFile){
                     
                        try {$RemoveFile = Remove-Item $ArchiveFile -ErrorAction Stop}
                        catch {throw "Unable to remove temporary file $ArchiveFile"}

                    }

                    $OverWriteCleanup = $True

                }

                $False {throw "$ArchiveFile exists. Please specify a new filename or use the -Overwrite parameter"}

            }
    
            }

        Else {$OverWriteCleanup = $False}
        
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
            If ($UTF8ForNonASCII.IsPresent){$7zParameters += "-mcu=on "}

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

               If ($Global:Interrupted -eq $True){$Operation = "$Operation Interrupted"; $Successful = $False}

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

        Switch ($Successful){
        
            $False {

                If ($PSBoundParameters.ContainsKey('VolSize')){Remove-Item $ArchiveFile\.* -ErrorAction SilentlyContinue}
                Else {Remove-Item $ArchiveFile -ErrorAction SilentlyContinue}

                If ($Global:Interrupted -eq $True -and $Loud){throw "Operation was interrupted before completion"}
                Elseif ($Global:Interrupted -eq $False -and $Loud){throw "Job errored; job found in state $($JobStatus.State) after completion"}
                Else {return $False} #-Quiet

            }

            $True {

                If ($OverWriteCleanup){

                    Remove-Item $FinalFileName -ErrorAction SilentlyContinue #Delete the original file
                    
                    Rename-Item -Path $ArchiveFile -NewName $FinalFileName -Confirm:$False #Rename the .tmp file to the original filename

                }

                If ($Loud){Write-Verbose "Archive file successfully created" -Verbose}
                Else {return $True}

            }

        }

    }

} #Close Function Extract-Archive

#region Module Instructions
New-Alias -Name i7z -Value Initialize-7zip
New-Alias -Name gap -Value Get-AbsolutePath
New-Alias -Name gac -Value Get-ArchiveContents
New-Alias -Name tarch -Value Test-Archive
New-Alias -Name earch -Value Extract-Archive
New-Alias -Name carch -Value Create-Archive

Export-ModuleMember -Function Initialize-7zip
Export-ModuleMember -Function Get-AbsolutePath
Export-ModuleMember -Function Get-ArchiveContents
Export-ModuleMember -Function Test-Archive
Export-ModuleMember -Function Extract-Archive
Export-ModuleMember -Function Create-Archive

Export-ModuleMember -Alias i7z
Export-ModuleMember -Alias gap
Export-ModuleMember -Alias gac
Export-ModuleMember -Alias tarch
Export-ModuleMember -Alias earch
Export-ModuleMember -Alias carch