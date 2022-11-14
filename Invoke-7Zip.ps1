Function Invoke-7Zip {
[CmdletBinding()] 
param( 
    [Parameter(ParameterSetName='Add',Mandatory=$False)][switch]$Add, # a
    [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidateScript({$_ -ge ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors -1)})][int]$CPUThreads, #-m -mmt(1-16)
    [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidateRange(1,9)][Alias('Level')][int]$CompressionLevel, #-m -mx(1-9)
    [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidatePattern('^[0-9]+[KkMmGg]$')][Alias('VolSize')][string]$VolumeSize, #-v
    [Parameter(ParameterSetName='Add',Mandatory=$False)][ValidateSet("7z","xz","zip","gzip","bzip2","tar")][Alias('Type')][string]$ArchiveType, #-tzip,-t7z,etc
    [Parameter(ParameterSetName='Extract',Mandatory=$False)][switch]$Extract, # x
    [Parameter(ParameterSetName='List',Mandatory=$False)][switch]$List, # l
    [Parameter(ParameterSetName='List',Mandatory=$False)][Alias('TechInfo')][switch]$ShowTechnicalInfo,
    [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][Alias('Pass')][string]$Password, #-p
    [Parameter(ParameterSetName='Add',Mandatory=$False)][Parameter(ParameterSetName='Extract',Mandatory=$False)][ValidateScript({Test-Path $_})][Alias('Dir')][string]$Directory,
    [Parameter(Mandatory=$False)][Alias('File')][string]$ArchiveFile, #7z [a|e|l|x] C:\path\to\file.7z; Note: e = "extract" (all files to one dir); x = "extract to full paths" (all files with subdirs preserved)
    [Parameter(Mandatory=$False)][switch]$DontAssumeYes #-y
    
    #[Parameter(Mandatory=$False)][Alias('Recurse')][switch]$RecurseSubdirectories, #-r This only applies with wildcard filters, which I'm not going to include for this wrapper
    
)

begin {

#region Case-correct the File/Directory (7zip is case-sensitive)
$FileSystemObject = New-Object -ComObject Scripting.FileSystemObject

$ArchiveFile = $FileSystemObject.GetAbsolutePathName((Get-Item $ArchiveFile).FullName)

If ($Null -ne $Directory -and $Directory.Length -gt 0){$Directory = $FileSystemObject.GetAbsolutePathName($Directory)}

Remove-Variable FileSystemObject | Out-null

#endregion Case-Correct

#region Validate File/Directory parameters, based on switches
If ($Add.IsPresent){

    try {!($TestPath = Test-Path $ArchiveFile -ErrorAction Stop)}
    catch {throw "$ArchiveFile already exists, stopping"}

} #Close if $Add.IsPresent

If ($Extract.IsPresent -or $List.IsPresent){

    try {$TestPath = Test-Path $ArchiveFile -ErrorAction Stop}
    catch {throw "$ArchiveFile doesn't exist, stopping"}

    } #Close If $Extract.IsPresent|$List.IsPresent

If ($Add.IsPresent -or $Extract.IsPresent){

    try {$TestPath = Test-Path $Directory -ErrorAction Stop}
    catch {throw "$Directory doesn't exist, stopping"}

} #Close If $Add.IsPresent|$Extract.IsPresent

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

    $True {$7zPath = (Get-Location).Path + "\7-Zip\7z.exe"}

} #Close Switch

Set-Alias -Name 7z -Value $7zPath

#endregion Define 7z Alias

#region Build Params
$7zParameters = ""

$Operation = "None"

If ($Add.IsPresent){

    $7zParameters += " a " + '"' + "$ArchiveFile" + '" "' + "$Directory" + '"'

    $7zParameters += " -m -mx$CompressionLevel -t$ArchiveType"
    If ($null -ne $VolumeSize){$7zParameters += " -v$VolumeSize"}
    If ($null -ne $Password){$7zParameters += " -p$Password"}
    If (!($DontAssumeYes.IsPresent)){$7zParameters += " -y"}

    $Operation = "Add"

    #LEFT OFF HERE: Do I need to specify -r (recurse)? #PICKED UP: Nope

} #Close $Add.IsPresent

Elseif ($Extract.IsPresent) {

    $7zParameters += " x " + '"' + "$ArchiveFile" + '"' + " -o" + '"' + "$Directory" + '"'
    If ($null -ne $Password){$7zParameters += " -p$($Password)"}
    If (!($DontAssumeYes.IsPresent)){$7zParameters += " -y"}
    
    $Operation = "Extract"

} #Close $Extract.IsPresent

Elseif ($List.IsPresent){

$7zParameters += " l " + '"' + "$ArchiveFile" + '"'
If ($ShowTechnicalInfo.IsPresent){$7zParameters += " -slt"; $Operation = "ListSLT"}
Else {$Operation = "List"}

} #Close $List.IsPresent

Else {throw "No valid parameters were found"}

#endregion Build Params

#region Build Scriptblock

#For Reference:
#7z x test.7z -bsp1 -ppassword -mmt14 -bse0 2>&1 >test.txt
#Extract test.7z, Redirect Progress to Stream 1, Password "password", 14 threads, Redirect Error to Stream 0, Redirect Stream 2 to 1, Output console output to test.txt

If ($Operation -eq "Add" -or $Operation -eq "Extract"){

$LogFile = "$((Get-Location).Path)\$(get-random -Minimum 1000000 -Maximum 9999999).log"

try {"Write test" | Out-File $LogFile -ErrorAction Stop}
catch {throw "Unable to write data out to new logfile $LogFile"}

$Scriptblock = { #11/13: working on building this to capture console output

    $WorkingDirectory = $args[0]
    $7zPath = $args[1]
    $7zParameters = $args[2]
    $LogFile = $args[3]

    try {Set-Location $WorkingDirectory -ErrorAction Stop}
    catch {throw "Job is unable to move to $WorkingDirectory"}

    Set-Alias -Name 7z -Value $7zPath

    $CommandRun = invoke-expression "7z $7zParameters -bsp1" | Out-String -Stream 2>&1 > $LogFile

    #$G = invoke-expression "7z $7zParameters -bsp1" -ErrorAction Stop 2>&1
    #&7z x .\zipfile.7z  -ppassword -bsp1 -mmt14 | out-string -Stream 2>&1 >test.txt

    } #Close Scriptblock

} #Close if $Operation -eq Add|Extract

#endregion Build Scriptblock

} #Close Begin

process {

#since we have to run "-slt" for -List -ShowTechnicalInfo anyway, we'll do it here:
If ($Operation -ne "Add" -and $Operation -ne "List"){

    $TechContents = 7z l "$ArchiveFile" -slt 2>&1
    
#region TechContents Error-catching:
    $ArchiveErrors = $TechContents[$TechContents.GetUpperBound(0)..0].Where({$_.Exception.Message.Length -gt 0}).Exception.Message
    
    Switch ($ArchiveErrors.Count){
    
    0 {$EncryptedTags = $TechContents.Where({$_ -eq "Encrypted = +"}) | Sort-Object -Unique}
    
    1 {throw $ArchiveErrors}
    
    {$_ -gt 1}{$ArchiveErrors[($ArchiveErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}; throw ($ArchiveErrors[0])}
    
    Default {throw "No idea what happened"}
    
    } #Close Switch ArchiveErrors.Count
#endregion TechContents Error-catching
    
#region Test Password for encrypted volumes
    If ($null -ne $EncryptedTags -and $null -eq $Password -and !($List.IsPresent)){throw "Archive is encrypted, but no password was specified"}
    
    If (($null -ne $EncryptedTags -and $null -ne $Password) -or $Operation -eq "ListSLT"){
    
        #Build a Powershell Array with parsed -slt data
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

        If ($Operation -ne "ListSLT"){ #If we're not doing l -slt, we need to find the smallest file to test password against

        $SmallestFile = $TechTable.Where({$_.Encrypted -eq '+'}) | Sort-Object Size | Select-Object -First 1
        
        $PasswordTest = 7z t $ArchiveFile -p"$Password" -i!\($SmallestFile.Path) -bso0 -bd 2>&1
        
        If ($PasswordTest.Count -gt 0){$TestErrors = $PasswordTest[$PasswordTest.GetUpperBound(0)..0].Where({$_.Exception.Message.Length -gt 0}).Exception.Message}
    
        Switch ($TestErrors.Count){
    
            0 {} #Do nothing
    
            1 {throw $TestErrors}
    
            {$_ -gt 1}{$TestErrors[($TestErrors.GetUpperBound(0))..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}; throw ($TestErrors[0])}
    
            Default {throw "No idea what happened"}
    
        } #Close Switch TestErrors.Count
    
     } #Close if $Operation -ne ListSLT
   
    } #Close If $null -ne $encryptedtags -and $null -ne $password, -or $Operation -eq "ListSLT"
    
#endregion Test Password for encrypted volumes

    } #Close If $Operation -ne "Add"
#If we made it this far, password validation succeeded

#region Do the actual work

Switch ($Operation){

        {$_ -eq "ListSLT"}{} #Do nothing; we already did this 
    
        {$_ -eq "List"}{

        $ListOutput = invoke-expression "7z $7zParameters -bso0 -bd 2>&1"
        
        $ListErrors = $ListOutput.Where({$_.GetType().Name -eq "ErrorRecord"})
        
        Switch ($ListErrors.Count){
    
            0 {} #Do nothing
    
            1 {throw $ListErrors}
    
            {$_ -gt 1}{$ListErrors[($ListErrors.Count -1)..1].ForEach{(Write-Error -Message "$_" -ErrorAction Continue)}; throw ($ListErrors[0])}
    
            Default {throw "No idea what happened"}
    
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
        
        } #Close if $_ -match '-'

        Else {$x++} #If we find a space character, add 1 to the index
        
        })
        
        (0..($BreakTable.Count -1)).ForEach({
        
            $Index = $_
            $Entry = $Breaktable[$Index]
                        
            $BreakTable[$Index].Name = ($Header[($Entry.Start)..($Entry.End)] -join '').Trim()

            If ($BreakTable[$Index].Name -match $DateTime){$BreakTable[$Index].Name = "DateTime"}
        })
        #endregion Create a table
        
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
        #endregion
        
        } #Close if $_ -eq "List"

} #Close switch $Operation
   
#endregion Do the actual work

#VALIDATE PASSWORD: 7z t <archive> -p<pass> -bse1 #-bs redirects/halts console output: https://sevenzip.osdn.jp/chm/cmdline/switches/bs.htm
                    # 7z t .\test.7z -p14 -bso0 2>&1 #Disable stdout, redirect stderr to stdout

                    #A functional way to capture an error (doesn't work with try/catch):
                        #$X = 7z t .\test.7z -p14  2>&1

                        #If ($LASTEXITCODE -ne 0){
                        #    $TestError = $X.Where({$_.GetType().Name -eq "ErrorRecord"})
                        #}




} #Close Process

end {

Switch ($Operation){

        {$_ -eq "ListSLT"}{return $TechTable}

        {$_ -eq "List"}{return $ListTable}

        {$_ -eq "Extract"}{

            $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList @("$((Get-Location).Path)",$7zPath,$7zParameters,$LogFile)
        
            

            } #Close If Eq Extract

        {$_ -eq "Add"}{}

} #Close Switch Operation


} #Close End

} #Close Invoke-7Zip

#$WorkingDirectory = $args[0]
#$7zPath = $args[1]
#$7zParameters = $args[2]
#$Logfile = $args[3]