# Invoke-7Zip (**I7Z**)

Invoke-7Zip is a comprehensive Powershell wrapper module for 7-Zip.

## Description

This module extends Powershell functionality to 7-Zip, while providing script and user-friendly capabilities and features.

![Example of 7z Archive Creation](/.github/images/compressionexample.png)

## Capabilities

* **List** the contents of archives
* **Test** archives for integrity or password accuracy
* **Archive** files and folders as ZIP, GZIP, BZIP2, 7Z, XZ or TAR 
* **Extract** the contents of any archive supported by 7-Zip

## Features

* **Progress Bar** provides a visual and textual indicator of archive and extract progress
* **Quiet Mode** for script-friendly message suppression of Archive/Extract operations
* **Input Validation** of parameters to quickly and easily identify issues and incompatibilities
* **Output Log Preservation** For retention of console output during Archive/Extract operations
* **Graceful Interruption** during execution to automatically clean up artifact files after a cancelled run

## Getting Started

### Dependencies

**Invoke-7Zip** has the following dependencies:
* Microsoft Windows OS (Windows 7 or greater, Windows Server 2008 or greater)
* Windows Powershell (5.1+ recommended)
* 7Zip Software v19.00 (preferrably the installed, not standalone; versions below 19.00 haven't been tested)


### Installing
Save the *Invoke-7Zip* folder to any one of these three folders:

```
C:\Users\<username>\Documents\WindowsPowerShell\Modules
C:\Program Files\WindowsPowerShell\Modules        
C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

### Importing the Module

Import the module using the following command:

```
Import-Module Invoke-7Zip -DisableNameChecking
```

**Note:** Some of the module's functions use "unapproved verbs". This is because the "approved verbs" list doesn't contain verbs that apply to the breadth of possible uses for the noncompliant functions.

## Create-Archive
Creates an archive file from a provided path.

![Create-Archive](/.github/images/create-archive-example.png)

### Basic Usage

```
Create-Archive -Source <File or Directory> -ArchiveFile <FileName> -<Archive Format>
```

Alternatively, you can use the alias:

```
carch -Src <File or Directory> -File <FileName> -<ArchiveFormat>
```

### Examples

Creates a TAR file from D:\Downloads:
```
Create-Archive -Source D:\Downloads -ArchiveFile D:\downloads.tar -Tar
```

Creates a password-protected BZIP2 file from D:\downloads.tar:
```
Create-Archive -Source D:\downloads.tar -ArchiveFile D:\downloads.tar.bz2 -BZip2 -Password P@ssw0rd
```

Same as the above, but no password and breaks archive up into 4GB volumes:
```
Create-Archive -Source D:\downloads.tar -ArchiveFile D:\downloads.tar.bz2 -BZip2 -VolumeSize 4G
```

### General Parameters
All parameters are explicitly positional to make the parameter order more coherent and to simplify tab-completion.

#### **-Source**
The file or directory you wish to add to an archive.

This parameter is mandatory.

#### **-ArchiveFile**
The name of the archive to to be created.

This parameter is mandatory.

#### **-VolumeSize**
Breaks the resultant archive file up into individual files of the specified size.

Valid values are any integer, followed by a "K", "M" or "G".

Examples:

* 512K = 512 Kilobytes
* 50M = 50 Megabytes
* 2G = 2 Gigabytes

If specified, the resultant archive files will be the name provided via *-ArchiveFile*, plus ".##"

**Note:** With the 7Zip application, no "root" (non-numbered) file is created when volume size is specified.

Example:

* Backup.tar.00
* Backup.tar.01
* Backup.tar.02

#### **-Password**
Applies a password to the archive, and encryption (when applicable to the chosen file format).

#### **-UseMultithreading**
Attempts to force maximal multithreading for the archive creation process (total cores - 1).

If not specified, the number of threads used will be the default for the chosen compression algorithm.

If specified but the compression algorithm doesn't support a non-fixed number of threads (1, 2 or 4), this parameter has no impact.

#### **-Overwrite**
Overwrite pre-existing archive files of the same name (as was specified with *-ArchiveFile* parameter).

#### **-KeepLogFile**
Don't delete the "streaming" log file created during the archive creation process.

This parameter is useful for troubleshooting and reviewing 7Zip's behavior after completion.

#### **-Quiet**
Suppress console output, (most) error output, and don't show a progress bar during the archive creation process.

This parameter is useful for incorporating the function into "silent" scripts.

If specified, the function will return *$true* if compression is successful, or *$false* if any problem is encountered.

### Archive Format Parameters
These parameters are used to specify the type of archive you wish to create.
Each of these parameters leads a parameters-set specific to the chosen format.

#### **-Zip**
Specifies the creation of a ZIP file.

#### **-GZip**
Specifies the creation of a GZIP file.

#### **-BZip2**
Specifies the creation of a BZIP2 file.

Note: BZip2 can only compress a single file.

#### **-SevenZip**
Specifies the creation of a 7Z file.

#### **-XZ**
Specifies the creation of an XZ file.

Note: XZ can only compress a single file.

#### **-Tar**
Specifies the creation of a Tar file.

### -Zip Parameters
These parameters apply to the *-Zip* parameter set.

#### **-ZipMethod**
Specifies the ZIP file compression method.

Valid values are:

* Copy
* Deflate
* Deflate64
* BZip2
* LZMA

If unspecified, default is Deflate.

#### **-CompressionLevel**
Specifies the level of compression, from 0 (none) to 9 (maximum).

If unspecified, default is 5.

#### **-EncryptionLevel**
Specifies the level of encryption.

Valid values are:

* ZipCrypto
* AES128
* AES192
* AES256

If unspecified, default is ZipCrypto.

#### **-PreserveTimestamps**
If specified, sets whether file creation, modification and access information are preserved in compressed files.

Valid values are boolean ($True or $False).

#### **-UseLocalCodePage**
Preserve the locale character set for compressed file names.

#### **-UTF8ForNonASCII**
Use UTF-8 encoding for filenames that use non-ASCII encoding.

#### **-Passes**
Specifies the number of passes 7-Zip will make when compressing each file.

Valid values are any integer from 1 to 10.

This parameter corresponds with values defined by the *-CompressionLevel* and *-ZipMethod* parameters, and should not be used under most circumstances.

### -GZip Parameters
These parameters apply to the *-GZip* parameter set.

#### **-CompressionLevel**
Specifies the level of compression, from 0 (none) to 9 (maximum).

If unspecified, default is 5.

#### **-EncryptionLevel**
Specifies the level of encryption.

Valid values are:

* ZipCrypto
* AES128
* AES192
* AES256

If unspecified, default is ZipCrypto.

#### **-PreserveTimestamps**
If specified, sets whether file creation, modification and access information are preserved in compressed files.

Valid values are boolean ($True or $False).

#### **-UseLocalCodePage**
Preserve the locale character set for compressed file names.

#### **-UTF8ForNonASCII**
Use UTF-8 encoding for filenames that use non-ASCII encoding.

#### **-Passes**
Specifies the number of passes 7-Zip will make when compressing each file.

Valid values are any integer from 1 to 10.

This parameter corresponds with values defined by the *-CompressionLevel* parameter, and should not be used under most circumstances.

### -BZip2 Parameters
These parameters apply to the *-BZip2* parameter set.

#### **-CompressionLevel**
Specifies the level of compression, from 0 (none) to 9 (maximum).

#### **-Passes**
Specifies the number of passes 7-Zip will make when compressing each file.

Valid values are any integer from 1 to 15.

This parameter corresponds with values defined by the *-CompressionLevel* parameter, and should not be used under most circumstances.

### -SevenZip Parameters
These parameters apply to the *-SevenZip* parameter set.

#### **-CompressionLevel**
Specifies the level of compression, from 0 (none) to 9 (maximum).

#### **-PreserveTimestamps**
If specified, sets whether file creation, modification and access information are preserved in compressed files.

Valid values are boolean ($True or $False).

#### **-SolidModeOff**
If specified, files are compressed individually instead of as a single, contiguous "block" of binary.

#### **-ExeCompressionOff**
If specified, 7-Zip will not attempt to compress executable files.

#### **-HeaderCompressionOff**
If specified, 7-Zip will not compress the archive header.

#### **-EncryptHeaderOn**
If specified, the archive header will be encrypted along with the archive contents.

### -Xz Parameters
There are no additional parameters available with the *-Xz* parameter.

### -Tar Parameters
There are no additional parameters available with the *-Tar* parameter.


## Extract-Archive
Extracts an archive to the specified path.

![Extract-Archive](/.github/images/extract-archive-example.png)

### Basic Usage

```
Extract-Archive -ArchiveFile <FileName> -Destination <Directory>
```

Alternatively, you can use the alias:

```
earch -File <FileName> -Dest <Directory>
```

### Examples

Extracts a TAR file to D:\Downloads:
```
Extract-Archive -ArchiveFile D:\downloads.tar -Destination D:\Downloads 
```

Extracts a password-protected BZIP2 file to D:\Downloads:
```
Extract-Archive -ArchiveFile D:\downloads.tar.bz2 -Destination D:\Downloads -Password P@ssw0rd
```

Same as the above, but no password and an extracts archive broken up into volumes:
```
Extract-Archive -ArchiveFile D:\downloads.tar.bz2.00  -Destination D:\Downloads
```

### Parameters
All parameters are explicitly positional to make the parameter order more coherent and to simplify tab-completion.

#### **-ArchiveFile**
The name of the archive to to be extracted.

This parameter is mandatory.

#### **-Destination**
The destination directory for the extracted contents of the archive file.

This parameter is mandatory.

#### **-UseMultithreading**

Attempts to force maximal multithreading for the archive extraction process (total cores - 1).

If not specified, the number of threads used will be the default for the chosen compression algorithm.

If specified but the compression algorithm doesn't support a non-fixed number of threads (1, 2 or 4), this parameter has no impact.

#### **-KeepLogFile**
Don't delete the "streaming" log file created during the archive extraction process.

This parameter is useful for troubleshooting and reviewing 7Zip's behavior after completion.

#### **-Quiet**
Suppress console output, (most) error output, and don't show a progress bar during the archive extraction process.

This parameter is useful for incorporating the function into "silent" scripts.

If specified, the function will return *$true* if compression is successful, or *$false* if any problem is encountered.

#### **-Password**
Specifies the password to decrypt a password-protected archive file.

#### **-SkipPasswordCheck**
If specified, *Extract-Archive* will not validate whether the specified password is correct before attempting to extract the archive's contents.

This parameter is useful if the archive contains a very large (>1GB) file or files, and will speed up processing.

Recommended use is if you are certain of the file password.


## Get-ArchiveContents
Lists the contents of an archive.

![Get-ArchiveContents](/.github/images/get-archivecontents-example.png)

### Basic Usage

```
Get-ArchiveContents -ArchiveFile <FileName>
```

Alternatively, you can use the alias:

```
gac -File <FileName>
```

### Examples

Displays the basic information for files in an archive:
```
Get-ArchiveContents -ArchiveFile D:\downloads.tar
```

Displays detailed information for files in an archive:
```
Get-ArchiveContents -ArchiveFile D:\downloads.tar -ShowTechnicalInfo
```

### Parameters

#### **-File**
The name of the archive whose contents should be enumerated.

This parameter is mandatory.

#### **-ShowTechnicalInfo**
If specified, will display advanced information about the archive's contents.

This parameter is recommended for most queries, though it's not a default in 7-Zip.


## Test-Archive
Tests an archive's integrity, and/or tests the validity of an archive's password.

![Test-Archive](/.github/images/test-archive-example.png) 

### Basic Usage

```
Test-Archive -ArchiveFile <FileName>
```

Alternatively, you can use the alias:

```
tarch -File <FileName>
```

### Examples

Tests the validity of a password against an archive:
```
Test-Archive -ArchiveFile downloads.tar -Password "robblerobble"
```

Tests a specific file
```
Get-ArchiveContents -ArchiveFile D:\downloads.tar -ShowTechnicalInfo
```

### Parameters

#### **-File**
The name of the archive whose contents should be enumerated.

This parameter is mandatory.

#### **-SpecificPathOrPattern**
If specified, will attempt to test files based on the provided pattern.

Please note that this functionality extends from [the -ir!](https://sevenzip.osdn.jp/chm/cmdline/switches/include.htm) parameter.

The *-ir!* parameter is unreliable and unpredictable. For example, providing the explicit path of a file in the archive may find numerous dissimilar filenames, or it may find no files at all.

If this parameter is necessary, it is strongly recommended that you provide the explicit file path within the archive. You can use the *Get-ArchiveContents* function to identify such a path (though the *Get-ArchiveContents* function also uses the Test-Archive function :-) )

#### **-Password**
Specifies the password to use for testing the password and/or testing the archive.

#### **-Quiet**
Suppress console output, (most) error output, and don't show a progress bar during the archive extraction process.

This parameter is useful for incorporating the function into "silent" scripts.

If specified, the function will return *$true* if compression is successful, or *$false* if any problem is encountered.


## Help
Notes and comments regarding all things involving the word "help"

### Powershell Help
Every function in this module has a full-featured Comment-Based Help (CBH) header.

You can run the **Get-Help** command to see more information about parameters, aliases, examples, etc.

To view the full help manifest for Invoke-7Zip, for example:
```
Get-Help Invoke-7Zip -Full
```

### Reporting Bugs
With the size and complexity of this module, there are undoubtedly bugs and problems in the code. I try to fix things as soon as I identify a problem, but that's often easier said than done.

If you encounter a bug, please report it. Let me know exactly how you encountered it, including relevant conditions, parameter input and console output.

## Known Issues
This is a list of things that I am aware of, and plan to fix:

* ~~"Clean Up" code after failure/cancellation will not work with multi-volume archives~~
* ~~"OverWrite Clean Up" code after success will not work with multi-volume archives~~
* Create-Archive's "$PreserveTimestamps" parameter has a mismatch (default is "on" with zip/gzip, mix of multiple on/off parameters with 7z)
    * For 7z, will roll all the attributes (create, modification, last access options) into this single parameter
* Create-Archive's "$Passes" parameter doesn't check for appropriate values (1-10 for zip/gzip, 1-15 for bzip)
* Create-Archive's "$EncryptHeaderOn" parameter needs to be compared to the $Password parameter to make sure encryption is specified

## To-Dos:
This is a list of enhancements and improvements:

* The "Create-Archive" function should be able to figure out the archive format from the file name's extension
    * This creates a problem with the parameter-sets structure that I need to work through
* Invoke "Initialize-7Zip" as part of the module import
* Create a parameter to specify a path to save the log file for "Extract-Archive" and "Create-Archive" functions
* Check 7-Zip version in the Initialize-7Zip function (minimum 19.00 recommended, version 22.xx is being tested)

## Authors

I am the author. If you would like to contact me for any reason, you can reach me at [this email address](mailto:jross365github@gmail.com).

## Version History

* 1.0 - Initial public version.
    * Pretty Spiffy

## License

This project is licensed under the GNUv3 License - see the LICENSE.md file for details.