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
If specified, file creation, modification and access information is preserved in compressed files.

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
If specified, file creation, modification and access information is preserved in compressed files.

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
If specified, file creation, modification and access information is preserved in compressed files.

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

#### **-ShowTechnicalInfo**
If specified, will display advanced information about the archive's contents.

This parameter is recommended for most queries, though it's not a default in 7-Zip.


## Help
Notes and comments regarding all things involving the word "help"

### Powershell Help
Every function in this module has a full-featured Comment-Based Help (CBH) header.

You can run the **Get-Help** command to see more information about parameters, aliases, examples, etc.

To view the full help manifest for Get-ExtendedAttributes, for example:
```
Get-Help Get-ExtendedAttributes -Full
```

### Reporting Bugs
With the size and complexity of this module, there are undoubtedly bugs and problems in the code. I try to fix things as soon as I identify a problem, but that's often easier said than done.

If you encounter a bug, please report it. Let me know exactly how you encountered it, including relevant conditions, parameter input and console output.

## Known Issues
* Strange/faulty behavior when working with files in UserProfile directories (caused by NTUSER.DAT)
* ~~Some file attribute values obtained from downloaded or non-Windows sources contain LRM (Left-to-Right Mark, Unicode 8206)~~ (06/06/2022)
    * ~~This is easy to sanitize, but the simplest way (ConvertTo-Csv => -replace [char][int](8206) | ConvertFrom-Csv) may add significant overhead~~
    * ~~May add a [switch]$PreserveLRM switch to disable LRM sanitization~~
* ~~Fix **gfo** "trailing-slash" bug~~ (06/06/2022)
    * ~~This doesn't effect the module functionality, but it's an easy bug to squash~~

## To-Dos:
This is a list of enhancements and improvements on my agenda:

* ~~Reduce **gea** "Helper File" parameters to a single parameter~~ (06/06/2022)
* Optimize/rewrite the supporting code behind the *-OmitEmptyFields* parameter
    * Figure out the fastest way to isolate unique, unused properties
* Write some "example scripts" to demo the module
* ~~Create a .psd1 for version tracking and Powershell/.NET CLR version enforcement~~ (06/06/2022)
* Apply Powershell 7.1 **foreach -parallel** functionality
    * This code is badly bottlenecked by single-threaded performance
    * Parallelizing it would add a tremendous performance enhancement


## Authors

I am the author. If you would like to contact me for any reason, you can reach me at [this email address](mailto:jross365github@gmail.com).

## Version History

* 1.0 - Initial public version.
    * Pretty Spiffy

## License

This project is licensed under the GNUv3 License - see the LICENSE.md file for details.