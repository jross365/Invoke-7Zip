# Invoke-7Zip (**I7Z**)

Invoke-7Zip is a comprehensive Powershell wrapper module for 7-Zip.

## Description

This module extends Powershell functionality to 7-Zip, while providing script and user-friendly capabilities and features.

![Example of 7z Archive Creation](/.github/images/compressionexample.png)

### Capabilities

* **List** the contents of archives
* **Test** archives for integrity or password accuracy
* **Archive** files and folders as ZIP, GZIP, BZIP2, 7Z, XZ or TAR 
* **Extract** the contents of any archive supported by 7-Zip

### Features

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

## Getting Started

### Using Invoke-7Zip

* Using the module is simple:

```
Get-ExtendedAttributes
```

Alternatively, you can use the alias:

```
gea
```

## Parameters

**gea** contains many parameters to enhance its functionality and applicability.


### **-Path**
The directory or file you wish to retrieve extended attributes from.

This parameter is positional (*position 0*), and can be used without being named.

If unspecified, *-Path* uses the present working directory.


### **-Recurse**
In cases where *-Path* is a directory, *-Recurse* will enumerate all subfolders and files within the provided path.

If *-Path* specifies a filename, *-Recurse* is ignored.


### **-WriteProgress**
Displays a progress bar to support your mental health and welfare.

The progress bar reports which file it's enumerating attributes for, and displays the overall file progress.


### **-HelperFile**
Provides the function with the path of the Helper File to use.

Details about what a Helper File is and how to use it are written in the **Helper File** section below.


### **-Exclude**
Applies an exclusionary ("*where not match*") filter on subfolders and files. If *-Path* is a file, *-Exclude* is ignored.

To specify more than one filter, comma-separate the strings you'd like to exclude.

This example excludes all files and folders containing ".png" or ".ps1" anywhere in the filename:

```
$N = Get-ExtendedAttributes -Exclude .png,.ps1
```
**Note:** *-Exclude* does not respect asterisks. If there's a desire to use asterisks for filtering, ask and I'll write the feature in. (*Or do it yourself, it's open source!*)


### **-Include**
Applies an inclusionary ("*where match*") filter **for files only**. If *-Path* is a file, *-Include* is ignored.

As with *-Exclude*, you can comma-separate multiple strings you'd like to include. 

Also as with *-Exclude*, *-Include* does not respect asterisks.


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