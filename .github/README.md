# Invoke-7Zip (**I7Z**)

Invoke-7Zip is a Powershell wrapper module for 7-Zip.

## Description

This module provides Powershell functionality for 7-Zip's essential features:

* **List** the contents of archives (Standard and "Show Technical Information" views)
* **Test** archives for integrity and password accuracy
* **Archive** files and folders as ZIP, GZIP, BZIP2, 7Z, XZ or TAR 
* **Extract** the contents of any archive supported by 7-Zip

![Example of 7z Archive Creation](/.github/images/compressionexample.png)


## Getting Started

### Dependencies

**Get-ExtendedAttributes** has the following dependencies:
* Microsoft Windows OS (Windows 7 or greater, Windows Server 2008 or greater)
* Windows Powershell (5.1+ recommended)


### Installing
Save the *Get-ExtendedAttributes* folder to any one of these three folders:

```
C:\Users\<username>\Documents\WindowsPowerShell\Modules
C:\Program Files\WindowsPowerShell\Modules        
C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```


### Importing the Module

Import the module using the following command:

```
Import-Module Get-ExtendedAttributes
```

**Note:** The module exports the path of a "Helper File" as variable $HelperFile. This is used to *greatly* improve the speed and efficiency. Details on how to use the helper file are explained in the **Helper File** below.


### Using Get-ExtendedAttributes

* Running the function is simple:

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


### **-OmitEmptyFields**
Instructs the function to remove all columns in the resultant data which do not contain any values. *-Clean* is an alias of *-OmitEmptyFields*.

For example, a set of values that looks like this:

| Name  | Address | Street | Phone Number   | Email Address | 
| ----- |-------- | ------ | -------------- | ------------- |
| John  | 123 st  |        |                |               |
| Jake  |         |        |                | no@ip.org     |
|       | 3rd ave.|        |                | yep@nope.com  |

Would be reduced to these fields:

| Name  | Address | Email Address | 
| ----- |-------- | ------------- |
| John  | 123 st  |               |
| Jake  |         | no@ip.org     |
|       | 3rd ave.| yep@nope.com  |


This operation can take a lot of time, depending on how many files and specified attributes reside in the dataset.

As with attribute lookups, the Helper File also reduces the number of possible empty fields. For this reason, it is *strongly* recommended that a Helper File be used when using *-OmitEmptyFields*.


### **-ReportAccessErrors**
Reports all "Access Denied" errors to the console after the resultant data has been processed. Error reporting does not impact enumeration against files that were accessible.

### **-ErrorOutFile**
Instructs the function to send errors to a designated text file instead of to the console.

### **-PreserveLRM**
Skips filtering/replacing Unicode character 8206 (Left-Right Mark) from the dataset.

This parameter is recommended when **not** anticipating media files and executables, and will slightly improve run-time.

If media files or executables *are** anticipated, **don't** specify this parameter to ensure the resultant data is plainly readable and exportable.


## The Helper File

**gea** is very quick when run without additional parameters for one or a small number of files.

In cases where there are a *large* number of files, the time it takes to query 500 attributes can cause **gea** to take a *very* long time to complete.

Thankfully, there's a clever solution to this problem.


### Understanding The Helper File

The Helper File is simply a JSON file called *exthelper.json*. It contains Keys (file extensions) and Values (applicable attributes for each file extension).

**gea** uses this file to limit the attribute retrievals to *only* attributes that are used by specific file types.

Instead of querying 500 attributes, when using the Helper File it will only query 30-40 (depending on the file type). This improves **gea**'s performance substantially.


### Where To Get It

I have included a Helper File with the module that contains 315 extensions. This was generated from files on my systems and storage, and works perfectly (for me).


### How To Use It

* If present when importing the module, the path to the Helper File is automatically assigned to the variable *$HelperFile*:

![Import-Module](/.github/images/import-module.png)

* When running **gea**, use the following parameters to use the Helper File:

```
Get-ExtendedAttributes -HelperFile $HelperFile
```

### Does It *Actually* Help?

That's a fair question. Here's a test against 410 files:

![HelperFile Speed](/.github/images/helperspeed.png)


| Without Helper| With Helper   |
| ------------- | ------------- |
| 83 seconds    | 10 seconds    |
| 4.94 files/sec| 41 files/sec  |

That's a difference of **8 times** faster when using the Helper File!


### How To Make It

If you have a unique or specific set of file types that aren't included in the provided set, I have included a function to create your own Helper File (**New-AttrsHelperFile**)

Details on how to use this tool are outlined in the **Other Functions** section below.

# Other Functions
If **gea** is the star of the show, then there's also a supporting cast. Without them, the show wouldn't be possible.

This section covers the other functions included and available for use in this Powershell module.


## **New-AttrsHelperFile**
Analyzes CSV files with contents created by **gea** to generate a new Helper File.

You may want to create a new helper file if your use-case for this module applies to files whose extensions aren't included in the provided *extHelper.json* file.

![New-AttrsHelperFile](/.github/images/new-attrshelperfile.png)

### Considerations
These are some notes and recommendations for using **New-AttrsHelperFile**:

* When running **gea** to generate the initial data, it's best to specify *-OmitEmptyFields* up-front (alternatively, *-Clean*). This will save a lot of time when re-analyzing the data.
* When saving the **gea** output as a CSV, make sure you specify the **Export-Csv** cmdlet's *-NoTypeInformation* parameter.
* You don't need a huge dataset of files in each CSV to generate a perfect *exthelper.json* file. 
    * Consider hand-picking a small quantity of each file type that you think will have the desired properties.
* You can use the existing *exthelper.json* file when running **gea** to generate a new Helper File.
    * Eligible extension-attributes will transfer over after the new analysis is complete, saving you time on "known attributes".
    * However, if any attributes were missed, those missed attributes will also be missing from the new file.
* Expect the function's run-time to take **1-2 minutes per 1MB** of CSVs, depending on your CPU's single-core performance.


### Using New-AttrsHelperFile

* Suppose you've created a folder of representative files for the purpose of generating a new exthelper file, and a location for your resultant CSV file:
```
D:\RepFiles
D:\AttrsFiles
```

* Import the **Get-ExtendedAttributes** module:
```
Import-Module Get-ExtendedAttributes
```

* Use **gea** to analyze your files:
```
$AttrData = gea -Path D:\RepFiles -Recurse -Write-Progress -Clean
```

* Save the file attribute data as a CSV:
```
$AttrData | Export-Csv D:\AttrsFiles\RepFiles.csv -NoTypeInformation
```

* Run **New-AttrsHelperFile** to generate the new *exthelper.json*
```
New-AttrsHelperFile -Folder D:\AttrsFiles -SaveAs D:\AttrsFiles\exthelper.json -WriteProgress
```

With the above parameters-set, **New-AttrsHelperFile** will display a progress bar. There is no console output after completion.


### Parameters
**New-AttrsHelperFile** has a small number of parameters:

#### **-Folder**
The path of the directory containing relevant CSV files. There is no default, and this parameter should be explicitly defined.

#### **-SaveAs**
The full file path to save the resultant .json as. There is no default, and this parameter should also be explicitly defined.

#### **-WriteProgress**
To support your mental health and welfare.

Reports on the overall progress, the extension it's analyzing, the extension progress, and the file whose attributes its analyzing.


## **Reinventing the Wheel:**
### Why **gfo** and **gfi** Were Created
When considering how to enumerate files and folders, I started with these three requirements.

1. Faster enumeration and simple/flat output of files and folders
2. Avoid enumerating attributes for the sake of efficiency
3.  Maintain all code within native Powershell/.NET Framework 

The first two requirements rule out *Get-ChildItem*, because **gci** is notoriously slow and enumerates attributes, which I was explicitly trying to avoid. The last requirement rules out the cmd.exe "*dir.exe*" command, which is very fast but would require a wrapper function.

This left no "*off-the-shelf*" options (that I'm aware of), and I didn't want to borrow someone else's code. So I wrote **Get-Folders** and **Get-Files**.

## **Get-Folders** (gfo)
Enumerates directories in a provided path, and can do so recursively.

### Using Get-Folders

* Running the function is simple:

```
Get-Folders
```

Alternatively, you can use the alias:

```
gfo
```

### Parameters
**gfo** contains a few parameters to enhance its functionality.

#### **-Directory**
The path of the directory you wish to enumerate directories within.

If *-Directory* is not specified, **gfo** uses the present working directory.

#### **-SuppressErrors**
Suppresses access errors without any output. This parameter can be useful when working with directory structures containing folders you know you don't have access to.

#### **-Recurse**
Instructs the function to recursively enumerate all subdirectories within the specified path.

#### **-NoSort**
Instructs the function to bypass alphabetical/hierarchical sorting of the enumerated directories, and returns the directories in the order they were discovered.

#### **-IgnoreExclusions**
By default, **gfo** filters out directory paths matching the following strings:

* "filehistory"
* "windows"
* "recycle"
* "@"

Specifying *-IgnoreExclusions* will include directory paths with the strings listed above.

#### **-IncludeRoot**
Adds the "root" (*-Directory*) directory to the returned list of discovered directories/subdirectories.


## **Get-Files** (gfi)
Enumerates files in a specified path.

**Note: Get-Files** does not operate recursively.

### Using Get-Files

* Running this function is also very simple:

```
Get-Files
```

Alternatively, you can use the alias:

```
gfi
```

### Parameters
**gfi** contains a handful of parameters to enhance its functionality.

#### **-Directory**
The path of the directory you wish to enumerate the files within.

If not specified, **gfi** uses the present working directory.

#### **-ExcludeFullPath**
By default, **gfi** provides the full directory path of every file it discovers. When specifying **-ExcludeFullPath**, only the file names are returned.

#### **-Filter**
Applies an inclusional ("matches") filter to the output. *-Filter* is a positional parameter (last position), and doesn't require being named.

**Note:** *-Filter* only allows a single filter to be specified. If you'd like the multi-filter functionality (like **gea** provides), let me know and I'll include it.

Here's an example of how to only show files of type ".txt" using the *-Filter* parameter:

```
gfi -Filter *.txt
```

## **Get-FileExtension**
Returns the file extension of a given file. 


### Using Get-FileExtension

* Running this function requires specifying the filename:

```
Get-FileExtension -FilePath D:\somefile.txt

.txt
```

However, the *actual* path (or the file's existence) doesn't matter. You can pass the function nonsense, and it will return the perceived file extension:
```
Get-FileExtension asdfq234r3e2f.sql

.sql
```
### Parameters
**Get-FileExtension** has a single parameter:

#### **-FilePath**
The name or path of the file.



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