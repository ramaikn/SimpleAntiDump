## Simple Anti Dump
This module provides anti-dumping protection for .NET applications that prevents automatic dumping tools.

## How it Works

- ZeroDataDirectoryTable : Zeros out all entries in the Data Directory Table, removing RVA and size information for all PE structures (import, export, resource, etc).
- ZeroExportAndDebugDirectories : Erases the Export and Debug directories and their entries in the PE header, removing export and debug information from the binary.
- ZeroBaseRelocationTable : Overwrites the Base Relocation Table with zeros, preventing relocation information from being used by dumpers or loaders.
- CorruptSectionAlignment : Sets SectionAlignment and FileAlignment in the Optional Header to 1, making the PE file invalid for loaders.
- RandomizeSectionNames : Randomizes the names of all sections in the Section Table, making section identification and analysis more difficult.
- TamperVirtualSize : Sets the VirtualSize field of each section to zero, invalidating the in-memory size information for each section.
- CorruptImportNames : Overwrites module and function names in the Import Table with fake data, corrupting external dependency information.
- ZeroImportDirectory : Zeros out the Import Directory (IMAGE_IMPORT_DESCRIPTOR array), removing all import descriptors from the PE.
- RandomizeSectionTableFields : Randomizes key fields in the Section Table (name, virtual address, PointerToRawData, characteristics), corrupting the section structure.
- ZeroPESignatures : Zeros out the DOS and NT header signatures ("MZ" and "PE\0\0"), making the binary unrecognizable as a valid PE file.

## Usage
Just Call `SimpleAntiDump.Protect()` at startup.

Example:

```vb.net
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        SimpleAntiDump.Protect()
    End Sub
```

## Proof
Tools like MegaDumper and ExtremeDumper fail to complete the dump, lol.

![ExtremeDumper@1x](https://github.com/user-attachments/assets/56948b3b-b8a7-4767-a94d-4e2725728b94) ![MegaDumper](https://github.com/user-attachments/assets/8fc016f3-e231-4189-a8d0-d3374f065056)

## Important Notes
- This only prevents automatic dumping and remains vulnerable to manual dumping techniques.
- My advanced anti-dump version, will prevent most common manual dumping method.

## Advanced Version
Contact me on Telegram: [@ramaikn](https://t.me/ramaikn)
