## Simple Anti Dump
This module provides anti-dumping protection for .NET applications that prevents automatic dumping tools.

## How it Works
### PE Header Scrubbing
- Wipes the start of the DOS header and the `e_lfanew` pointer.
- Nulls the PE header in memory to break signature-based detection.
### Directory Table Scrambling
- Clears all 16 `IMAGE_DATA_DIRECTORY` entries (Export, Import, Resource, etc.).
- Makes directory-based tools unable to parse the file properly.
### Export & Debug Directory Cleanup
- Finds the Export and Debug directories.
- Zeros out their data and clears the RVA/Size entries.
### Import Table & IAT Corruption
- Replaces module and function names with fake/random data.
- Clears raw Import Table bytes to block import-based analysis.
### Base Relocation Table Scrambling
- Zeros out the Base Relocation block to prevent address fixups.
### Section Table Tampering
- Randomizes section names (like `.text`, `.rdata`) with arbitrary ASCII.
- Scrambles `VirtualAddress`, `SizeOfRawData`, and `PointerToRawData`.
- Corrupts `SectionAlignment` and `FileAlignment` values.
### Section Virtual Size Tampering
- Sets each section’s `VirtualSize` to zero.
- Breaks consistency between file layout and memory mapping.
### PE Header Removal
- Wipes the first 8 bytes at the module base.
- Destroys key DOS header values, essentially erasing the PE structure.

## Usage
Just Call `SimpleAntiDump.Protect()` at startup.

Example:

```vb.net
Sub Main()
    SimpleAntiDump.Protect()
    Application.Run(New MainForm())
End Sub
```

## Proof
Tools like MegaDumper and ExtremeDumper fail to complete the dump, lol.

![ExtremeDumper@1x](https://github.com/user-attachments/assets/56948b3b-b8a7-4767-a94d-4e2725728b94) ![MegaDumper](https://github.com/user-attachments/assets/8fc016f3-e231-4189-a8d0-d3374f065056)

## Important Notes
- This only prevents automatic dumping and remains vulnerable to manual dumping techniques.
- Use my advanced anti-dump version or tweak it yourself to improve protection.

## Advanced Version
Contact me on Telegram: [@ramaikn](https://t.me/ramaikn)
