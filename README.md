## Simple Anti Dump

This module provides anti-dumping protection for .NET applications. It works by Removes PE section headers, overwrites import table entries with fake data and clears the CLR header and .NET metadata streams.

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
![MegaDumper](https://github.com/user-attachments/assets/1c7bb690-7925-4fec-a22b-06f98c969d23) ![MegaDumper](https://github.com/user-attachments/assets/8fc016f3-e231-4189-a8d0-d3374f065056)

## Important Notes

- This module does not prevent memory dumps entirely, but it complicates and disrupts most common .NET dumping tools.
- This is just a simple method and need further improvements.

## Need Advanced Version ?

I also offer a **paid and private version** of this anti-dump module with enhanced techniques.

Contact me on Telegram: [@ramaikn](https://t.me/ramaikn)
