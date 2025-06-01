## Simple Anti Dump
This module provides anti-dumping protection for .NET applications that prevents automatic dumping tools. It works by Removes PE section headers, overwrites import table entries with fake data and clear the CLR header and .NET metadata streams.

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
