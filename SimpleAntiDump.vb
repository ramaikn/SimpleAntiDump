Imports System.Reflection
Imports System.Runtime.InteropServices

Friend Module SimpleAntiDump

    <DllImport("kernel32.dll", SetLastError:=True)>
    Private Function VirtualProtect(
        lpAddress As IntPtr,
        dwSize As UIntPtr,
        flNewProtect As UInteger,
        ByRef lpflOldProtect As UInteger) As Boolean
    End Function

    <DllImport("kernel32.dll", CharSet:=CharSet.Ansi, SetLastError:=True)>
    Private Function LoadLibrary(lpLibFileName As String) As IntPtr
    End Function

    <DllImport("kernel32.dll", CharSet:=CharSet.Ansi, SetLastError:=True)>
    Private Function GetProcAddress(
        hModule As IntPtr,
        lpProcName As String
    ) As IntPtr
    End Function

    Private Const PAGE_EXECUTE_READWRITE As UInteger = &H40UI

    <StructLayout(LayoutKind.Sequential)>
    Private Structure EXCEPTION_POINTERS
        Public ExceptionRecord As IntPtr
        Public ContextRecord As IntPtr
    End Structure

    Public Sub Protect()
        Try
            Dim modl As [Module] = GetType(SimpleAntiDump).Module
            Dim baseAddr As IntPtr = Marshal.GetHINSTANCE(modl)
            Dim dosHdrOffsetPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + &H3C)
            Dim e_lfanew As Integer = Marshal.ReadInt32(dosHdrOffsetPtr)
            Dim ntHeaderPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + e_lfanew)
            Dim sectionsCount As UShort = CType(Marshal.ReadInt16(New IntPtr(ntHeaderPtr.ToInt64() + &H6)), UShort)
            Dim optHeaderSize As UShort = CType(Marshal.ReadInt16(New IntPtr(ntHeaderPtr.ToInt64() + &HE)), UShort)
            Dim sectionTablePtr As IntPtr = New IntPtr(ntHeaderPtr.ToInt64() + &H18 + optHeaderSize)
            Dim oldProt As UInteger = 0
            ScrubExportAndDebugDirs(baseAddr, ntHeaderPtr, oldProt) 'N
            ScrambleBaseRelocTable(baseAddr, ntHeaderPtr, oldProt) 'N
            WipeImportTable(baseAddr, ntHeaderPtr, sectionsCount, oldProt) 'N
            CorruptIAT(baseAddr, ntHeaderPtr, oldProt) 'N
            RandomizeSectionNames(sectionTablePtr, sectionsCount, oldProt) 'E
            TamperVirtualSize(sectionTablePtr, sectionsCount, oldProt) 'N
            WipeSectionTable(sectionTablePtr, sectionsCount, oldProt) 'E
            CorruptSectionAlignment(ntHeaderPtr, oldProt) 'E
            ScrambleDirectoryTable(baseAddr, ntHeaderPtr, oldProt) 'E
            WipePEHeader(baseAddr) 'E
        Catch ex As Exception

        End Try
    End Sub

    Private Sub WipePEHeader(baseAddr As IntPtr)

        Try
            Dim oldProt As UInteger = 0
            If VirtualProtect(baseAddr, CType(8, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                Marshal.WriteInt16(baseAddr, 0)
                Dim e_lfanew As Integer = Marshal.ReadInt32(IntPtr.Add(baseAddr, &H3C))
                If e_lfanew > 0 AndAlso e_lfanew < &H400 Then
                    Marshal.WriteInt32(IntPtr.Add(baseAddr, e_lfanew), 0)

                End If
                VirtualProtect(baseAddr, CType(8, UIntPtr), oldProt, oldProt)
            End If
        Catch
        End Try
    End Sub

    Private Sub CorruptIAT(baseAddr As IntPtr, ntHeaderPtr As IntPtr, oldProt As UInteger)
        Try

            Dim importDirRva As Integer = Marshal.ReadInt32(IntPtr.Add(ntHeaderPtr, &H80))
            Dim importDirSize As Integer = Marshal.ReadInt32(IntPtr.Add(ntHeaderPtr, &H84))
            If importDirRva = 0 OrElse importDirSize = 0 Then Return

            Dim importDirPtr As IntPtr = IntPtr.Add(baseAddr, importDirRva)
            If VirtualProtect(importDirPtr, CType(importDirSize, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                Dim zero(importDirSize - 1) As Byte
                Marshal.Copy(zero, 0, importDirPtr, importDirSize)
                VirtualProtect(importDirPtr, CType(importDirSize, UIntPtr), oldProt, oldProt)
            End If
        Catch
        End Try
    End Sub

    Private Sub TamperVirtualSize(sectionTablePtr As IntPtr, sectionsCount As Integer, oldProtect As UInteger)
        Try
            For i As Integer = 0 To sectionsCount - 1
                Dim entryPtr As IntPtr = New IntPtr(sectionTablePtr.ToInt64() + (i * &H28))
                Dim virtSizePtr As IntPtr = New IntPtr(entryPtr.ToInt64() + &H8)
                If VirtualProtect(virtSizePtr, CType(4UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                    Marshal.WriteInt32(virtSizePtr, 0)
                End If
            Next
        Catch
        End Try
    End Sub

    Private Sub WipeSectionTable(sectionTablePtr As IntPtr, sectionsCount As Integer, oldProt As UInteger)
        Try
            Dim rnd As New Random()
            For i As Integer = 0 To sectionsCount - 1
                Dim entryPtr As IntPtr = New IntPtr(sectionTablePtr.ToInt64() + (i * &H28))
                Dim namePtr As IntPtr = entryPtr
                If VirtualProtect(namePtr, CType(8UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                    Dim newName As Byte() = New Byte(7) {}
                    For j As Integer = 0 To 5
                        newName(j) = CByte(rnd.Next(65, 91))
                    Next
                    newName(6) = 0
                    newName(7) = 0
                    Marshal.Copy(newName, 0, namePtr, 8)
                    VirtualProtect(namePtr, CType(8UI, UIntPtr), oldProt, oldProt)
                End If
                Dim vaPtr As IntPtr = IntPtr.Add(entryPtr, 12)
                Dim rawPtr As IntPtr = IntPtr.Add(entryPtr, 20)
                Dim charPtr As IntPtr = IntPtr.Add(entryPtr, 36)
                If VirtualProtect(vaPtr, CType(4UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                    Marshal.WriteInt32(vaPtr, rnd.Next(&H1000, &H80000))
                    VirtualProtect(vaPtr, CType(4UI, UIntPtr), oldProt, oldProt)
                End If
                If VirtualProtect(rawPtr, CType(4UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                    Marshal.WriteInt32(rawPtr, rnd.Next(&H200, &H10000))
                    VirtualProtect(rawPtr, CType(4UI, UIntPtr), oldProt, oldProt)
                End If
                If VirtualProtect(charPtr, CType(4UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                    Marshal.WriteInt32(charPtr, rnd.Next())
                    VirtualProtect(charPtr, CType(4UI, UIntPtr), oldProt, oldProt)
                End If
            Next
        Catch
        End Try
    End Sub

    Private Sub WipeImportTable(baseAddr As IntPtr, ntHeaderPtr As IntPtr, sectCount As Integer, oldProtect As UInteger)
        Try
            Dim importDirRva As Integer = Marshal.ReadInt32(New IntPtr(ntHeaderPtr.ToInt64() + &H80))
            If importDirRva = 0 Then Return
            Dim importDirPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + importDirRva)

            Dim iterPtr As IntPtr = importDirPtr
            Do
                Dim oftRva As Integer = Marshal.ReadInt32(iterPtr)
                Dim nameRva As Integer = Marshal.ReadInt32(New IntPtr(iterPtr.ToInt64() + &HC))
                If oftRva = 0 And nameRva = 0 Then
                    Exit Do
                End If

                Dim modNameRva As Integer = nameRva
                Dim modNamePtr As IntPtr = New IntPtr(baseAddr.ToInt64() + modNameRva)
                If VirtualProtect(modNamePtr, CType(12UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                    Dim fakeName As Byte() = BitConverter.GetBytes(&H6C64746E)
                    Dim tail As Byte() = BitConverter.GetBytes(&H6C642E6C)
                    Dim lenByte As Byte() = BitConverter.GetBytes(CType(&H6C, UShort))
                    Dim newBytes As Byte() = New Byte(10) {}
                    Array.Copy(fakeName, 0, newBytes, 0, 4)
                    Array.Copy(tail, 0, newBytes, 4, 4)
                    Array.Copy(lenByte, 0, newBytes, 8, 2)
                    newBytes(10) = 0
                    For i As Integer = 0 To 10
                        Marshal.WriteByte(New IntPtr(modNamePtr.ToInt64() + i), newBytes(i))
                    Next
                End If

                Dim iatRva As Integer = Marshal.ReadInt32(New IntPtr(iterPtr.ToInt64() + &H10))
                If iatRva <> 0 Then
                    Dim iatPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + iatRva)
                    Dim funcNamePtr As IntPtr
                    If IntPtr.Size = 8 Then
                        Dim funcRva64 As Long = Marshal.ReadInt64(iatPtr)
                        funcNamePtr = New IntPtr(baseAddr.ToInt64() + (funcRva64 And &HFFFFFFFFL) + 2)
                    Else
                        Dim funcRva32 As Integer = Marshal.ReadInt32(iatPtr)
                        funcNamePtr = New IntPtr(baseAddr.ToInt64() + funcRva32 + 2)
                    End If
                    If VirtualProtect(funcNamePtr, CType(12UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                        Dim fake1 As Byte() = BitConverter.GetBytes(&H6F43744E)
                        Dim fake2 As Byte() = BitConverter.GetBytes(&H6E69746E)
                        Dim fakeLen As Byte() = BitConverter.GetBytes(CType(&H6575, UShort))
                        Dim data2 As Byte() = New Byte(10) {}
                        Array.Copy(fake1, 0, data2, 0, 4)
                        Array.Copy(fake2, 0, data2, 4, 4)
                        Array.Copy(fakeLen, 0, data2, 8, 2)
                        data2(10) = 0
                        For i As Integer = 0 To 10
                            Marshal.WriteByte(New IntPtr(funcNamePtr.ToInt64() + i), data2(i))
                        Next
                    End If
                End If

                iterPtr = New IntPtr(iterPtr.ToInt64() + &H14)
            Loop

        Catch
        End Try
    End Sub


    Private Sub ScrambleDirectoryTable(baseAddr As IntPtr, ntHeaderPtr As IntPtr, oldProtect As UInteger)
        Try
            Dim dataDirPtr As IntPtr = New IntPtr(ntHeaderPtr.ToInt64() + &H80)
            Dim totalSize As Integer = 16 * 8
            If VirtualProtect(dataDirPtr, CType(totalSize, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                For offset As Integer = 0 To totalSize - 1
                    Marshal.WriteByte(New IntPtr(dataDirPtr.ToInt64() + offset), 0)
                Next
            End If
        Catch
        End Try
    End Sub

    Private Sub ScrubExportAndDebugDirs(baseAddr As IntPtr, ntHeaderPtr As IntPtr, oldProtect As UInteger)
        Try
            Dim exportDirOffset As IntPtr = IntPtr.Add(ntHeaderPtr, &H78)
            Dim exportRva As Integer = Marshal.ReadInt32(exportDirOffset)
            Dim exportSize As Integer = Marshal.ReadInt32(IntPtr.Add(ntHeaderPtr, &H7C))

            If exportRva > 0 AndAlso exportSize > 0 Then
                Dim exportPtr As IntPtr = IntPtr.Add(baseAddr, exportRva)
                Dim tempProtect As UInteger = 0

                If VirtualProtect(exportPtr, CType(exportSize, UIntPtr), PAGE_EXECUTE_READWRITE, tempProtect) Then
                    Dim zero(exportSize - 1) As Byte
                    Marshal.Copy(zero, 0, exportPtr, exportSize)
                    VirtualProtect(exportPtr, CType(exportSize, UIntPtr), tempProtect, tempProtect)
                End If

                Marshal.WriteInt32(exportDirOffset, 0)
                Marshal.WriteInt32(IntPtr.Add(ntHeaderPtr, &H7C), 0)
            End If

            Dim debugDirOffset As IntPtr = IntPtr.Add(ntHeaderPtr, &HA8)
            Dim debugRva As Integer = Marshal.ReadInt32(debugDirOffset)
            Dim debugSize As Integer = Marshal.ReadInt32(IntPtr.Add(ntHeaderPtr, &HAC))

            If debugRva > 0 AndAlso debugSize > 0 Then
                Dim debugPtr As IntPtr = IntPtr.Add(baseAddr, debugRva)
                Dim tempProtect As UInteger = 0

                If VirtualProtect(debugPtr, CType(debugSize, UIntPtr), PAGE_EXECUTE_READWRITE, tempProtect) Then
                    Dim zero(debugSize - 1) As Byte
                    Marshal.Copy(zero, 0, debugPtr, debugSize)
                    VirtualProtect(debugPtr, CType(debugSize, UIntPtr), tempProtect, tempProtect)
                End If

                Marshal.WriteInt32(debugDirOffset, 0)
                Marshal.WriteInt32(IntPtr.Add(ntHeaderPtr, &HAC), 0)
            End If

        Catch ex As Exception
        End Try
    End Sub

    Private Sub RandomizeSectionNames(sectionTablePtr As IntPtr, sectionsCount As Integer, oldProtect As UInteger)
        Try
            Dim rnd As New Random()
            For i As Integer = 0 To sectionsCount - 1
                Dim entryPtr As IntPtr = New IntPtr(sectionTablePtr.ToInt64() + (i * &H28))
                Dim namePtr As IntPtr = entryPtr
                If VirtualProtect(namePtr, CType(8UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                    Dim newName As Byte() = New Byte(7) {}
                    For j As Integer = 0 To 5
                        Dim c As Char = ChrW(AscW("A"c) + rnd.Next(0, 26))
                        newName(j) = CByte(AscW(c))
                    Next
                    newName(6) = 0
                    newName(7) = 0
                    For j As Integer = 0 To 7
                        Marshal.WriteByte(New IntPtr(namePtr.ToInt64() + j), newName(j))
                    Next
                End If
            Next
        Catch
        End Try
    End Sub

    Private Sub ScrambleBaseRelocTable(baseAddr As IntPtr, ntHeaderPtr As IntPtr, oldProtect As UInteger)
        Try
            Dim relocDirRva As Integer = Marshal.ReadInt32(New IntPtr(ntHeaderPtr.ToInt64() + &HA0))
            Dim relocDirSize As Integer = Marshal.ReadInt32(New IntPtr(ntHeaderPtr.ToInt64() + &HA4))
            If relocDirRva = 0 OrElse relocDirSize = 0 Then Return
            Dim relocPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + relocDirRva)
            If VirtualProtect(relocPtr, CType(relocDirSize, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                Dim zeroBuf(relocDirSize - 1) As Byte
                Marshal.Copy(zeroBuf, 0, relocPtr, relocDirSize)
            End If
        Catch
        End Try
    End Sub

    Private Sub CorruptSectionAlignment(ntHeaderPtr As IntPtr, oldProtect As UInteger)
        Try

            Dim sectionAlignPtr As IntPtr = IntPtr.Add(ntHeaderPtr, &H38)
            Dim fileAlignPtr As IntPtr = IntPtr.Add(ntHeaderPtr, &H3C)
            If VirtualProtect(sectionAlignPtr, CType(8UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProtect) Then
                Marshal.WriteInt32(sectionAlignPtr, &H1)
                Marshal.WriteInt32(fileAlignPtr, &H1)
            End If
        Catch
        End Try
    End Sub

End Module

