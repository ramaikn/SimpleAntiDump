Imports System
Imports System.Reflection
Imports System.Runtime.InteropServices
Imports System.Security
Imports System.Security.Permissions
Imports System.Threading

Friend Module SimpleAntiDump

    <DllImport("kernel32.dll", SetLastError:=True)>
    Private Function VirtualProtect(
        lpAddress As IntPtr,
        dwSize As UIntPtr,
        flNewProtect As UInteger,
        ByRef lpflOldProtect As UInteger) As Boolean
    End Function

    Private Const PAGE_EXECUTE_READWRITE As UInteger = &H40UI

    Public Sub Protect()
        Try
            Dim modl As [Module] = GetType(AntiDump).Module
            Dim baseAddr As IntPtr = Marshal.GetHINSTANCE(modl)
            Dim dosHdrOffsetPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + &H3C)
            Dim e_lfanew As Integer = Marshal.ReadInt32(dosHdrOffsetPtr)
            Dim ntHeaderPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + e_lfanew)
            Dim sectionsCount As UShort = CType(Marshal.ReadInt16(New IntPtr(ntHeaderPtr.ToInt64() + &H6)), UShort)
            Dim optHeaderSize As UShort = CType(Marshal.ReadInt16(New IntPtr(ntHeaderPtr.ToInt64() + &HE)), UShort)
            Dim sectionTablePtr As IntPtr = New IntPtr(ntHeaderPtr.ToInt64() + &H18 + optHeaderSize)
            Dim oldProt As UInteger = 0
            For i As Integer = 0 To sectionsCount - 1
                Dim entryPtr As IntPtr = New IntPtr(sectionTablePtr.ToInt64() + (i * &H28))
                If Not VirtualProtect(entryPtr, CType(8UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                Else
                    Dim zeroBytes As Byte() = New Byte(7) {}
                    Marshal.Copy(zeroBytes, 0, entryPtr, 8)
                End If
            Next
            Dim importDirRva As Integer = Marshal.ReadInt32(New IntPtr(ntHeaderPtr.ToInt64() + &H80))
            If importDirRva <> 0 Then
                Dim importDirPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + importDirRva)
                WipeImportTable(importDirPtr, baseAddr, sectionsCount, sectionTablePtr, oldProt)
            End If
            Dim clrDirRva As Integer = Marshal.ReadInt32(New IntPtr(ntHeaderPtr.ToInt64() + &H88))
            If clrDirRva <> 0 Then
                Dim clrDirPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + clrDirRva)
                If VirtualProtect(clrDirPtr, CType(&H48UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                    For offset As Integer = 0 To &H3C Step 4
                        Marshal.WriteInt32(New IntPtr(clrDirPtr.ToInt64() + offset), 0)
                    Next
                    Dim metaDataRva As Integer = Marshal.ReadInt32(New IntPtr(clrDirPtr.ToInt64() + &H8))
                    If metaDataRva <> 0 Then
                        Dim metaDataPtr As IntPtr = New IntPtr(baseAddr.ToInt64() + metaDataRva)
                        If VirtualProtect(metaDataPtr, CType(4UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                            Marshal.WriteInt32(metaDataPtr, 0)
                        End If
                        Dim offsetBase As Integer = &H10 + Marshal.ReadInt32(New IntPtr(metaDataPtr.ToInt64() + &HC))
                        offsetBase = (offsetBase + 3) And Not 3
                        Dim streamsCount As UShort = CType(Marshal.ReadInt16(New IntPtr(metaDataPtr.ToInt64() + offsetBase)), UShort)
                        offsetBase += 2

                        For s As Integer = 0 To streamsCount - 1
                            If VirtualProtect(New IntPtr(metaDataPtr.ToInt64() + offsetBase), CType(8UI, UIntPtr), PAGE_EXECUTE_READWRITE, oldProt) Then
                                Marshal.WriteInt32(New IntPtr(metaDataPtr.ToInt64() + offsetBase), 0)
                                Marshal.WriteInt32(New IntPtr(metaDataPtr.ToInt64() + offsetBase + 4), 0)
                            End If
                            Dim nameIter As Integer = 0
                            Do
                                nameIter += 1
                            Loop While Marshal.ReadByte(New IntPtr(metaDataPtr.ToInt64() + offsetBase + 8 + nameIter - 1)) <> 0
                            offsetBase += 8 + ((nameIter + 1 + 3) And Not 3)
                        Next
                    End If
                End If
            End If


        Catch ex As Exception
        End Try
    End Sub

    Private Sub WipeImportTable(importDirPtr As IntPtr, baseAddr As IntPtr, sectCount As Integer, sectionTablePtr As IntPtr, oldProtect As UInteger)
        Try
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

End Module
