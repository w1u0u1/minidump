.code

NtAdjustPrivilegesToken PROC
	mov rax, gs:[60h]                             ; Load PEB into RAX.
NtAdjustPrivilegesToken_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtAdjustPrivilegesToken_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtAdjustPrivilegesToken_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtAdjustPrivilegesToken_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtAdjustPrivilegesToken_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtAdjustPrivilegesToken_SystemCall_6_0_6002
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 003fh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0040h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtAdjustPrivilegesToken_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAdjustPrivilegesToken ENDP

NtReadVirtualMemory PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtReadVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtReadVirtualMemory_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtReadVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtReadVirtualMemory_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtReadVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtReadVirtualMemory_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtReadVirtualMemory_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtReadVirtualMemory_SystemCall_6_0_6002
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtReadVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtReadVirtualMemory_SystemCall_6_1_7601
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtReadVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtReadVirtualMemory_SystemCall_10_0_19042
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 003dh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 003eh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtReadVirtualMemory ENDP

NtOpenProcessToken PROC
	mov rax, gs:[60h]                        ; Load PEB into RAX.
NtOpenProcessToken_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtOpenProcessToken_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcessToken_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcessToken_Check_10_0_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtOpenProcessToken_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcessToken_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcessToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenProcessToken_SystemCall_6_3_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtOpenProcessToken_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtOpenProcessToken_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtOpenProcessToken_SystemCall_6_0_6002
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtOpenProcessToken_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenProcessToken_SystemCall_6_1_7601
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtOpenProcessToken_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenProcessToken_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenProcessToken_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenProcessToken_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenProcessToken_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenProcessToken_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenProcessToken_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenProcessToken_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenProcessToken_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenProcessToken_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtOpenProcessToken_SystemCall_10_0_19042
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 00beh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 00f7h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 00f3h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 00f3h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 00f9h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 00f9h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 010bh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 010eh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0114h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0117h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0119h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 011dh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 011fh
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0121h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0122h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0123h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0123h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 0128h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 0128h
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenProcessToken_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcessToken ENDP

NtOpenProcess PROC
	mov rax, gs:[60h]                   ; Load PEB into RAX.
NtOpenProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtOpenProcess_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtOpenProcess_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtOpenProcess_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtOpenProcess_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtOpenProcess_SystemCall_6_0_6002
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtOpenProcess_SystemCall_10_0_19042
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0024h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0025h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcess ENDP

NtClose PROC
	mov rax, gs:[60h]             ; Load PEB into RAX.
NtClose_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtClose_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtClose_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtClose_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtClose_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtClose_SystemCall_6_0_6002
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtClose_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtClose_SystemCall_10_0_19042
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 000dh
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 000eh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP

NtQuerySystemInformation PROC
	mov rax, gs:[60h]                              ; Load PEB into RAX.
NtQuerySystemInformation_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 5
	je  NtQuerySystemInformation_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtQuerySystemInformation_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQuerySystemInformation_Check_10_0_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 0
	je  NtQuerySystemInformation_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtQuerySystemInformation_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_0_XXXX:               ; Check build number for Windows Vista.
	cmp word ptr [rax+120h], 6000
	je  NtQuerySystemInformation_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtQuerySystemInformation_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtQuerySystemInformation_SystemCall_6_0_6002
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp word ptr [rax+120h], 7600
	je  NtQuerySystemInformation_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtQuerySystemInformation_SystemCall_6_1_7601
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtQuerySystemInformation_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtQuerySystemInformation_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtQuerySystemInformation_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtQuerySystemInformation_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtQuerySystemInformation_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtQuerySystemInformation_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtQuerySystemInformation_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtQuerySystemInformation_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtQuerySystemInformation_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtQuerySystemInformation_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtQuerySystemInformation_SystemCall_10_0_19042
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_SystemCall_5_X_XXXX:          ; Windows XP and Server 2003
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_0_6000:          ; Windows Vista SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_0_6001:          ; Windows Vista SP1 and Server 2008 SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_0_6002:          ; Windows Vista SP2 and Server 2008 SP2
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0034h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0035h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQuerySystemInformation_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQuerySystemInformation ENDP

end