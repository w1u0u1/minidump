.code

EXTERN SW2_GetSyscallNumber: PROC

NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0DD5C3A56h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClose ENDP

NtAdjustPrivilegesToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 065DB2916h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustPrivilegesToken ENDP

NtOpenProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 003AC0634h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcess ENDP

NtQuerySystemInformation PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00E530CC7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemInformation ENDP

NtReadVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 081D064BEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadVirtualMemory ENDP

NtOpenProcessToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01B9AF681h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcessToken ENDP

end