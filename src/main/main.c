#include <libfam/error.H>
#include <libfam/sys.H>
#include <libfam/types.H>

i32 main(i32 argc, char *argv[], char *envp[]);

#ifdef __aarch64__
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    ldr x0, [sp]\n"
    "    add x1, sp, #8\n"
    "    add x2, x0, #1\n"
    "    lsl x2, x2, #3\n"
    "    add x2, x1, x2\n"
    "    bl main\n"
    "    mov x8, #93\n"
    "    svc #0\n");
#endif /* __aarch64__ */
#ifdef __amd64__
__asm__(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    movq (%rsp), %rdi\n"
    "    lea 8(%rsp), %rsi\n"
    "    mov %rdi, %rcx\n"
    "    add $1, %rcx\n"
    "    shl $3, %rcx\n"
    "    lea (%rsi, %rcx), %rdx\n"
    "    mov %rsp, %rcx\n"
    "    and $-16, %rsp\n"
    "    call main\n"
    "    mov %rax, %rdi\n"
    "    mov $60, %rax\n"
    "    syscall\n");
#endif /* __amd64__ */

i32 main(i32 argc __attribute__((unused)), char **argv __attribute__((unused)),
	 char **envp __attribute__((unused))) {
	i32 fd = 0;
	u64 len = 0;
	u8 *ptr = NULL;

	if (argc != 2 || !(exists((const u8 *)argv[1]))) {
		err = EINVAL;
		return -1;
	}

	fd = file((const u8 *)argv[1]);
	len = fsize(fd);
	ptr = fmap(fd, len, 0);

	munmap(ptr, len);
	close(fd);

	return 0;
}
