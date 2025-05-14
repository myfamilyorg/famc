#include <exec.h>
#include <sys.h>
#include <types.h>

typedef struct {
	const char *data_in;
	size_t data_in_len;
	char *data_out;
	size_t data_out_len;
} FamcInfo;

int printf(const char *, ...);

int famc_expand(FamcInfo *info) {
	info->data_out = (char *)info->data_in;
	info->data_out_len = info->data_in_len;
	return 0;
}

int famc_compile(const char *cc, const char *file, const char *out_file) {
	int fd = openfd(file, OPEN_RDONLY);
	if (fd < 0) return -1;
	int64_t size = fsize(fd);
	const char *data = fview(fd, 0, 1 + (size / PAGE_SIZE));
	closefd(fd);
	if (data == NULL) return -1;

	char *args[] = {(char *)cc,	  "-x", "c", "-", "-c", "-o",
			(char *)out_file, NULL};

	ExecHandle handle;
	if (exec_pipe(cc, args, &handle) == -1) {
		return -1;
	}

	FamcInfo info = {.data_in = data, .data_in_len = size};
	int res = famc_expand(&info);
	int64_t n = handle_write(&handle, info.data_out, info.data_out_len);
	if (n == -1) {
		handle_close(&handle);
		return -1;
	}

	handle_close(&handle);
	int status = handle_wait_pid(&handle);

	unmap((char *)data, 1 + (size / PAGE_SIZE));

	return 0;
}

int famc(int argc, char **argv) {
	if (argc != 4) {
		printf("usage: famc <cc> <file> <out_file>\n");
		return -1;
	}
	famc_compile(argv[1], argv[2], argv[3]);
	return 0;
}
