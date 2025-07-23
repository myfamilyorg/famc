#include <error.H>
#include <sys.H>
#include <types.H>

int main(int argc, char **argv) {
	i32 fd;
	u64 len;
	u8 *ptr;

	if (argc != 2 || !exists((const u8 *)argv[1])) {
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
