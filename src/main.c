#include <sys.H>
#include <types.H>

int main(int argc, char **argv) {
	i32 fd = file((const u8 *)argv[1]);
	u64 len = fsize(fd);
	u8 *ptr = fmap(fd, len, 0);

	munmap(ptr, len);
	close(fd);
	return 0;
}
