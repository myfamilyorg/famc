#include <famc/syn.H>
#include <libfam/error.H>

i32 syn_append(SynTree *tree, const u8 *text, u64 length) {
	if (!tree || !text) {
		err = EINVAL;
		return -1;
	}
	if (lexer_init(&tree->lex, text, length) < 0) return -1;

	return 0;
}
void syn_cleanup(SynTree *tree) {
	if (!tree) {
	}
}

