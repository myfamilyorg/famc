#include <famc/syn.H>
#include <libfam/test.H>

Test(syn1) {
	i32 i;
	SynTree tree1 = SYN_INIT;
	const char *test1 = "@abc::def; @def::ghi;";
	ASSERT(!syn_append(&tree1, test1, strlen(test1)), "append");

	println("root children = {}", tree1.root->num_children);
	for (i = 0; i < tree1.root->num_children; i++) {
		println("addr[{}]={x}", i, (u64)tree1.root->children[i]);
		/*println("child[{}].stype={}",
		 * tree1.root->children[i]->stype);*/
	}
}
