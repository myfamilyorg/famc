#include <famc/syn.H>
#include <libfam/test.H>

Test(syn1) {
	SynTree tree1 = SYN_INIT;
	const char *test1 = "@abc::def; @def::ghi;";
	ASSERT(!syn_append(&tree1, test1, strlen(test1)), "append");

	ASSERT_EQ(tree1.root->num_children, 2, "children=2");
	ASSERT_EQ(tree1.root->children[0]->stype, SynNodeTypeImport,
		  "SynNodeTypeImport1");
	ASSERT_EQ(tree1.root->children[1]->stype, SynNodeTypeImport,
		  "SynNodeTypeImport2");
	ASSERT_EQ(tree1.root->children[0]->node_data.import.count, 2, "c=2");
	ASSERT_EQ(tree1.root->children[0]->node_data.import.module_list[0].len,
		  3, "len=3");
	ASSERT(
	    !strcmpn(
		tree1.root->children[0]->node_data.import.module_list[0].data,
		"abc", 3),
	    "abc");

	ASSERT_EQ(tree1.root->children[0]->node_data.import.module_list[1].len,
		  3, "len=3");
	ASSERT(
	    !strcmpn(
		tree1.root->children[0]->node_data.import.module_list[1].data,
		"def", 3),
	    "def");

	ASSERT_EQ(tree1.root->children[1]->node_data.import.module_list[0].len,
		  3, "len=3");
	ASSERT(
	    !strcmpn(
		tree1.root->children[1]->node_data.import.module_list[0].data,
		"def", 3),
	    "def");

	ASSERT_EQ(tree1.root->children[1]->node_data.import.module_list[1].len,
		  3, "len=3");
	ASSERT(
	    !strcmpn(
		tree1.root->children[1]->node_data.import.module_list[1].data,
		"ghi", 3),
	    "ghi");

	syn_cleanup(&tree1);

	ASSERT_BYTES(0);
}

Test(syn2) {
	SynTree tree1 = SYN_INIT;
	const char *test1 = "a + 101";
	ASSERT(!syn_append(&tree1, test1, strlen(test1)), "append");
	ASSERT_EQ(tree1.root->num_children, 1, "1 child");
	ASSERT_EQ(tree1.root->children[0]->stype, SynNodeTypeBin, "Bin");
	ASSERT_EQ(tree1.root->children[0]->node_data.binary.op, BinaryOpCodeAdd,
		  "+");
	ASSERT_EQ(tree1.root->children[0]->num_children, 2, "num=2");
	ASSERT(
	    !strcmpn(tree1.root->children[0]->children[0]->node_data.leaf.data,
		     "a", 1),
	    "a");
	ASSERT(
	    !strcmpn(tree1.root->children[0]->children[1]->node_data.leaf.data,
		     "101", 3),
	    "101");

	syn_cleanup(&tree1);

	ASSERT_BYTES(0);
}
