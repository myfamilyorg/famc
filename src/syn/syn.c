#include <famc/syn.H>
#include <libfam/alloc.H>
#include <libfam/error.H>
#include <libfam/format.H>

#define LEAF_DATA_EQUAL(child, text)                 \
	child->node_data.leaf.len == strlen(text) && \
	    !strcmpn(child->node_data.leaf.data, text, strlen(text))

STATIC i32 syn_compact_import(SynTree *tree) {
	void *tmp;
	u64 i, count, num;
	SynNode **children = tree->cur->children;
	SynNode *nnode = alloc(sizeof(SynNode));
	num = tree->cur->num_children;
	if (!nnode) return -1;
	nnode->stype = SynNodeTypeImport;
	count = (num - tree->cur->first_leaf - 1) / 2;
	nnode->node_data.import.count = count;
	nnode->node_data.import.module_list = alloc(sizeof(SynDataLen) * count);
	if (!nnode->node_data.import.module_list) {
		release(nnode);
		return -1;
	}
	for (i = 0; i < count; i++) {
		nnode->node_data.import.module_list[i].data =
		    children[tree->cur->first_leaf + 1 + i * 2]
			->node_data.leaf.data;
		nnode->node_data.import.module_list[i].len =
		    children[tree->cur->first_leaf + 1 + i * 2]
			->node_data.leaf.len;
	}

	for (i = tree->cur->first_leaf; i < num; i++) release(children[i]);
	tmp = resize(tree->cur->children,
		     (tree->cur->first_leaf + 1) * sizeof(SynNode *));
	if (!tmp) {
		release(nnode->node_data.import.module_list);
		release(nnode);
		return -1;
	}
	tree->cur->children = tmp;
	tree->cur->num_children = tree->cur->first_leaf + 1;
	tree->cur->children[tree->cur->first_leaf++] = nnode;
	return 0;
}

STATIC i32 syn_try_compact(SynTree *tree) {
	SynNode **children = tree->cur->children;
	u64 num = tree->cur->num_children;
	if (num - tree->cur->first_leaf > 1 &&
	    LEAF_DATA_EQUAL(children[num - 1], ";")) {
		if (tree->cur->first_leaf < num &&
		    LEAF_DATA_EQUAL(children[tree->cur->first_leaf], "@")) {
			if (syn_compact_import(tree) < 0) return -1;
		}
	}
	return 0;
}

STATIC void free_syn_node(SynNode *node) {
	i32 i;
	if (!node) return;
	for (i = 0; i < node->num_children; i++)
		free_syn_node(node->children[i]);
	if (node->stype == SynNodeTypeImport)
		release(node->node_data.import.module_list);
	release(node->children);
	release(node);
}

i32 syn_append(SynTree *tree, const u8 *text, u64 length) {
	Lexer lex;
	i32 token_ret;
	Token token;
	if (!tree || !text) {
		err = EINVAL;
		return -1;
	}
	if (!tree->root) {
		tree->cur = tree->root = alloc(sizeof(SynNode));
		if (!tree->root) return -1;
		tree->root->stype = SynNodeTypeRoot;
		tree->root->parent = NULL;
		tree->root->children = NULL;
		tree->root->num_children = 0;
		tree->root->first_leaf = 0;
	}
	if (lexer_init(&lex, text, length) < 0) return -1;
	while ((token_ret = lexer_next_token(&lex, &token)) != TOKEN_COMPLETE) {
		struct SynNode *nnode;
		u64 nchildren;
		void *tmp;
		if (token_ret == TOKEN_ERR) return -1;
		nnode = alloc(sizeof(struct SynNode));
		if (!nnode) return -1;
		nnode->stype = SynNodeTypeLeaf;
		nnode->node_data.leaf.data = token.value;
		nnode->node_data.leaf.len = token.len;
		nnode->children = NULL;
		nnode->num_children = 0;
		nnode->parent = tree->cur;
		nnode->first_leaf = 0;
		nchildren = tree->cur->num_children + 1;
		tmp = resize(tree->cur->children,
			     nchildren * sizeof(struct SynNode *));
		if (!tmp) {
			release(nnode);
			return -1;
		}
		tree->cur->children = tmp;
		tree->cur->children[tree->cur->num_children++] = nnode;
		if (syn_try_compact(tree) < 0) return -1;
	}

	return 0;
}

void syn_cleanup(SynTree *tree) {
	if (!tree || !tree->root) return;
	free_syn_node(tree->root);
	tree->cur = tree->root = NULL;
}
