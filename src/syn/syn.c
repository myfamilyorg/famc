#include <famc/syn.H>
#include <libfam/alloc.H>
#include <libfam/error.H>
#include <libfam/format.H>

#define LEAF_DATA_EQUAL(child, text)                 \
	child->node_data.leaf.len == strlen(text) && \
	    !strcmpn(child->node_data.leaf.data, text, strlen(text))

STATIC i32 syn_try_compact(SynTree *tree) {
	u64 i, count;
	SynNode **children = tree->cur->children;
	u64 num = tree->cur->num_children;
	u64 first_leaf = 0;
	if (num > 1) {
		if (LEAF_DATA_EQUAL(children[num - 1], ";")) {
			println("semi!!!!");
			for (i = 0; i < num; i++) {
				if (children[i]->stype == SynNodeTypeLeaf)
					break;
				first_leaf++;
			}
			println("first_leaf={}", first_leaf);
			if (LEAF_DATA_EQUAL(children[first_leaf], "@")) {
				if ((num - first_leaf) % 2 == 1) {
					SynNode *nnode = alloc(sizeof(SynNode));
					if (!nnode) return -1;
					println("nnode={x}", (u64)nnode);
					nnode->stype = SynNodeTypeImport;
					count = (num - first_leaf) / 2;
					nnode->node_data.import.count = count;
					nnode->node_data.import.module_list =
					    alloc(sizeof(SynDataLen) * count);
					if (!nnode->node_data.import
						 .module_list)
						return -1;
					println("insert count = {}", count);
					for (i = 0; i < count; i++) {
						nnode->node_data.import
						    .module_list[i]
						    .data =
						    children[first_leaf + 1 +
							     i * 2]
							->node_data.leaf.data;
						nnode->node_data.import
						    .module_list[i]
						    .len =
						    children[first_leaf + 1 +
							     i * 2]
							->node_data.leaf.len;
					}

					for (i = first_leaf; i < num; i++) {
						release(tree->cur->children[i]);
					}

					tree->cur->num_children =
					    1 + first_leaf;
					tree->cur->children[first_leaf] = nnode;
					println(
					    "nnode->stype={},tree->stype={}",
					    nnode->stype,
					    tree->cur->children[first_leaf]
						->stype);

					println("import!!!!");
				}
			}
		}
	}
	return 0;
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
	}

	if (lexer_init(&lex, text, length) < 0) return -1;

	while ((token_ret = lexer_next_token(&lex, &token)) != TOKEN_COMPLETE) {
		struct SynNode *nnode;
		u64 nchildren;
		void *tmp;
		if (token_ret == TOKEN_ERR) return -1;

		nnode = alloc(sizeof(SynNode));
		if (!nnode) return -1;
		nnode->stype = SynNodeTypeLeaf;
		nnode->node_data.leaf.data = token.value;
		nnode->node_data.leaf.len = token.len;
		nchildren = tree->cur->num_children + 1;
		tmp = resize(tree->cur->children,
			     nchildren * sizeof(struct SynNode *));
		if (!tmp) {
			release(nnode);
			return -1;
		}
		tree->cur->children = tmp;
		tree->cur->children[tree->cur->num_children] = nnode;
		tree->cur->num_children++;

		{
			u8 buf[128];
			memcpy(buf, token.value, token.len);
			buf[token.len] = 0;
			println("token={},num_children={}", buf,
				tree->cur->num_children);
		}

		syn_try_compact(tree);
	}

	return 0;
}

void syn_cleanup(SynTree *tree) {
	if (!tree) {
	}
}

