/********************************************************************************
 * MIT License
 *
 * Copyright (c) 2025 Christopher Gilliard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *******************************************************************************/

#ifndef _SYN_H
#define _SYN_H

#include <famc/lexer.H>
#include <libfam/types.H>

typedef enum {
	SynNodeTypeRoot,
	SynNodeTypeLeaf,
	SynNodeTypeDeclaration,
	SynNodeTypeTrait,
	SynNodeTypeLoop,
	SynNodeTypeType,
	SynNodeTypeImport,
	SynNodeTypeMethod,
	SynNodeTypeIf,
} SynNodeType;

typedef struct {
	const u8 *data;
	u64 len;
} SynDataLen;

typedef struct SynNode {
	SynNodeType stype;
	struct SynNode *parent;
	struct SynNode **children;
	i32 num_children;
	u64 first_leaf;
	union {
		struct {
			const u8 *data;
			u64 len;
		} leaf;
		struct {
			u8 dummy;
		} declaration;
		struct {
			u8 dummy;
		} trait;
		struct {
			u8 dummy;
		} loop;
		struct {
			u8 dummy;
		} type;
		struct {
			u64 count;
			SynDataLen *module_list;
		} import;
		struct {
			u8 dummy;
		} method;
		struct {
			u8 dummy;
		} ifvalue;
	} node_data;
} SynNode;

typedef struct {
	SynNode *root;
	SynNode *cur;
} SynTree;

#define SYN_INIT {NULL, NULL}
i32 syn_append(SynTree *tree, const u8 *text, u64 length);
void syn_cleanup(SynTree *tree);

#endif /* _SYN_H */
