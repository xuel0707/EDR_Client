#ifndef _RADIX_H_
#define _RADIX_H_
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include "interface.h"


// define the alphabet size for english.
#define ALPHABET_SIZE 64

// linked String structure
typedef struct linked_str {
    // linked string node contains a char.
    char character;
    struct linked_str *next;

} linked_str;

// trie_node structure
typedef struct trie_node {
    struct trie_node *children[ALPHABET_SIZE];
    time_t honey_port_last_repor;
    // linked string to place the str inside the trie node.
    linked_str *linked_str;
    int st_mode:1,
        white_conf:1,
        black_conf:1,
        filter_conf:1,
        honey_port_conf:1,
        scan_port:1,
        honeyport_locked:1,
        portscan_locked:1,
        trust_conf:1;
    // boolean to check for leaf_nodes
    int is_leaf:1;
    void *data;
} trie_node;

enum module_t {
    CONF,
    DYNAMIC,
    MODULE_MAX
};

/* function signatures */

// create a trie Node.
trie_node *create_node(void);
// appends to the string[initial: end] and return a linked string.
linked_str *appendlinked_str(unsigned char *str, int inital, int end);
// break the linked string and create a node with the breaked string and returns intial.
trie_node *breaklinked_str(trie_node *previous_node, trie_node *node, linked_str *break_point);
// insert a str to the trie node.
trie_node *insert(trie_node *root, unsigned char *str);
// returns the pointer if found the str else returns NULL
trie_node *search_nodes(trie_node *root, unsigned char *str);
// convert a string in to charactors
int str_to_char(linked_str *begin, unsigned char *str, int initial);
// print suggestions for the prefix.
void print_suggetions(trie_node *suggested_node, char str[], int size);
// create a linked string with a given char.
linked_str *create_str(char c_char);
int destroy_tree(trie_node *root);

#endif
