#include "radix.h"
#if 0
static const char *slb_module_name[MODULE_MAX] = {
    "sniper_conf_cache",
    "sniper_dynamic_cache"
};
#endif
// node count to get the memory used.
static int node_count = 0;
// link string count to get the memory.
static int link_string_node_count = 0;

struct kmem_cache *slb_linked_cachep[MODULE_MAX];
struct kmem_cache *slb_node_cachep[MODULE_MAX];
// static int linked_num[MODULE_MAX];
// static int node_num[MODULE_MAX];

void slab_linked_ctor(void *cachep){
    // ++linked_num;
}
void slab_node_ctor(void *cachep){
    // ++node_num;
}
#if 0
int init_trie_slbbuf(enum module_t type_id)
{
    slb_linked_cachep[type_id] = kmem_cache_create(slb_module_name[type_id], sizeof(linked_str), 0, SLAB_HWCACHE_ALIGN, slab_linked_ctor);
    if(!slb_linked_cachep[type_id]) {
        myprintk("create linked cache fail\n");
        return -1;
    }

    slb_node_cachep[type_id] = kmem_cache_create(slb_module_name[type_id], sizeof(trie_node), 0, SLAB_HWCACHE_ALIGN, slab_node_ctor);
    if(!slb_node_cachep[type_id]) {
        kmem_cache_free(slb_linked_cachep[type_id], NULL);
        myprintk("create node cache fail\n");
        return -1;
    }

    return 0;
}
#endif

// TODO 从树中删除某个字符串,从根到叶子节点
int del_node(trie_node *root, unsigned char *str)
{
    trie_node *current_node = NULL;
    linked_str *current_letter = NULL;
    int ret = 0;
    int i = 0;
    int lastIndex = 0;
    int charIndex = 0;

    if (root == NULL || str == NULL) { // the trie is empty.
        // printl("EEEEEEEE %s\n", str);
        return -1;
    }

    lastIndex = strlen(str);
    current_node = root;
    current_letter = current_node->linked_str;

    while (i < lastIndex) {
        // get the index from the char Index.
        charIndex = str[i] - '0';
        // if current letter is null.
        if (current_letter == NULL) {
            if (current_node->children[charIndex] != NULL) {
                // printk("IIIIII %d %d\n", charIndex, lastIndex);
                char *tmp = &str[i];
                ret = del_node(current_node->children[charIndex], tmp);
                // printf("ret:%d, bbbb %d, %d\n", ret, i, lastIndex);
                if (ret == 1) { /* 最后的叶子节点删除,所以删除指向最后叶子节点的上层children[charIndex] */
                    if (current_node->children[charIndex]) {
                        sniper_kfree(current_node->children[charIndex], sizeof(trie_node), KMALLOC_CREATENODE);
                        current_node->children[charIndex] = NULL;
                        node_count --;
                    }
                } else if (ret == 3) { /* 删除的非叶子节点,检查当前节点中是否有children,没有则删除当前节点 */
                    for (i = 0; i < ALPHABET_SIZE; ++i) {
                        if (current_node->children[i] != NULL) {
                            break;
                        }
                    }
                    if (i == ALPHABET_SIZE) { /* 空的children */
                        current_letter = current_node->linked_str;
                        while(current_letter) {
                            linked_str *tmp = current_letter;
                            current_letter = current_letter->next;
                            if (tmp) {
                                // printk("m===%c\n", tmp->character);
                                sniper_kfree(tmp, sizeof(linked_str), KMALLOC_CREATESTR);
                                link_string_node_count--;
                            }
                        }
                        if (current_node) {
                            sniper_kfree(current_node, sizeof(trie_node), KMALLOC_CREATENODE);
                            node_count --;
                        }
                        return 2;
                    }
                } else {
                    // printk("ssss  %d\n", ret);
                    return ret;
                }
            }
        } else {
            if (current_letter->character != str[i]) {
                // printk("rrrrrr\n");
                return -1;
            } else {
                //printf("+%d:%d+++%c+++%c\n", i, lastIndex, current_letter->character, str[i]);
                if (lastIndex == (i+1)) { /* 最后一个节点 */
                    current_letter = current_node->linked_str;
                    while(current_letter) {
                        linked_str *tmp = current_letter;
                        if (tmp) {
                            // printk("l===%c\n", tmp->character);
                            sniper_kfree(tmp, sizeof(linked_str), KMALLOC_CREATESTR);
                            link_string_node_count--;
                        }
                        current_letter = current_letter->next;
                    }
                    return 1; /* 返回1表示最后一个叶子节点删除 */
                }
            }
            // go to the next letter.
            current_letter = current_letter->next;
        }
        i++;
    }

    return 3;
}



int destroy_tree(trie_node *root)
{
    trie_node *current_node = NULL;
    linked_str *current_letter = NULL;
    int ret = 0;
    int i = 0;

    if (root == NULL) { // the trie is empty.
        return 0;
    }

    current_node = root;

    for (i = 0; i < ALPHABET_SIZE; ++i) {
        if (current_node->children[i] != NULL) {
            current_letter = current_node->children[i]->linked_str;
            while(current_letter) {
                //printk("=%d====%s====\n", i, current_letter);
                linked_str *tmp = current_letter;
                current_letter = current_letter->next;
                if (tmp) {
                    // kmem_cache_free(slb_linked_cachep, current_letter);
                    // -- linked_num;
                    sniper_kfree(tmp, sizeof(linked_str), KMALLOC_CREATESTR);
                    link_string_node_count--;
                }
                if (current_node->data) {
                    sniper_kfree(current_node->data, sizeof(trie_node), KMALLOC_CREATENODE);
                }
            }
            destroy_tree(current_node->children[i]);
        }
    }
    if (current_node) {
        // kmem_cache_free(slb_node_cachep, current_node);
        // -- node_num;
        sniper_kfree(current_node, sizeof(trie_node), KMALLOC_CREATENODE);
        -- node_count;
    }

    return ret;
}

trie_node *create_node(void)
{
    int i;
    // allocate space for new trie node.
    // struct slab_test *newtrie_node = (trie_node *)kmem_cache_alloc(slb_node_cachep, GFP_ATOMIC);
    trie_node *newtrie_node = (trie_node *)sniper_kmalloc(sizeof(trie_node), GFP_ATOMIC, KMALLOC_CREATENODE);
    // initialize the linked string with NULL
    newtrie_node->linked_str = NULL;
    // make it as not a leaf
    newtrie_node->is_leaf = 0;
    newtrie_node->data = NULL;

    for (i = 0; i < ALPHABET_SIZE; ++i) {
        // make all the chiledrens null.
        newtrie_node->children[i] = NULL;
    }
    ++node_count;

    return newtrie_node;
}

linked_str *create_str(char c_char)
{
    // allocate space for a new string dynamically.
    // linked_str *new_str = (linked_str *)kmem_cache_alloc(slb_linked_cachep, GFP_ATOMIC);
    linked_str *new_str = (linked_str *)sniper_kmalloc(sizeof(linked_str), GFP_ATOMIC, KMALLOC_CREATESTR);
    // put the char into its character
    new_str->character = c_char;
    // make the next pointer null.
    new_str->next = NULL;
    link_string_node_count++;
    // return the new string.
    return new_str;
}

linked_str *appendlinked_str(unsigned char *str, int inital, int end)
{
    int i = 0;
    // create a pointers to linked strings.
    linked_str *current_str = create_str(str[inital]);
    linked_str *new_str = NULL;
    linked_str *string = current_str;

    // go from initial position to end position
    for (i = inital + 1; i < end; ++i) {
        // crate a new string with char index i or str
        new_str = create_str(str[i]);
        // make the next pointer point to new string.
        current_str->next = new_str;
        // go through the string
        current_str = current_str->next;
    }
    // make the last pointer at the end.
    current_str = NULL;
    return string;
}

trie_node *breaklinked_str(trie_node *previous_node, trie_node *node, linked_str *break_point)
{
    int index1;
    int index2;

    // create a new trie node pointer.
    trie_node *new_node = create_node();
    // create a new string beginning next to the break point.
    linked_str *new_str = break_point->next;
    break_point->next = NULL;
    // convert char to index
    index1 = (new_str->character) - '0';

    new_node->linked_str = node->linked_str;
    node->linked_str = new_str;
    new_node->children[index1] = node;

    index2 = (new_node->linked_str->character) - '0';
    // pointer the new node to the relevent index of the parent node.
    previous_node->children[index2] = new_node;

    // return the newnode.
    return new_node;
}

trie_node *insert(trie_node *root, unsigned char *str)
{
    // get the length of the str
    int last_letter_index = strlen(str);
    int i = 0, charIndex;

    // create trie nodes and likedlist pointers to track
    // previous current and next pointer nodes.
    trie_node *current_node = root, *previous_node = NULL;
    trie_node *new_node = NULL;
    linked_str *current_letter, *previousLetter = NULL;
    current_letter = current_node -> linked_str;

    // go till the last leter of the string.
    while (i < last_letter_index) {
        charIndex = (str[i]) - '0';
        // if current letter is null
        if (current_letter == NULL) {
            // if the trie is empty.
            if (current_node->children[charIndex] == NULL) {
                // create a new node.
                new_node = create_node();
                // append the string[i:last_letter_index] point to the new nodes linked
                new_node->linked_str = appendlinked_str(str, i, last_letter_index);
                new_node->is_leaf = 1;
                current_node->children[charIndex] = new_node;
                break;
            } else { // if it is the first node.
                // make the previous node pointing to the current node.
                previous_node = current_node;
                current_node = current_node->children[charIndex];
                previousLetter = current_node->linked_str;
                current_letter = current_node->linked_str->next;
            }
        } else {
            if (current_letter->character != str[i]) {
                // make the current node pointing to the breakedlinked_str.
                current_node = breaklinked_str(previous_node, current_node, previousLetter);
                // create a new node.
                new_node = create_node();
                // append the link string to the newnodes linked_str.
                new_node->linked_str = appendlinked_str(str, i, last_letter_index);
                // make new node a leaf node
                new_node->is_leaf = 1;
                // put new_node as a child of a current node.
                current_node->children[charIndex] = new_node;
                break;
            } else {
                previousLetter = current_letter;
                current_letter = current_letter->next;
            }
        }
        i++;
    }

    return new_node;
}

trie_node *search_nodes(trie_node *root, unsigned char *str)
{
    // get the lastIndex of the str
    int lastIndex = strlen(str);
    int i = 0, charIndex;
    trie_node *current_node = root;
    linked_str *current_letter = current_node->linked_str;

    while (i < lastIndex) {
        // get the index from the char Index.
        charIndex = str[i] - '0';

        // if current letter is null.
        if (current_letter == NULL) {
            // point the relevent index to the current_node.
            current_node = current_node->children[charIndex];
            // if the word is not found. Then the current node
            // and the current_letter is NULL.
            if (!current_node) return NULL;
            // make the currentLeter pointing to the linked strings next letter.
            current_letter = current_node->linked_str->next;
        } else {
            // go to the next letter.
            current_letter = current_letter->next;
        }
        i++;
    }

    // go untilll the current letter is found null
    while (current_letter != NULL) {
        // go till the end of the character.
        str[lastIndex] = current_letter->character;
        current_letter = current_letter->next;
        lastIndex++;
    }
    // make the last index pointing to the terminating character
    str[lastIndex] = '\0';
    return current_node;
}

int str_to_char(linked_str *begin, unsigned char *str, int initial)
{
    int newSize = initial;
    linked_str *current_letter = begin;

    // go while current lettter is not null
    while (current_letter != NULL) {
        // put the char by char in str
        str[newSize] = current_letter->character;
        // goto the next letter
        current_letter = current_letter->next;
        newSize++;
    }
    // set the terminating character.
    str[newSize] = '\0';
    return newSize - 1;
}

void print_suggetions(trie_node *suggested_node, char str[], int size)
{
    // create a poiter to the suggested node
    trie_node *current_node = NULL;
    int i, j, newSize;

    if (suggested_node == NULL) {
        printk("empty\n");
        return;
    }

    current_node = suggested_node;

    if (current_node->is_leaf){
        // go till the word_size
        for (j = 0; j < size; ++j){
            // print the uppercased char
            printk("%c", str[j]);
        }
        // print the endline
        printk("\n");
    }

    // go through each children node.
    for (i = 0; i < ALPHABET_SIZE; ++i) {
        // if each child is not null
        if (current_node->children[i] != NULL) {
            // break down the string and get the characters
            newSize = str_to_char(current_node->children[i]->linked_str, str, size);
            // print the suggestion.
            print_suggetions(current_node->children[i], str, newSize + 1);
        }
    }
}
