#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "structs.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	printf("EXEC pid is :%ld\n", e->pid);
	printf("EXEC filename is :%s\n", e->data);

	return 0;
}

int main(int argc, char **argv) {

  // The location of the bytecode file.
  char path[PATH_MAX];
  sprintf(path, "%s/lsm_kern.o", dirname(argv[0]));
  printf("bytecode file path: %s\n", path);

  // int prog_fd;

  // Open and Load the bytecode file.
  struct bpf_object *obj;
  obj = bpf_object__open(path);
  printf("Ok! BPF bytecode open over......\n");

  int load_res = bpf_object__load(obj);
  if (load_res != 0){
    printf("BPF Program loaded failed......\n");
    return -1;
  }
  printf("Ok! BPF Program loaded......\n");

  // Find the program been loaded into the kernel.
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "lsm_demo");

  // attach the program into the Hooks.
  // bpf_program__attach(prog);
  struct bpf_link *lsm_link = bpf_program__attach_lsm(prog);

  struct bpf_program *tp_prog =
      bpf_object__find_program_by_name(obj, "trace_enter_execve");
  bpf_program__attach(tp_prog);




  // TESTING PASSING STRUCT TO MAP
  struct bpf_map *book_map = bpf_object__find_map_by_name(obj, "book_test");
  int book_map_fd = bpf_map__fd(book_map);
  
  struct TestStruct book;
  memset(&book, 0, sizeof(book));
  strcpy(book.title, "Waging Heavy Peace");
  strcpy(book.author, "Neil Young");
  book.length = 998;

  int m = 10;
  int attempt = bpf_map_update_elem(book_map_fd, &m, &book, BPF_ANY);
  printf("Success is %d for adding a struct to the map.\n", attempt);

  /* Print Ringbuf Data*/
  struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(obj, "events");
  int ringbuf_map_fd = bpf_map__fd(ringbuf_map);
  struct ring_buffer *event = NULL;
  event = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);

	if (!event) {
		printf("Failed to create ring buffer\n");
		return 0;
	}

  while (1){
    ring_buffer__poll(event, 100 /* timeout, ms */);
  }



  printf("Press any key to continue...\n");
  getchar();

  // // Iterate over all keys in the map
  // while (bpf_map_get_next_key(lsm_map_fd, &prev_key, &key) == 0) {
  //   printf("The pid is : %ld\n", key);
  //   bpf_map_lookup_elem(lsm_map_fd, &key, &val);
  //   printf("The number of argument is : %ld\n", val);
  //   prev_key = key;
  // }


  int destroy_res = bpf_link__destroy(lsm_link);
  printf("destroy_res : %d\n", destroy_res);

  printf("the program is over......\n");
  return 0;
}
