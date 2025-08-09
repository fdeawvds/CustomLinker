#include <stdio.h>
#include <elf.h>

#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>

void shared_function() {
  printf("This is a shared function from the shared library.\n");

  // initialize libelf
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
    return;
  }

  printf("ELF library initialized successfully.\n");

  // open the current executable
  int fd = open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    perror("open");
    return;
  }

  // read ELF header
  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!elf) {
    fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
    close(fd);
    return;
  }

  GElf_Ehdr ehdr;
  if (gelf_getehdr(elf, &ehdr) != &ehdr) {
    fprintf(stderr, "gelf_getehdr() failed: %s\n", elf_errmsg(-1));
  } else {
    printf("ELF type: %u, machine: %u\n", (unsigned)ehdr.e_type, (unsigned)ehdr.e_machine);
  }

  // cleanup
  elf_end(elf);
  close(fd);

}

int main() {
  printf("Shared library loaded successfully.\n");
  shared_function();
  return 0;
}