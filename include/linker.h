/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef LINKER_H
#define LINKER_H

#include <elf.h>
#include <stdbool.h>

#include "elf_util.h"

#define MAX_DEPS 64

struct loaded_dep {
  struct csoloader_elf *img;
  bool is_manual_load;

  uintptr_t load_bias;

  void *map_base;
  size_t map_size;
};

struct linker {
  struct csoloader_elf *img;

  struct loaded_dep dependencies[MAX_DEPS];
  int dep_count;

  size_t main_map_size;
  bool is_linked;
};

void *linker_load_library_manually(const char *lib_path, struct loaded_dep *dep_info);

bool linker_init(struct linker *linker, struct csoloader_elf *img);

void linker_destroy(struct linker *linker);

void linker_abandon(struct linker *linker);

bool linker_link(struct linker *linker);

#endif /* LINKER_H */
