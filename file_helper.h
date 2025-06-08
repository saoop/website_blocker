#ifndef FILE_HELPER_H
#define FILE_HELPER_H

#include <stdio.h>
#include "types.h"

void save_string(FILE *f, const char *str);
void save_string_array(FILE *f, StringArray *sa);
void save_domain_array(const DomainArray *da, const char *filename);
char *load_string(FILE *f);
void load_string_array(FILE *f, StringArray *sa);
void load_domain_array(DomainArray *da, const char *filename);

#endif
