#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>

void copy_hostname(const char *host);
void append_line(char *dst, const char *line);
void format_path(char *out, const char *dir, const char *name);
int read_exact(unsigned char *dst, const unsigned char *src, int n);

int copy_hostname_safe(char *dst, size_t dst_size, const char *host);
int append_line_safe(char *dst, size_t dst_size, const char *line);
size_t sum_bytes(const unsigned char *src, size_t n);

#endif /* BUFFER_H */
