#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

typedef struct session {
    char *name;
    char *buffer;
    size_t buffer_len;
    int fd;
} session_t;

void *alloc_table(unsigned int count, unsigned int elem_size);
int update_session_name(session_t *s, const char *new_name);
void close_session(session_t *s);
const char *session_label(const session_t *s);

void *alloc_table_safe(unsigned int count, unsigned int elem_size);
int update_session_name_safe(session_t *s, const char *new_name);
const char *session_label_safe(const session_t *s);

#endif /* MEMORY_H */
