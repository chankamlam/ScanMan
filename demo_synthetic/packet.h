#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>

typedef struct tlv {
    unsigned char type;
    size_t len;
    unsigned char *value;
    size_t total;
} tlv_t;

typedef struct field {
    char *name;
    char *value;
} field_t;

typedef struct msg {
    field_t *fields;
    size_t count;
} msg_t;

int parse_tlv(const unsigned char *buf, size_t buf_len, tlv_t *out);
unsigned int checksum(const unsigned char *buf, size_t len);
int find_field(const msg_t *msg, const char *name);

int parse_tlv_safe(const unsigned char *buf, size_t buf_len, tlv_t *out);
unsigned int checksum_safe(const unsigned char *buf, size_t len);
int find_field_safe(const msg_t *msg, const char *name);

#endif /* PACKET_H */
