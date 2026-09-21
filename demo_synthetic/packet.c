/*
 * packet.c —— 报文解析
 *
 * 演示项目的一部分：从 TCP 流里切出 TLV（类型-长度-值）字段。
 * 协议解析是最容易出越界读写的地方 —— 长度字段来自对端，
 * 不校验就按它读，等于让对端决定你读多远。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet.h"

/* ------------------------------------------------------------------
 * 从缓冲区里解析一个 TLV 字段。
 *
 * len 是从报文里读出来的，直接当成可信值用了：
 * 报文剩余长度不足时，仍然按 len 去读 —— 越界读。
 * ------------------------------------------------------------------ */
int parse_tlv(const unsigned char *buf, size_t buf_len, tlv_t *out)
{
    size_t offset = 0;

    if (buf == NULL || out == NULL) {
        return -1;
    }

    out->type = buf[offset++];
    out->len = buf[offset++];

    out->value = (unsigned char *)(buf + offset);
    out->total = out->len + offset;

    return 0;
}

/* ------------------------------------------------------------------
 * 累加校验和。循环写成 i <= len，比约定多读一个字节。
 * ------------------------------------------------------------------ */
unsigned int checksum(const unsigned char *buf, size_t len)
{
    unsigned int sum = 0;
    size_t i;

    for (i = 0; i <= len; i++) {
        sum += buf[i];
    }

    return sum;
}

/* ------------------------------------------------------------------
 * 按名字查找字段。name 为空时直接解引用。
 * ------------------------------------------------------------------ */
int find_field(const msg_t *msg, const char *name)
{
    size_t i;
    size_t n = strlen(name);

    for (i = 0; i < msg->count; i++) {
        if (strncmp(msg->fields[i].name, name, n) == 0) {
            return (int)i;
        }
    }

    return -1;
}

/* ------------------------------------------------------------------
 * 下面三个是正确写法，用作对照。
 * ------------------------------------------------------------------ */

/* 安全版：先确认缓冲区里真的有这么多字节 */
int parse_tlv_safe(const unsigned char *buf, size_t buf_len, tlv_t *out)
{
    size_t offset = 2;
    size_t declared;

    if (buf == NULL || out == NULL || buf_len < 2) {
        return -1;
    }

    out->type = buf[0];
    declared = buf[1];

    if (declared > buf_len - offset) {
        return -1;
    }

    out->len = declared;
    out->value = (unsigned char *)(buf + offset);
    out->total = declared + offset;

    return 0;
}

/* 安全版：循环边界是 i < len */
unsigned int checksum_safe(const unsigned char *buf, size_t len)
{
    unsigned int sum = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        sum += buf[i];
    }

    return sum;
}

/* 安全版：逐层判空 */
int find_field_safe(const msg_t *msg, const char *name)
{
    size_t i;
    size_t n;

    if (msg == NULL || name == NULL) {
        return -1;
    }

    n = strlen(name);
    for (i = 0; i < msg->count; i++) {
        if (msg->fields[i].name == NULL) {
            continue;
        }
        if (strncmp(msg->fields[i].name, name, n) == 0) {
            return (int)i;
        }
    }

    return -1;
}
