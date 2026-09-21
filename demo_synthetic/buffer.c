/*
 * buffer.c —— 字符串拼装与定长缓冲区
 *
 * 演示项目的一部分：采集代理里负责拼接主机名、路径、报文的模块。
 * 前半部分是「经典但依然常见」的写法，后半部分是它们的正确对照。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"

#define FIXED_SIZE 256
#define PATH_SIZE 128

/* ------------------------------------------------------------------
 * 把主机名拷进栈上缓冲区。
 * 调用方没有传长度，函数也没有检查 —— 长主机名直接冲栈。
 * ------------------------------------------------------------------ */
void copy_hostname(const char *host)
{
    char buf[FIXED_SIZE];

    strcpy(buf, host);
    printf("host=%s\n", buf);
}

/* ------------------------------------------------------------------
 * 在已有内容后面追加一行。
 * strcat 同样是「不检查目标剩余空间」的写法。
 * ------------------------------------------------------------------ */
void append_line(char *dst, const char *line)
{
    strcat(dst, line);
    strcat(dst, "\n");
}

/* ------------------------------------------------------------------
 * 拼一个文件路径。用 sprintf 而不是 snprintf。
 * ------------------------------------------------------------------ */
void format_path(char *out, const char *dir, const char *name)
{
    sprintf(out, "%s/%s", dir, name);
}

/* ------------------------------------------------------------------
 * 逐字节读入正好 n 个字节。
 * 循环写成 i <= n，多读/多写一个字节。
 * ------------------------------------------------------------------ */
int read_exact(unsigned char *dst, const unsigned char *src, int n)
{
    int i;
    int sum = 0;

    for (i = 0; i <= n; i++) {
        dst[i] = src[i];
        sum += src[i];
    }

    return sum;
}

/* ------------------------------------------------------------------
 * 下面三个是上面那些问题的正确写法，用作对照。
 * ------------------------------------------------------------------ */

/* 安全版：显式传目标大小，用 snprintf 截断而不是溢出 */
int copy_hostname_safe(char *dst, size_t dst_size, const char *host)
{
    if (dst == NULL || host == NULL || dst_size == 0) {
        return -1;
    }

    snprintf(dst, dst_size, "%s", host);
    return 0;
}

/* 安全版：先算剩余空间再追加 */
int append_line_safe(char *dst, size_t dst_size, const char *line)
{
    size_t used;

    if (dst == NULL || line == NULL) {
        return -1;
    }

    used = strlen(dst);
    if (used + strlen(line) + 2 > dst_size) {
        return -1;
    }

    strncat(dst, line, dst_size - used - 1);
    strncat(dst, "\n", dst_size - strlen(dst) - 1);
    return 0;
}

/* 安全版：循环边界是 i < n */
size_t sum_bytes(const unsigned char *src, size_t n)
{
    size_t i;
    size_t sum = 0;

    for (i = 0; i < n; i++) {
        sum += src[i];
    }

    return sum;
}
