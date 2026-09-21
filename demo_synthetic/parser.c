/*
 * parser.c —— 配置行与报文的解析
 *
 * 演示项目的一部分：一个小型采集代理的配置解析模块。
 * 这里集中了若干「看着很正常、实际上有问题」的写法。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

#define MAX_NAME 64
#define MAX_VALUE 128

/* ------------------------------------------------------------------
 * 解析 "key=value" 形式的配置行。
 *
 * 调用方按约定传入两个缓冲区，但函数本身不校验长度 ——
 * value 指向的缓冲区如果小于这行的 value 部分，就会写越界。
 * ------------------------------------------------------------------ */
int parse_config_line(const char *line, char *key, char *value)
{
    const char *eq;
    size_t key_len;

    if (line == NULL || key == NULL || value == NULL) {
        return -1;
    }

    eq = strchr(line, '=');
    if (eq == NULL) {
        return -1;
    }

    key_len = (size_t)(eq - line);
    memcpy(key, line, key_len);
    key[key_len] = '\0';

    /* 这里没有校验 eq+1 的长度 */
    strcpy(value, eq + 1);

    return 0;
}

/* ------------------------------------------------------------------
 * 去掉字符串首尾空白。这个函数是安全的，用作对照。
 * ------------------------------------------------------------------ */
char *trim(char *s)
{
    char *end;

    if (s == NULL) {
        return NULL;
    }

    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }

    return s;
}

/* ------------------------------------------------------------------
 * 把整行按逗号拆成字段，写进固定大小的数组。
 *
 * count 是「实际写入的个数」，但没有和 max_fields 做比较 ——
 * 字段数超过 max_fields 时越界写。
 * ------------------------------------------------------------------ */
int split_fields(char *line, char **fields, int max_fields, int *count)
{
    char *p = line;
    int n = 0;

    while (p != NULL && *p != '\0') {
        char *comma = strchr(p, ',');
        if (comma != NULL) {
            *comma = '\0';
        }
        fields[n] = p;
        n++;
        p = (comma != NULL) ? comma + 1 : NULL;
    }

    *count = n;
    return 0;
}

/* ------------------------------------------------------------------
 * 格式化一条日志。用小缓冲区拼可能很长的字符串。
 * ------------------------------------------------------------------ */
void log_event(const char *tag, const char *detail)
{
    char buf[128];

    sprintf(buf, "[%s] %s", tag, detail);
    puts(buf);
}

/* ------------------------------------------------------------------
 * 递归下降地找匹配的右括号，返回下标；找不到返回 -1。
 * 没有做深度限制，但逻辑本身是安全的。
 * ------------------------------------------------------------------ */
int find_matching_paren(const char *s, int open_pos)
{
    int depth = 0;
    int i;

    for (i = open_pos; s[i] != '\0'; i++) {
        if (s[i] == '(') {
            depth++;
        } else if (s[i] == ')') {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }

    return -1;
}
