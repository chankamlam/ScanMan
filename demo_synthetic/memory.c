/*
 * memory.c —— 动态内存管理
 *
 * 演示项目的一部分：会话表、缓冲区池的分配与释放。
 * 这里的几个函数对应内核/网络代码里最典型的三类内存缺陷：
 * 整数溢出导致的分配不足、释放后使用、重复释放。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"

/* ------------------------------------------------------------------
 * 按「元素个数 × 单元大小」申请内存。
 *
 * 乘法在 32 位的 size_t 上会回绕：传进来一个很大的 count，
 * 乘积绕回成一个小数字，于是分配出来的缓冲区远小于预期。
 * ------------------------------------------------------------------ */
void *alloc_table(unsigned int count, unsigned int elem_size)
{
    size_t total = (size_t)(count * elem_size);

    return malloc(total);
}

/* ------------------------------------------------------------------
 * 更新会话名字：先释放旧名字，再申请新的。
 *
 * 释放之后如果 strdup 失败，返回的指针就是悬垂的；
 * 更常见的写法是下面这样「用完再释放」，但那也没解决问题 ——
 * 调用方拿到的 name 指向已释放的内存。
 * ------------------------------------------------------------------ */
int update_session_name(session_t *s, const char *new_name)
{
    if (s == NULL || new_name == NULL) {
        return -1;
    }

    free(s->name);
    s->name = strdup(new_name);
    if (s->name == NULL) {
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------
 * 关闭会话：释放成员，再释放结构体本身。
 * 但没有把指针置空，调用方再调一次就是重复释放。
 * ------------------------------------------------------------------ */
void close_session(session_t *s)
{
    if (s == NULL) {
        return;
    }

    free(s->name);
    free(s->buffer);
    free(s);
}

/* ------------------------------------------------------------------
 * 取会话的名字，用于打日志。
 * 没有判断 s 是否为空，也没有判断 name 是否为空。
 * ------------------------------------------------------------------ */
const char *session_label(const session_t *s)
{
    return s->name;
}

/* ------------------------------------------------------------------
 * 下面两个是正确写法，用作对照。
 * ------------------------------------------------------------------ */

/* 安全版：乘法前先判断会不会溢出 */
void *alloc_table_safe(unsigned int count, unsigned int elem_size)
{
    size_t total;

    if (elem_size != 0 && count > (size_t)-1 / elem_size) {
        return NULL;
    }

    total = (size_t)count * elem_size;
    if (total == 0) {
        return NULL;
    }

    return calloc(1, total);
}

/* 安全版：先申请成功再释放旧的，失败时保持原状 */
int update_session_name_safe(session_t *s, const char *new_name)
{
    char *copy;

    if (s == NULL || new_name == NULL) {
        return -1;
    }

    copy = strdup(new_name);
    if (copy == NULL) {
        return -1;
    }

    free(s->name);
    s->name = copy;
    return 0;
}

/* 安全版：取标签时逐层判空 */
const char *session_label_safe(const session_t *s)
{
    if (s == NULL || s->name == NULL) {
        return "(unknown)";
    }

    return s->name;
}
