/* test_09.c —— 整数与数值计算
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

static int ssl_scan_clienthello_custom_tlsext(SSL *s,
                                              const unsigned char *data,
                                              const unsigned char *limit,
                                              int *al)
{
    unsigned short type, size, len;
    /* If resumed session or no custom extensions nothing to do */
     if (s->hit || s->cert->srv_ext.meths_count == 0)
         return 1;
 
    if (data >= limit - 2)
         return 1;
     n2s(data, len);
 
    if (data > limit - len)
         return 1;
 
    while (data <= limit - 4) {
         n2s(data, type);
         n2s(data, size);
 
        if (data + size > limit)
             return 1;
         if (custom_ext_parse(s, 1 /* server */ , type, data, size, al) <= 0)
             return 0;

        data += size;
    }

    return 1;
}
