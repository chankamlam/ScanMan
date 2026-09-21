/* test_10.c —— 输入验证与信息泄露
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

static int encrypt(struct blkcipher_desc *desc,
		   struct scatterlist *dst, struct scatterlist *src,
		   unsigned int nbytes)
{
	struct blkcipher_walk walk;
	struct crypto_blkcipher *tfm = desc->tfm;
	struct salsa20_ctx *ctx = crypto_blkcipher_ctx(tfm);
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, 64);
 
 	salsa20_ivsetup(ctx, walk.iv);
 
	if (likely(walk.nbytes == nbytes))
	{
		salsa20_encrypt_bytes(ctx, walk.dst.virt.addr,
				      walk.src.virt.addr, nbytes);
		return blkcipher_walk_done(desc, &walk, 0);
	}
 	while (walk.nbytes >= 64) {
 		salsa20_encrypt_bytes(ctx, walk.dst.virt.addr,
 				      walk.src.virt.addr,
				      walk.nbytes - (walk.nbytes % 64));
		err = blkcipher_walk_done(desc, &walk, walk.nbytes % 64);
	}

	if (walk.nbytes) {
		salsa20_encrypt_bytes(ctx, walk.dst.virt.addr,
				      walk.src.virt.addr, walk.nbytes);
		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}

static int xfrm_alloc_replay_state_esn(struct xfrm_replay_state_esn **replay_esn,
				       struct xfrm_replay_state_esn **preplay_esn,
 				       struct nlattr *rta)
 {
 	struct xfrm_replay_state_esn *p, *pp, *up;
 
 	if (!rta)
 		return 0;
 
 	up = nla_data(rta);
 
	p = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
 	if (!p)
 		return -ENOMEM;
 
	pp = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
 	if (!pp) {
 		kfree(p);
 		return -ENOMEM;
 	}
 
 	*replay_esn = p;
 	*preplay_esn = pp;
 
	return 0;
}
