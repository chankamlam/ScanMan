/* test_12.c —— 资源生命周期与并发
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

static int shmem_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	struct shmem_sb_info config = *sbinfo;
 	unsigned long inodes;
 	int error = -EINVAL;
 
 	if (shmem_parse_options(data, &config, true))
 		return error;
 
	spin_lock(&sbinfo->stat_lock);
	inodes = sbinfo->max_inodes - sbinfo->free_inodes;
	if (percpu_counter_compare(&sbinfo->used_blocks, config.max_blocks) > 0)
		goto out;
	if (config.max_inodes < inodes)
		goto out;
	/*
	 * Those tests disallow limited->unlimited while any are in use;
	 * but we must separately disallow unlimited->limited, because
	 * in that case we have no record of how much is already in use.
	 */
	if (config.max_blocks && !sbinfo->max_blocks)
		goto out;
	if (config.max_inodes && !sbinfo->max_inodes)
		goto out;

	error = 0;
	sbinfo->max_blocks  = config.max_blocks;
 	sbinfo->max_inodes  = config.max_inodes;
 	sbinfo->free_inodes = config.max_inodes - inodes;
 
	mpol_put(sbinfo->mpol);
	sbinfo->mpol        = config.mpol;	/* transfers initial ref */
 out:
 	spin_unlock(&sbinfo->stat_lock);
 	return error;
}

static int xfrm_dump_policy(struct sk_buff *skb, struct netlink_callback *cb)
 {
 	struct net *net = sock_net(skb->sk);
	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *) &cb->args[1];
 	struct xfrm_dump_info info;
 
	BUILD_BUG_ON(sizeof(struct xfrm_policy_walk) >
		     sizeof(cb->args) - sizeof(cb->args[0]));
 	info.in_skb = cb->skb;
 	info.out_skb = skb;
 	info.nlmsg_seq = cb->nlh->nlmsg_seq;
 	info.nlmsg_flags = NLM_F_MULTI;
 
	if (!cb->args[0]) {
		cb->args[0] = 1;
		xfrm_policy_walk_init(walk, XFRM_POLICY_TYPE_ANY);
	}
 	(void) xfrm_policy_walk(net, walk, dump_one_policy, &info);
 
 	return skb->len;
}

struct dentry *debugfs_rename(struct dentry *old_dir, struct dentry *old_dentry,
		struct dentry *new_dir, const char *new_name)
 {
 	int error;
 	struct dentry *dentry = NULL, *trap;
	const char *old_name;
 
 	trap = lock_rename(new_dir, old_dir);
 	/* Source or destination directories don't exist? */
	if (d_really_is_negative(old_dir) || d_really_is_negative(new_dir))
		goto exit;
	/* Source does not exist, cyclic rename, or mountpoint? */
	if (d_really_is_negative(old_dentry) || old_dentry == trap ||
	    d_mountpoint(old_dentry))
		goto exit;
	dentry = lookup_one_len(new_name, new_dir, strlen(new_name));
	/* Lookup failed, cyclic rename or target exists? */
 	if (IS_ERR(dentry) || dentry == trap || d_really_is_positive(dentry))
 		goto exit;
 
	old_name = fsnotify_oldname_init(old_dentry->d_name.name);
 
 	error = simple_rename(d_inode(old_dir), old_dentry, d_inode(new_dir),
 			      dentry, 0);
 	if (error) {
		fsnotify_oldname_free(old_name);
 		goto exit;
 	}
 	d_move(old_dentry, dentry);
	fsnotify_move(d_inode(old_dir), d_inode(new_dir), old_name,
 		d_is_dir(old_dentry),
 		NULL, old_dentry);
	fsnotify_oldname_free(old_name);
 	unlock_rename(new_dir, old_dir);
 	dput(dentry);
 	return old_dentry;
exit:
	if (dentry && !IS_ERR(dentry))
		dput(dentry);
	unlock_rename(new_dir, old_dir);
	return NULL;
}
