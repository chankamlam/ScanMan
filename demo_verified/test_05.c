/*
 * linux.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：安全 ==== */
static u32 nested_vmx_load_msr(struct kvm_vcpu *vcpu, u64 gpa, u32 count)
{
	u32 i;
	struct vmx_msr_entry e;
	struct msr_data msr;

	msr.host_initiated = false;
	for (i = 0; i < count; i++) {
		if (kvm_vcpu_read_guest(vcpu, gpa + i * sizeof(e),
					&e, sizeof(e))) {
			pr_debug_ratelimited(
				"%s cannot read MSR entry (%u, 0x%08llx)\n",
				__func__, i, gpa + i * sizeof(e));
			goto fail;
		}
		if (nested_vmx_load_msr_check(vcpu, &e)) {
			pr_debug_ratelimited(
				"%s check failed (%u, 0x%x, 0x%x)\n",
				__func__, i, e.index, e.reserved);
			goto fail;
		}
		msr.index = e.index;
		msr.data = e.value;
		if (kvm_set_msr(vcpu, &msr)) {
			pr_debug_ratelimited(
				"%s cannot write MSR (%u, 0x%x, 0x%llx)\n",
				__func__, i, e.index, e.value);
			goto fail;
		}
	}
	return 0;
fail:
	return i + 1;
}

/* ==== 真实标签：有漏洞（CWE-264） ==== */
static int userns_install(struct nsproxy *nsproxy, void *ns)
{
	struct user_namespace *user_ns = ns;
	struct cred *cred;

	/* Don't allow gaining capabilities by reentering
	 * the same user namespace.
	 */
	if (user_ns == current_user_ns())
		return -EINVAL;

	/* Threaded processes may not enter a different user namespace */
 	if (atomic_read(&current->mm->mm_users) > 1)
 		return -EINVAL;
 
 	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
 		return -EPERM;
 
	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	put_user_ns(cred->user_ns);
	set_cred_user_ns(cred, get_user_ns(user_ns));

	return commit_creds(cred);
}

/* ==== 真实标签：有漏洞（CWE-476） ==== */
key_ref_t keyring_search(key_ref_t keyring,
			 struct key_type *type,
			 const char *description)
{
	struct keyring_search_context ctx = {
 		.index_key.type		= type,
 		.index_key.description	= description,
 		.cred			= current_cred(),
		.match_data.cmp		= type->match,
 		.match_data.raw_data	= description,
 		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
 		.flags			= KEYRING_SEARCH_DO_STATE_CHECK,
 	};
 	key_ref_t key;
 	int ret;
 
	if (!ctx.match_data.cmp)
		return ERR_PTR(-ENOKEY);
 	if (type->match_preparse) {
 		ret = type->match_preparse(&ctx.match_data);
 		if (ret < 0)
			return ERR_PTR(ret);
	}

	key = keyring_search_aux(keyring, &ctx);

	if (type->match_free)
		type->match_free(&ctx.match_data);
	return key;
}

/* ==== 真实标签：有漏洞（CWE-125） ==== */
void common_timer_get(struct k_itimer *timr, struct itimerspec64 *cur_setting)
{
	const struct k_clock *kc = timr->kclock;
	ktime_t now, remaining, iv;
 	struct timespec64 ts64;
 	bool sig_none;
 
	sig_none = (timr->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE;
 	iv = timr->it_interval;
 
 	/* interval timer ? */
	if (iv) {
		cur_setting->it_interval = ktime_to_timespec64(iv);
	} else if (!timr->it_active) {
		/*
		 * SIGEV_NONE oneshot timers are never queued. Check them
		 * below.
		 */
		if (!sig_none)
			return;
	}

	/*
	 * The timespec64 based conversion is suboptimal, but it's not
	 * worth to implement yet another callback.
	 */
	kc->clock_get(timr->it_clock, &ts64);
	now = timespec64_to_ktime(ts64);

	/*
	 * When a requeue is pending or this is a SIGEV_NONE timer move the
	 * expiry time forward by intervals, so expiry is > now.
	 */
	if (iv && (timr->it_requeue_pending & REQUEUE_PENDING || sig_none))
		timr->it_overrun += kc->timer_forward(timr, now);

	remaining = kc->timer_remaining(timr, now);
	/* Return 0 only, when the timer is expired and not pending */
	if (remaining <= 0) {
		/*
		 * A single shot SIGEV_NONE timer must return 0, when
		 * it is expired !
		 */
		if (!sig_none)
			cur_setting->it_value.tv_nsec = 1;
	} else {
		cur_setting->it_value = ktime_to_timespec64(remaining);
	}
}

/* ==== 真实标签：安全 ==== */
static void __dentry_kill(struct dentry *dentry)
{
	struct dentry *parent = NULL;
	bool can_free = true;
	if (!IS_ROOT(dentry))
		parent = dentry->d_parent;

	/*
	 * The dentry is now unrecoverably dead to the world.
	 */
	lockref_mark_dead(&dentry->d_lockref);

	/*
	 * inform the fs via d_prune that this dentry is about to be
	 * unhashed and destroyed.
	 */
	if (dentry->d_flags & DCACHE_OP_PRUNE)
		dentry->d_op->d_prune(dentry);

	if (dentry->d_flags & DCACHE_LRU_LIST) {
		if (!(dentry->d_flags & DCACHE_SHRINK_LIST))
			d_lru_del(dentry);
	}
	/* if it was on the hash then remove it */
	__d_drop(dentry);
	dentry_unlist(dentry, parent);
	if (parent)
		spin_unlock(&parent->d_lock);
	if (dentry->d_inode)
		dentry_unlink_inode(dentry);
	else
		spin_unlock(&dentry->d_lock);
	this_cpu_dec(nr_dentry);
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);

	spin_lock(&dentry->d_lock);
	if (dentry->d_flags & DCACHE_SHRINK_LIST) {
		dentry->d_flags |= DCACHE_MAY_FREE;
		can_free = false;
	}
	spin_unlock(&dentry->d_lock);
	if (likely(can_free))
		dentry_free(dentry);
}
