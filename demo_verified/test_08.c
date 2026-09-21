/* test_08.c —— 缓冲区与越界
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

int usbip_recv_xbuff(struct usbip_device *ud, struct urb *urb)
{
	int ret;
	int size;

	if (ud->side == USBIP_STUB) {
		/* the direction of urb must be OUT. */
		if (usb_pipein(urb->pipe))
			return 0;

		size = urb->transfer_buffer_length;
	} else {
		/* the direction of urb must be IN. */
		if (usb_pipeout(urb->pipe))
			return 0;

		size = urb->actual_length;
	}

	/* no need to recv xbuff */
 	if (!(size > 0))
 		return 0;
 
 	ret = usbip_recv(ud->tcp_socket, urb->transfer_buffer, size);
 	if (ret != size) {
 		dev_err(&urb->dev->dev, "recv xbuf, %d\n", ret);
		if (ud->side == USBIP_STUB) {
			usbip_event_add(ud, SDEV_EVENT_ERROR_TCP);
		} else {
			usbip_event_add(ud, VDEV_EVENT_ERROR_TCP);
			return -EPIPE;
		}
	}

	return ret;
}

int common_timer_set(struct k_itimer *timr, int flags,
		     struct itimerspec64 *new_setting,
		     struct itimerspec64 *old_setting)
{
	const struct k_clock *kc = timr->kclock;
	bool sigev_none;
	ktime_t expires;

	if (old_setting)
		common_timer_get(timr, old_setting);

	/* Prevent rearming by clearing the interval */
	timr->it_interval = 0;
	/*
	 * Careful here. On SMP systems the timer expiry function could be
	 * active and spinning on timr->it_lock.
	 */
	if (kc->timer_try_to_cancel(timr) < 0)
		return TIMER_RETRY;

	timr->it_active = 0;
	timr->it_requeue_pending = (timr->it_requeue_pending + 2) &
		~REQUEUE_PENDING;
	timr->it_overrun_last = 0;

	/* Switch off the timer when it_value is zero */
	if (!new_setting->it_value.tv_sec && !new_setting->it_value.tv_nsec)
		return 0;
 
 	timr->it_interval = timespec64_to_ktime(new_setting->it_interval);
 	expires = timespec64_to_ktime(new_setting->it_value);
	sigev_none = (timr->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE;
 
 	kc->timer_arm(timr, expires, flags & TIMER_ABSTIME, sigev_none);
 	timr->it_active = !sigev_none;
	return 0;
}
