/* test_11.c —— 权限与访问控制
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

struct tcp_sock_t *tcp_open(uint16_t port)
 {
 	struct tcp_sock_t *this = calloc(1, sizeof *this);
 	if (this == NULL) {
		ERR("callocing this failed");
 		goto error;
 	}
 
 	this->sd = -1;
 	this->sd = socket(AF_INET6, SOCK_STREAM, 0);
 	if (this->sd < 0) {
		ERR("sockect open failed");
 		goto error;
 	}
 
	struct sockaddr_in6 addr;
 	memset(&addr, 0, sizeof addr);
 	addr.sin6_family = AF_INET6;
 	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
 
 	if (bind(this->sd,
 	        (struct sockaddr *)&addr,
 	        sizeof addr) < 0) {
 		if (g_options.only_desired_port == 1)
			ERR("Bind on port failed. "
 			    "Requested port may be taken or require root permissions.");
 		goto error;
 	}
 
 	if (listen(this->sd, HTTP_MAX_PENDING_CONNS) < 0) {
		ERR("listen failed on socket");
 		goto error;
 	}
 
	return this;

error:
	if (this != NULL) {
		if (this->sd != -1) {
			close(this->sd);
		}
		free(this);
	}
	return NULL;
}

void preproc_mount_mnt_dir(void) {
	if (!tmpfs_mounted) {
		if (arg_debug)
			printf("Mounting tmpfs on %s directory\n", RUN_MNT_DIR);
		if (mount("tmpfs", RUN_MNT_DIR, "tmpfs", MS_NOSUID | MS_STRICTATIME,  "mode=755,gid=0") < 0)
			errExit("mounting /run/firejail/mnt");
		tmpfs_mounted = 1;
 		fs_logger2("tmpfs", RUN_MNT_DIR);
 
 #ifdef HAVE_SECCOMP
 		if (arg_seccomp_block_secondary)
 			copy_file(PATH_SECCOMP_BLOCK_SECONDARY, RUN_SECCOMP_BLOCK_SECONDARY, getuid(), getgid(), 0644); // root needed
 		else {
			copy_file(PATH_SECCOMP_32, RUN_SECCOMP_32, getuid(), getgid(), 0644); // root needed
		}
		if (arg_allow_debuggers)
			copy_file(PATH_SECCOMP_DEFAULT_DEBUG, RUN_SECCOMP_CFG, getuid(), getgid(), 0644); // root needed
		else
			copy_file(PATH_SECCOMP_DEFAULT, RUN_SECCOMP_CFG, getuid(), getgid(), 0644); // root needed

		if (arg_memory_deny_write_execute)
			copy_file(PATH_SECCOMP_MDWX, RUN_SECCOMP_MDWX, getuid(), getgid(), 0644); // root needed
		create_empty_file_as_root(RUN_SECCOMP_PROTOCOL, 0644);
		if (set_perms(RUN_SECCOMP_PROTOCOL, getuid(), getgid(), 0644))
			errExit("set_perms");
		create_empty_file_as_root(RUN_SECCOMP_POSTEXEC, 0644);
		if (set_perms(RUN_SECCOMP_POSTEXEC, getuid(), getgid(), 0644))
			errExit("set_perms");
#endif
	}
}
