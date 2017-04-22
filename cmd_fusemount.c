#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <stdio.h>

#include <fuse_lowlevel.h>

#include "cmds.h"
#include "bcachefs.h"
#include "btree_iter.h"
#include "dirent.h"
#include "error.h"
#include "inode.h"
#include "libbcachefs.h"
#include "opts.h"
#include "super.h"
#include "tools-util.h"

#include <linux/dcache.h>

#include "fs.h" /* XXX for nlink_bias() */

/* XXX cut and pasted from fsck.c */
#define QSTR(n) { { { .len = strlen(n) } }, .name = n }

static struct stat inode_to_stat(struct bch_fs *c,
				 struct bch_inode_unpacked *bi)
{
	return (struct stat) {
		.st_size	= bi->i_size,
		.st_mode	= bi->i_mode,
		.st_uid		= bi->i_uid,
		.st_gid		= bi->i_gid,
		.st_nlink	= bi->i_nlink + nlink_bias(bi->i_mode),
		.st_rdev	= bi->i_dev,
		.st_blksize	= block_bytes(c),
		.st_blocks	= bi->i_sectors,
		.st_atim	= bch2_time_to_timespec(c, bi->i_atime),
		.st_mtim	= bch2_time_to_timespec(c, bi->i_mtime),
		.st_ctim	= bch2_time_to_timespec(c, bi->i_ctime),
	};
}

static struct fuse_entry_param inode_to_entry(struct bch_fs *c,
					      struct bch_inode_unpacked *bi)
{
	return (struct fuse_entry_param) {
		.ino		= bi->inum,
		.generation	= bi->i_generation,
		.attr		= inode_to_stat(c, bi),
		.attr_timeout	= DBL_MAX,
		.entry_timeout	= DBL_MAX,
	};
}

static int get_hash_info(struct bch_fs *c, u64 inum,
			 struct bch_hash_info *hash)
{
	struct bch_inode_unpacked bi;
	int ret;

	ret = bch2_inode_find_by_inum(c, inum, &bi);
	if (ret)
		return ret;

	*hash = bch2_hash_info_init(c, &bi);
	return 0;
}

static void bcachefs_fuse_destroy(void *arg)
{
	struct bch_fs *c = arg;

	bch2_fs_stop(c);
}

static int bcachefs_fuse_stat(struct bch_fs *c, u64 inum,
			      struct fuse_entry_param *e)
{
	struct bch_inode_unpacked bi;
	int ret;

	ret = bch2_inode_find_by_inum(c, inum, &bi);
	if (ret)
		return ret;

	*e = inode_to_entry(c, &bi);
	return 0;
}

static void bcachefs_fuse_lookup(fuse_req_t req, fuse_ino_t parent,
				 const char *name)
{
	struct bch_fs *c = fuse_req_userdata(req);
	struct bch_inode_unpacked bi;
	struct bch_hash_info hash;
	struct qstr qstr = QSTR(name);
	u64 inum;
	int ret;

	ret = get_hash_info(c, parent, &hash);
	if (ret)
		goto err;

	inum = bch2_dirent_lookup(c, parent, &hash, &qstr);
	if (!inum) {
		ret = -ENOENT;
		goto err;
	}

	ret = bch2_inode_find_by_inum(c, inum, &bi);
	if (ret)
		goto err;

	struct fuse_entry_param e = inode_to_entry(c, &bi);
	fuse_reply_entry(req, &e);
	return;
err:
	fuse_reply_err(req, -ret);
}

static void bcachefs_fuse_getattr(fuse_req_t req, fuse_ino_t inum,
				  struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
	struct bch_inode_unpacked bi;
	struct stat attr;
	int ret;

	ret = bch2_inode_find_by_inum(c, inum, &bi);
	if (ret) {
		fuse_reply_err(req, -ret);
		return;
	}

	attr = inode_to_stat(c, &bi);
	fuse_reply_attr(req, &attr, DBL_MAX);
}

static void bcachefs_fuse_setattr(fuse_req_t req, fuse_ino_t inum,
				  struct stat *attr, int to_set,
				  struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
	struct bch_inode_unpacked inode_u;
	struct bkey_inode_buf inode_p;
	struct btree_iter iter;
	int ret;

	bch2_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(inum, 0),
			     BTREE_ITER_INTENT);
	do {
		struct bkey_s_c k = bch2_btree_iter_peek_with_holes(&iter);

		if ((ret = btree_iter_err(k)))
			break;

		if (bch2_fs_inconsistent_on(k.k->type != BCH_INODE_FS, c,
			      "inode %lu not found when updating", inum)) {
			ret = -ENOENT;
			break;
		}

		ret = bch2_inode_unpack(bkey_s_c_to_inode(k), &inode_u);
		if (bch2_fs_inconsistent_on(ret, c,
			      "error %i unpacking inode %lu", ret, inum)) {
			ret = -ENOENT;
			break;
		}

		if (to_set & FUSE_SET_ATTR_MODE)
			inode_u.i_mode	= attr->st_mode;
		if (to_set & FUSE_SET_ATTR_UID)
			inode_u.i_uid	= attr->st_uid;
		if (to_set & FUSE_SET_ATTR_GID)
			inode_u.i_gid	= attr->st_gid;
		if (to_set & FUSE_SET_ATTR_SIZE)
			inode_u.i_size	= attr->st_size;
		if (to_set & FUSE_SET_ATTR_ATIME)
			inode_u.i_atime	= timespec_to_bch2_time(c, attr->st_atim);
		if (to_set & FUSE_SET_ATTR_MTIME)
			inode_u.i_mtime	= timespec_to_bch2_time(c, attr->st_mtim);
		if (to_set & FUSE_SET_ATTR_ATIME_NOW)
		if (to_set & FUSE_SET_ATTR_MTIME_NOW)

		bch2_inode_pack(&inode_p, &inode_u);

		ret = bch2_btree_insert_at(c, NULL, NULL, NULL,
				BTREE_INSERT_ATOMIC|
				BTREE_INSERT_NOFAIL,
				BTREE_INSERT_ENTRY(&iter, &inode_p.inode.k_i));
	} while (ret == -EINTR);

	bch2_btree_iter_unlock(&iter);

	if (!ret) {
		*attr = inode_to_stat(c, &inode_u);
		fuse_reply_attr(req, attr, DBL_MAX);
	} else {
		fuse_reply_err(req, -ret);
	}
}

static void bcachefs_fuse_readlink(fuse_req_t req, fuse_ino_t inum)
{
	//struct bch_fs *c = fuse_req_userdata(req);

	//char *link = malloc();

	//fuse_reply_readlink(req, link);
}

static int do_create(struct bch_fs *c, u64 dir,
		     const char *name, mode_t mode, dev_t rdev,
		     struct bch_inode_unpacked *new_inode)
{
	struct bkey_inode_buf inode_p;
	struct qstr qstr = QSTR(name);
	struct bch_hash_info hash;
	int ret;

	ret = get_hash_info(c, dir, &hash);

	bch2_inode_init(c, new_inode, 0, 0, mode, rdev);
	bch2_inode_pack(&inode_p, new_inode);

	ret = bch2_inode_create(c, &inode_p.inode.k_i,
			       BLOCKDEV_INODE_MAX, 0,
			       &c->unused_inode_hint);
	if (ret)
		return ret;

	new_inode->inum = inode_p.inode.k.p.inode;

	ret = bch2_dirent_create(c, dir, &hash,
				 mode_to_type(mode),
				 &qstr,
				 new_inode->inum,
				 NULL,
				 BCH_HASH_SET_MUST_CREATE);
	if (ret)
		bch2_inode_rm(c, new_inode->inum);

	return ret;
}

static void bcachefs_fuse_mknod(fuse_req_t req, fuse_ino_t dir,
				const char *name, mode_t mode,
				dev_t rdev)
{
	struct bch_fs *c = fuse_req_userdata(req);
	struct bch_inode_unpacked new_inode;
	int ret;

	ret = do_create(c, dir, name, mode, rdev, &new_inode);
	if (ret)
		goto err;

	if (S_ISDIR(mode)) {
		/* XXX: inc nlink */
	}

	struct fuse_entry_param e = inode_to_entry(c, &new_inode);
	fuse_reply_entry(req, &e);
	return;
err:
	fuse_reply_err(req, -ret);
}

static void bcachefs_fuse_mkdir(fuse_req_t req, fuse_ino_t dir,
				const char *name, mode_t mode)
{
	bcachefs_fuse_mknod(req, dir, name, mode, 0);
}

static void bcachefs_fuse_unlink(fuse_req_t req, fuse_ino_t parent,
				 const char *name)
{
	struct bch_fs *c = fuse_req_userdata(req);
	struct bch_hash_info hash;
	struct qstr qstr = QSTR(name);
	int ret;

	ret = get_hash_info(c, parent, &hash);
	if (ret)
		goto err;

	ret = bch2_dirent_delete(c, parent, &hash, &qstr, NULL);
err:
	fuse_reply_err(req, -ret);
}

static void bcachefs_fuse_rmdir(fuse_req_t req, fuse_ino_t parent,
				const char *name)
{
#if 0
	struct bch_fs *c = fuse_req_userdata(req);

	if (bch2_empty_dir(c, inum)) {
		fuse_reply_err(req, -ENOTEMPTY);
		return;
	}
#endif
	bcachefs_fuse_unlink(req, parent, name);
}

static void bcachefs_fuse_symlink(fuse_req_t req, const char *link,
				  fuse_ino_t parent, const char *name)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_rename(fuse_req_t req, fuse_ino_t parent,
				 const char *name, fuse_ino_t newparent,
				 const char *newname)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_link(fuse_req_t req, fuse_ino_t inum,
			       fuse_ino_t newparent, const char *newname)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_open(fuse_req_t req, fuse_ino_t inum,
			       struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_read(fuse_req_t req, fuse_ino_t inum,
			       size_t size, off_t off,
			       struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_flush(fuse_req_t req, fuse_ino_t inum,
				struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_release(fuse_req_t req, fuse_ino_t inum,
				  struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_fsync(fuse_req_t req, fuse_ino_t inum, int datasync,
				struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_opendir(fuse_req_t req, fuse_ino_t inum,
				  struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_readdir(fuse_req_t req, fuse_ino_t inum,
				  size_t size, off_t off,
				  struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_releasedir(fuse_req_t req, fuse_ino_t inum,
				     struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_fsyncdir(fuse_req_t req, fuse_ino_t inum, int datasync,
				   struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_statfs(fuse_req_t req, fuse_ino_t inum)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_setxattr(fuse_req_t req, fuse_ino_t inum,
				   const char *name, const char *value,
				   size_t size, int flags)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_getxattr(fuse_req_t req, fuse_ino_t inum,
				   const char *name, size_t size)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_listxattr(fuse_req_t req, fuse_ino_t inum, size_t size)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_removexattr(fuse_req_t req, fuse_ino_t inum,
				      const char *name)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_create(fuse_req_t req, fuse_ino_t parent,
				 const char *name, mode_t mode,
				 struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_write_buf(fuse_req_t req, fuse_ino_t inum,
				    struct fuse_bufvec *bufv, off_t off,
				    struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static void bcachefs_fuse_fallocate(fuse_req_t req, fuse_ino_t inum, int mode,
				    off_t offset, off_t length,
				    struct fuse_file_info *fi)
{
	struct bch_fs *c = fuse_req_userdata(req);
}

static const struct fuse_lowlevel_ops bcachefs_fuse_ops = {
	.destroy	= bcachefs_fuse_destroy,
	.lookup		= bcachefs_fuse_lookup,
	.getattr	= bcachefs_fuse_getattr,
	.setattr	= bcachefs_fuse_setattr,
	.readlink	= bcachefs_fuse_readlink,
	.mknod		= bcachefs_fuse_mknod,
	.mkdir		= bcachefs_fuse_mkdir,
	.unlink		= bcachefs_fuse_unlink,
	.rmdir		= bcachefs_fuse_rmdir,
	.symlink	= bcachefs_fuse_symlink,
	.rename		= bcachefs_fuse_rename,
	.link		= bcachefs_fuse_link,
	.open		= bcachefs_fuse_open,
	.read		= bcachefs_fuse_read,
	//.write	= bcachefs_fuse_write,
	.flush		= bcachefs_fuse_flush,
	.release	= bcachefs_fuse_release,
	.fsync		= bcachefs_fuse_fsync,
	.opendir	= bcachefs_fuse_opendir,
	.readdir	= bcachefs_fuse_readdir,
	.releasedir	= bcachefs_fuse_releasedir,
	.fsyncdir	= bcachefs_fuse_fsyncdir,
	.statfs		= bcachefs_fuse_statfs,
	.setxattr	= bcachefs_fuse_setxattr,
	.getxattr	= bcachefs_fuse_getxattr,
	.listxattr	= bcachefs_fuse_listxattr,
	.removexattr	= bcachefs_fuse_removexattr,
	.create		= bcachefs_fuse_create,

	/* posix locks: */
#if 0
	.getlk		= bcachefs_fuse_getlk,
	.setlk		= bcachefs_fuse_setlk,
#endif
	.write_buf	= bcachefs_fuse_write_buf,
	.fallocate	= bcachefs_fuse_fallocate,

};

int cmd_device_fusemount(int argc, char *argv[])
{
	struct bch_opts opts = bch2_opts_empty();
	struct bch_fs *c = NULL;
	const char *err;

	err = bch2_fs_open(argv + optind, argc - optind, opts, &c);
	if (err)
		die("error opening %s: %s", argv[optind], err);

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	char *mountpoint;
	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) < 0)
		die("fuse_parse_cmdline err: %m");

	struct fuse_chan *ch = fuse_mount(mountpoint, &args);
	if (!ch)
		die("fuse_mount err: %m");

	struct fuse_session *se =
		fuse_lowlevel_new(&args, &bcachefs_fuse_ops,
				  sizeof(bcachefs_fuse_ops), c);
	if (!se)
		die("fuse_lowlevel_new err: %m");

	if (fuse_set_signal_handlers(se) < 0)
		die("fuse_set_signal_handlers err: %m");

	fuse_session_add_chan(se, ch);

	int ret = fuse_session_loop(se);

	fuse_remove_signal_handlers(se);
	fuse_session_remove_chan(ch);
	fuse_session_destroy(se);
	fuse_unmount(mountpoint, ch);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
