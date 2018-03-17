/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <malloc.h>
#include <string.h>
#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/conf.h"
#include "spdk/env.h"
#include "spdk/io_channel.h"

#include "spdk_internal/bdev.h"
#include "spdk_internal/log.h"

#include "bdev_raid.h"
#include "spdk/util.h"

// erasure code
#include <isa-l/raid.h>
#include <isa-l/crc.h>
SPDK_DECLARE_BDEV_MODULE(raid);

#define RAID_DRIVES_MAX (8)
struct raid_drive {
	char name[16];
	struct spdk_bdev_desc *desc;
	struct spdk_bdev *bdev;
	struct spdk_io_channel *ch;
	bool is_nvme;
};

struct raid_bdev {
	struct spdk_bdev	bdev;
	int raid_level;
	int num_drives;
	unsigned int stripe_size_blks;
	unsigned int stripe_size_bytes;
	int parity_size_bytes;
	int parity_size_blks;
	struct raid_drive drives[RAID_DRIVES_MAX];
	int ec_fd;
	TAILQ_ENTRY(raid_bdev)	tailq;
};

struct raid_io_channel {
	struct spdk_poller		*poller;
	TAILQ_HEAD(, spdk_bdev_io)	io;
};

static TAILQ_HEAD(, raid_bdev) g_raid_bdev_head;
static void *g_raid_read_buf;

static int
bdev_raid_destruct(void *ctx)
{
	struct raid_bdev *bdev = ctx;

	for (int i = 0; i < bdev->num_drives; i++) {
			printf("Closing raid drive %d\n", i);
			if (bdev->drives[i].is_nvme == false) {
				spdk_put_io_channel(bdev->drives[i].ch);
				spdk_bdev_close(bdev->drives[i].desc);
			} else {
				spdk_put_io_channel(bdev->drives[i].ch);
				printf("Skiping close for nvme drive %s\n", bdev->drives[i].name);
			}
		}

	TAILQ_REMOVE(&g_raid_bdev_head, bdev, tailq);
	free(bdev->bdev.name);
	spdk_dma_free(bdev);

	return 0;
}

struct bdev_raid_read_task {
	struct raid_io_channel *parent_io_channel;
	struct spdk_bdev_io    *parent_io_cmd;
	int num_issued;
	int num_complete;
	uint64_t stripe_num;
	uint64_t dev_num;
};

static void
bdev_raid_read_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct bdev_raid_read_task *task = cb_arg;

	task->num_complete++;
	//printf("task->num_issued %d complete %d crc %d\n",
			//task->num_issued, task->num_complete, crc32_ieee(0, bdev_io->u.bdev.iovs[0].iov_base, 512));
	if (task->num_issued == task->num_complete) {
		spdk_bdev_io_complete(task->parent_io_cmd, bdev_io->status);

		 //TAILQ_INSERT_TAIL(&task->parent_io_channel->io, task->parent_io_cmd,
		//	module_link);
		spdk_dma_free(task);
	}
	spdk_bdev_free_io(bdev_io);
}

static void
bdev_raid_read(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0, ret;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);

	//printf("bdev_raid_read %lu %lu,\n", bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	struct bdev_raid_read_task *task = spdk_dma_malloc(sizeof(*task), 0, NULL);
	task->parent_io_cmd = bdev_io;
	task->parent_io_channel = ch;
	task->num_issued = bdev_io->u.bdev.num_blocks;
	task->num_complete = 0;
	struct spdk_thread *th = spdk_get_thread();
	//printf("read thread %s\n", spdk_thread_get_name(th));



	uint64_t stripe_num, dev_num;
	switch (rbdev->raid_level) {
	case 6:
		for (i = 0; i < bdev_io->u.bdev.num_blocks; i++) {
			stripe_num = (bdev_io->u.bdev.offset_blocks + i) / rbdev->stripe_size_blks;
			dev_num = (bdev_io->u.bdev.offset_blocks + i) % rbdev->stripe_size_blks;

			//printf("reading block stripe %lu dev %lu\n", stripe_num, dev_num);
			ret = spdk_bdev_read_blocks(rbdev->drives[dev_num].desc,
						rbdev->drives[dev_num].ch,
						bdev_io->u.bdev.iovs[0].iov_base + (i * rbdev->bdev.blocklen),
						stripe_num,
						1,
						bdev_raid_read_done,
						task);

			assert(ret == 0);
			//printf("ret = %d\n", ret);
		}
		break;
	default:
		assert(0);
		break;
	}
}

struct bdev_raid_write_task {
	int num_issued;
	int num_complete;
	struct raid_io_channel *parent_io_channel;
	struct spdk_bdev_io    *parent_io_cmd;
};


struct cmd_data {
	struct bdev_raid_write_task *task;
	char *buf;
	bool free_buf;
};

static void
bdev_raid_write_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct cmd_data *cmd_data = cb_arg;
	struct bdev_raid_write_task *task = cmd_data->task;

	task->num_complete++;

	//printf("num issued %d num complete %d\n", task->num_issued, task->num_complete);

	if (task->num_issued == task->num_complete) {

	spdk_bdev_io_complete(task->parent_io_cmd, bdev_io->status);

	//TAILQ_INSERT_TAIL(&task->parent_io_channel->io, task->parent_io_cmd,
	//		module_link);

		spdk_dma_free(task);
	}

	if (cmd_data->free_buf) {
		spdk_dma_free(cmd_data->buf);
	}
	spdk_dma_free(cmd_data);
	spdk_bdev_free_io(bdev_io);
}

static void
bdev_raid_write(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0, ret, j = 0;
	uint64_t frag_len;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);
	
	
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	struct bdev_raid_write_task *task = spdk_dma_malloc(sizeof(*task), 0, NULL);
	task->parent_io_cmd = bdev_io;
	task->parent_io_channel = ch; 
	task->num_issued = rbdev->num_drives;
	task->num_complete = 0;

	//printf("Write : offset %lu blocks %lu\n", bdev_io->u.bdev.offset_blocks,
	//		bdev_io->u.bdev.num_blocks);

	switch (rbdev->raid_level) {
	case 6:
		// N Data - 2 parity
		if (bdev_io->u.bdev.offset_blocks % rbdev->stripe_size_blks == 0 &&
				bdev_io->u.bdev.num_blocks == rbdev->stripe_size_blks) {
			// No RMW
			void **enc_data = spdk_dma_malloc(sizeof (void *) * (rbdev->num_drives), 0, NULL);
			char *enc_parity1 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);
//				memalign(4096, rbdev->bdev.blocklen);
			char *enc_parity2 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);
//			char *enc_parity2 = memalign(4096, rbdev->bdev.blocklen);
			assert(enc_parity1 && enc_parity2);

			assert(bdev_io->u.bdev.iovcnt == 1);
			for (i = 0; i < rbdev->num_drives - 2; i++) {
				enc_data[i] = bdev_io->u.bdev.iovs[0].iov_base + (i * rbdev->bdev.blocklen);
			}
			enc_data[rbdev->num_drives - 2] = enc_parity1;
			enc_data[rbdev->num_drives - 1] = enc_parity2;

			pq_gen(rbdev->num_drives, rbdev->bdev.blocklen, enc_data);

			for (i = 0; i < rbdev->num_drives; i++) {
				uint64_t stripe_num = (bdev_io->u.bdev.offset_blocks)
					/ rbdev->stripe_size_blks;
				struct cmd_data *cmd_data = spdk_dma_malloc(sizeof *cmd_data, 0, NULL);
				cmd_data->task = task;
				if (i == rbdev->num_drives - 2) {
					cmd_data->buf = enc_parity1;
					cmd_data->free_buf = true;
				} else if (i == rbdev->num_drives - 1) {
					cmd_data->buf = enc_parity2;
					cmd_data->free_buf = true;
				}
				
				//printf("writing block stripe %lu dev %lu crc %d\n", stripe_num, i,
				//		crc32_ieee(0, enc_data[i], rbdev->bdev.blocklen));
				ret = spdk_bdev_write_blocks(rbdev->drives[i].desc,
						rbdev->drives[i].ch,
						enc_data[i],
						stripe_num,
						1,
						bdev_raid_write_done, cmd_data);
				assert(ret == 0);
			}

		} else {
			printf("unsupported\n");
			assert(0);
		}
		break;
	default:
		printf("unsupported\n");
		assert(0);
		break;
	}


						


#if 0
	for (i = 0; i < rbdev->num_drives; i++) {
		//printf("issuing write to base drive\n");
		//printf("issuing write to base drive offset %u num_blks %u\n",
			//	bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);

		ret = spdk_bdev_writev(rbdev->drives[i].desc, rbdev->drives[i].ch,
				bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
				bdev_io->u.bdev.offset_blocks * rbdev->bdev.blocklen,
				bdev_io->u.bdev.num_blocks * rbdev->bdev.blocklen,
				bdev_raid_write_done, task);
		assert(ret == 0);
	}
#endif
}

static void
bdev_raid_write_zeroes(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0, ret;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);
	
	
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	struct bdev_raid_write_task *task = spdk_dma_malloc(sizeof(*task), 0, NULL);
	task->parent_io_cmd = bdev_io;
	task->parent_io_channel = ch; 
	task->num_issued = rbdev->num_drives;
	task->num_complete = 0;

	for (i = 0; i < rbdev->num_drives; i++) {
		//printf("issuing write zeroes to base drive offset %u num_blks %u\n",
				//bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
		ret = spdk_bdev_write_zeroes(rbdev->drives[i].desc, rbdev->drives[i].ch,
				bdev_io->u.bdev.offset_blocks * rbdev->bdev.blocklen,
				bdev_io->u.bdev.num_blocks * rbdev->bdev.blocklen,
				bdev_raid_write_done, task);
		assert(ret == 0);
	}
}


static void
bdev_raid_submit_request(struct spdk_io_channel *_ch, struct spdk_bdev_io *bdev_io)
{
	struct raid_io_channel *ch = spdk_io_channel_get_ctx(_ch);

	//printf("Got command bdev_raid_submit_request\n");
	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
	//	SPDK_NOTICELOG("Submitted read request\n");
		if (bdev_io->u.bdev.iovs[0].iov_base == NULL) {
			spdk_bdev_io_get_buf(bdev_io, bdev_raid_read,
				     bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);

//			assert(bdev_io->u.bdev.iovcnt == 1);
//			bdev_io->u.bdev.iovs[0].iov_base = g_raid_read_buf;
//			bdev_io->u.bdev.iovs[0].iov_len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen;
		} else {
			bdev_raid_read(ch, bdev_io);
		}
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		bdev_raid_write(ch, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		bdev_raid_write_zeroes(ch, bdev_io);
	case SPDK_BDEV_IO_TYPE_RESET:
		assert(0);
		SPDK_NOTICELOG("Submitted write reset request\n");
		TAILQ_INSERT_TAIL(&ch->io, bdev_io, module_link);
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	default:
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		break;
	}
}

static bool
bdev_raid_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_RESET:
		return true;
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	default:
		return false;
	}
}

static struct spdk_io_channel *
bdev_raid_get_io_channel(void *ctx)
{
	printf("Get IO Channel\n");
	struct raid_bdev *rbdev, *tmp;

	TAILQ_FOREACH_SAFE(rbdev, &g_raid_bdev_head, tailq, tmp) {
	for (int i = 0 ; i < rbdev->num_drives; i++) {
		rbdev->drives[i].ch =
			spdk_bdev_get_io_channel(rbdev->drives[i].desc);
	}
	}

	return spdk_get_io_channel(&g_raid_bdev_head);
}

static const struct spdk_bdev_fn_table raid_fn_table = {
	.destruct		= bdev_raid_destruct,
	.submit_request		= bdev_raid_submit_request,
	.io_type_supported	= bdev_raid_io_type_supported,
	.get_io_channel		= bdev_raid_get_io_channel,
};

struct spdk_bdev *
create_raid_bdev(const char *name, uint64_t num_blocks, uint32_t block_size,
		int raid_level, int num_drives, const char **drives)
{
	struct raid_bdev *bdev;
	int rc;

	if (block_size % 512 != 0) {
		SPDK_ERRLOG("Block size %u is not a multiple of 512.\n", block_size);
		return NULL;
	}

	if (num_blocks == 0) {
		SPDK_ERRLOG("Disk must be more than 0 blocks\n");
		return NULL;
	}

	
	bdev = spdk_dma_zmalloc(sizeof(*bdev), 0, NULL);
	if (!bdev) {
		SPDK_ERRLOG("could not allocate raid_bdev\n");
		return NULL;
	}


	switch (raid_level) {
		case 6:
#if 0
			ec_args.k = num_drives - 2;
			ec_args.m = 2;
			ec_args.w = 16;
			ec_args.hd = 2;
			ec_args.ct = CHKSUM_NONE;
#endif
			bdev->stripe_size_blks = num_drives - 2;
			bdev->stripe_size_bytes = (num_drives - 2) * block_size;
			bdev->parity_size_bytes = 2 * block_size;
			bdev->parity_size_blks = 2;
			break;
		default:
			assert(0);
			break;
	}

	bdev->bdev.name = strdup(name);
	if (!bdev->bdev.name) {
		spdk_dma_free(bdev);
		return NULL;
	}
	bdev->bdev.product_name = "Raid disk";

	bdev->bdev.write_cache = 0;
	bdev->bdev.blocklen = block_size;
	bdev->bdev.blockcnt = num_blocks;

	bdev->bdev.ctxt = bdev;
	bdev->bdev.fn_table = &raid_fn_table;
	bdev->bdev.module = SPDK_GET_BDEV_MODULE(raid);
	struct spdk_thread *th = spdk_get_thread();
	printf("raid thread %s\n", spdk_thread_get_name(th));

	for (int i = 0; i < num_drives; i++) {
		// Find the Drive
		bdev->drives[i].bdev = spdk_bdev_get_by_name(drives[i]);
		if (bdev->drives[i].bdev == NULL) {
			SPDK_ERRLOG("Could not find %s drive\n", drives[i]);
			break;
		} else {
			SPDK_NOTICELOG("Found drive %s\n", drives[i]);
		}

		if (strncasecmp(drives[i], "nvme", 4) == 0) {
			printf("Assuming drive %s is nvme drive\n", drives[i]);
			bdev->drives[i].is_nvme = true;
		} else {
			bdev->drives[i].is_nvme = false;
		}

		// Open the Drive
		int ret = spdk_bdev_open(bdev->drives[i].bdev, true, NULL, NULL,
				&bdev->drives[i].desc);

		if (ret) {
			SPDK_ERRLOG("Unable to open %s err %d\n", drives[i],
					ret);
			break;
		}
		strcpy(bdev->drives[i].name, drives[i]);
//		bdev->drives[i].ch = spdk_bdev_get_io_channel(bdev->drives[i].desc);
	}

	bdev->num_drives = num_drives;
	bdev->raid_level = raid_level;



	rc = spdk_bdev_register(&bdev->bdev);
	if (rc) {
		free(bdev->bdev.name);
		spdk_dma_free(bdev);
		return NULL;
	}

	TAILQ_INSERT_TAIL(&g_raid_bdev_head, bdev, tailq);

	return &bdev->bdev;
}

static void
raid_io_poll(void *arg)
{
	struct raid_io_channel		*ch = arg;
	TAILQ_HEAD(, spdk_bdev_io)	io;
	struct spdk_bdev_io		*bdev_io;

	TAILQ_INIT(&io);
	TAILQ_SWAP(&ch->io, &io, spdk_bdev_io, module_link);

	while (!TAILQ_EMPTY(&io)) {
		bdev_io = TAILQ_FIRST(&io);
		TAILQ_REMOVE(&io, bdev_io, module_link);
//		SPDK_NOTICELOG("Completed request %d\n", bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	}
}

static int
raid_bdev_create_cb(void *io_device, void *ctx_buf)
{
	struct raid_io_channel *ch = ctx_buf;

	TAILQ_INIT(&ch->io);
	ch->poller = spdk_poller_register(raid_io_poll, ch, 0);

	return 0;
}

static void
raid_bdev_destroy_cb(void *io_device, void *ctx_buf)
{
	struct raid_io_channel *ch = ctx_buf;

	printf("raid_bdev_destroy_cb...\n");
	spdk_poller_unregister(&ch->poller);
}

static int
bdev_raid_initialize(void)
{
	struct spdk_conf_section *sp = spdk_conf_find_section(NULL, "Raid");
	uint64_t size_in_mb, num_blocks = -1;
	int block_size = 0, i, rc = 0;
	struct spdk_bdev *bdev;
	const char *name = NULL, *val;
	int num_drives = 0, raid_level = -1;
	const char *drives[RAID_DRIVES_MAX];

	printf("Finding Raid Disks\n");

	TAILQ_INIT(&g_raid_bdev_head);

	/*
	 * This will be used if upper layer expects us to allocate the read buffer.
	 *  Instead of using a real rbuf from the bdev pool, just always point to
	 *  this same zeroed buffer.
	 */
	g_raid_read_buf = spdk_dma_zmalloc(SPDK_BDEV_LARGE_BUF_MAX_SIZE, 0, NULL);

	/*
	 * We need to pick some unique address as our "io device" - so just use the
	 *  address of the global tailq.
	 */
	spdk_io_device_register(&g_raid_bdev_head, raid_bdev_create_cb, raid_bdev_destroy_cb,
				sizeof(struct raid_io_channel));

	if (sp == NULL) {
		goto end;
	}

	i = 0;
	while (i < 2) {
		val = spdk_conf_section_get_nval(sp, "Dev", i);
		if (val != NULL) {
			name = spdk_conf_section_get_nmval(sp, "Dev", i, 0);
			if (name == NULL) {
				SPDK_ERRLOG("Raid entry %d: Name must be provided\n", i);
				continue;
			}

			val = spdk_conf_section_get_nmval(sp, "Dev", i, 1);
			if (val == NULL) {
				SPDK_ERRLOG("Raid entry %d: Size in MB must be provided\n", i);
				continue;
			}

			errno = 0;
			size_in_mb = strtoull(val, NULL, 10);
			if (errno) {
				SPDK_ERRLOG("Raid entry %d: Invalid size in MB %s\n", i, val);
				continue;
			}

			val = spdk_conf_section_get_nmval(sp, "Dev", i, 2);
			if (val == NULL) {
				block_size = 512;
			} else {
				errno = 0;
				block_size = (int)strtol(val, NULL, 10);
				if (errno) {
					SPDK_ERRLOG("Raid entry %d: Invalid block size %s\n", i, val);
					continue;
				}
			}

			num_blocks = size_in_mb * (1024 * 1024) / block_size;

		} else {
			val = spdk_conf_section_get_nval(sp, "Base", 0);

			if (val != NULL) {
				val = spdk_conf_section_get_nmval(sp, "Base", 0, 0);
				if (val == NULL) {
					printf("Raid level not provided");
					rc = EINVAL;
					goto end;
				} else {
					errno = 0;
					raid_level = (int)strtol(val, NULL, 10);
					if (errno) {
						SPDK_ERRLOG("Raid entry %d: Invalid Raid level %s\n", i, val);
						rc = EINVAL;
						goto end;
					}

					printf("Raid Level %d\n", raid_level);
				}

				val = spdk_conf_section_get_nmval(sp, "Base", 0, 1);
				if (val == NULL) {
					printf("Number of Drives not provided");
					rc = EINVAL;
					goto end;
				} else {
					errno = 0;
					num_drives = (int)strtol(val, NULL, 10);
					if (errno) {
						SPDK_ERRLOG("Raid entry %d: Invalid Number of drive %s\n", i, val);
						rc = EINVAL;
						goto end;
					}
					printf("Number of Drives in the RAID Group %d\n", num_drives);
				}

				for (int j = 0; j < num_drives; j++) {
					val = spdk_conf_section_get_nmval(sp, "Base", 0, 2 + j);
					if (val == NULL) {
						printf("Drive name not provided");
						rc = EINVAL;
						goto end;
					} else {
						errno = 0;
						drives[j] = val;
					}
				}
			} else {
				break;
			}
		}

		printf("i = %d \n", i);
		i++;
	}


	for (i = 0; i < num_drives; i++) {
		printf("Raid group Drive[%d] %s\n", i, drives[i]);
	}

	bdev = create_raid_bdev(name, num_blocks, block_size, raid_level, num_drives, drives);
	if (bdev == NULL) {
		SPDK_ERRLOG("Could not create raid bdev\n");
		rc = EINVAL;
		goto end;
	}

end:
	return rc;
}

static void
bdev_raid_finish(void)
{
	struct raid_bdev *bdev, *tmp;

	printf("bdev_raid_finish...\n");

	TAILQ_FOREACH_SAFE(bdev, &g_raid_bdev_head, tailq, tmp) {
		printf("Closing rbdev\n");
		for (int i = 0; i < bdev->num_drives; i++) {
			printf("Closing raid drive %d\n", i);
			spdk_bdev_close(bdev->drives[i].desc);
		}
		spdk_bdev_unregister(&bdev->bdev, NULL, NULL);
	}
}

static void
bdev_raid_get_spdk_running_config(FILE *fp)
{
	struct raid_bdev *bdev;
	uint64_t raid_bdev_size;

	fprintf(fp, "\n[Raid]\n");

	TAILQ_FOREACH(bdev, &g_raid_bdev_head, tailq) {
		raid_bdev_size = bdev->bdev.blocklen * bdev->bdev.blockcnt;
		raid_bdev_size /= (1024 * 1024);
		fprintf(fp, "  %s %" PRIu64 " %d\n",
			bdev->bdev.name, raid_bdev_size, bdev->bdev.blocklen);
	}
}

SPDK_BDEV_MODULE_REGISTER(raid, bdev_raid_initialize, bdev_raid_finish,
			  bdev_raid_get_spdk_running_config, NULL, NULL)

SPDK_LOG_REGISTER_COMPONENT("bdev_raid", SPDK_LOG_BDEV_RAID)
