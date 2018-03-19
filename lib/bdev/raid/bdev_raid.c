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
#include <isa-l/erasure_code.h>
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
	int parity_level;
	int num_drives;
	int num_parity;
	int num_data_drives_healthy;
	int num_faulty_drives;
	int drive_status[RAID_DRIVES_MAX];
	unsigned int stripe_size_blks;
	unsigned int stripe_size_bytes;
	int parity_size_bytes;
	int parity_size_blks;
	struct raid_drive drives[RAID_DRIVES_MAX];
	int ec_fd;

	struct {
		unsigned char *encode_matrix;
		unsigned char *decode_matrix;
		unsigned char *invert_matrix;
		unsigned char *g_tables;
	} ec;

	struct {
		uint64_t num_reads, num_writes;
		uint64_t num_bytes_read, num_bytes_write;
		uint64_t read_time, write_time;
	} stats;

	TAILQ_ENTRY(raid_bdev)	tailq;
};

struct raid_io_channel {
	struct spdk_poller		*poller;
	TAILQ_HEAD(, spdk_bdev_io)	io;
};


struct cmd_data {
	void *task;
};


static TAILQ_HEAD(, raid_bdev) g_raid_bdev_head;
static void *g_raid_read_buf;

static int
bdev_raid_destruct(void *ctx)
{
	struct raid_bdev *bdev = ctx;

	printf("Stats\n");
	printf("num_reads: %lu\n", bdev->stats.num_reads);
	printf("num_writes: %lu\n", bdev->stats.num_writes);

	for (int i = 0; i < bdev->num_drives; i++) {
		printf("Closing raid drive %d\n", i);
		if (bdev->drives[i].is_nvme == false) {
			if (bdev->drives[i].ch) 
				spdk_put_io_channel(bdev->drives[i].ch);
			spdk_bdev_close(bdev->drives[i].desc);
		} else {
			spdk_put_io_channel(bdev->drives[i].ch);
			printf("Skiping close for nvme drive %s\n", bdev->drives[i].name);
		}
	}

	TAILQ_REMOVE(&g_raid_bdev_head, bdev, tailq);
	free(bdev->ec.encode_matrix);
	free(bdev->ec.decode_matrix);
	free(bdev->ec.invert_matrix);
	free(bdev->ec.g_tables);
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

	uint8_t  err_list[RAID_DRIVES_MAX];
	char **enc_data;
};

static void
bdev_raid_read_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct bdev_raid_read_task *task = cb_arg;

	task->num_complete++;
	if (task->num_issued == task->num_complete) {
		spdk_bdev_io_complete(task->parent_io_cmd, bdev_io->status);
		free(task);
	}
	spdk_bdev_free_io(bdev_io);
}

#define MMAX RAID_DRIVES_MAX
#define KMAX RAID_DRIVES_MAX
#define TEST_SOURCES RAID_DRIVES_MAX

static void
bdev_raid_read_rec_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct cmd_data *cmd_data = cb_arg;
	struct bdev_raid_read_task *task = cmd_data->task;

	task->num_complete++;

	//printf("issued %d complete %d\n", task->num_issued, task->num_complete);

	if (task->num_issued == task->num_complete) {
        	uint8_t *a, b[MMAX * KMAX], c[MMAX * KMAX], d[MMAX * KMAX];
        	uint8_t g_tbls[KMAX * KMAX * 32];
        	uint8_t src_err_list[TEST_SOURCES], *recov[TEST_SOURCES], *src_in_err;
		struct raid_bdev *rbdev = SPDK_CONTAINEROF(task->parent_io_cmd->bdev,
				struct raid_bdev, bdev);
		int k = rbdev->num_drives - rbdev->num_parity;
		int i, r, j, nerrs = (rbdev->num_drives - rbdev->num_parity) - rbdev->num_data_drives_healthy;
		int r_idx = 0;
		uint8_t *temp_buffs[KMAX];

		src_in_err = task->err_list;
		a = rbdev->ec.encode_matrix;

		// Recover data

		for (i = 0, r = 0; i < k; i++) {
			if (task->err_list[i]) {
				src_err_list[r++] = i;
			}
		}

                for (i = 0, r = 0; i < k; i++, r++) {
                        while (src_in_err[r]) {
				temp_buffs[r_idx] = task->enc_data[r];
                                r++;
				r_idx++;
			}
                        recov[i] = task->enc_data[r];
                        for (j = 0; j < k; j++)
                                b[k * i + j] = a[k * r + j];
                }

                if (gf_invert_matrix(b, d, k) < 0) {
                        printf("BAD MATRIX\n");
			exit(-1);
                }

                for (i = 0; i < nerrs; i++)
                        for (j = 0; j < k; j++)
                                c[k * i + j] = d[k * src_err_list[i] + j];

                // Recover data
                ec_init_tables(k, nerrs, c, g_tbls);
                ec_encode_data(rbdev->bdev.blocklen, k, nerrs, g_tbls, recov, temp_buffs);
		spdk_bdev_io_complete(task->parent_io_cmd, bdev_io->status);
		//spdk_dma_free(task->enc_data[rbdev->num_drives - 1]);
		//spdk_dma_free(task->enc_data[rbdev->num_drives - 2]);
		
		for (int parity_idx = rbdev->num_drives - rbdev->num_parity;
				parity_idx < rbdev->num_drives; parity_idx++) {
			free(task->enc_data[parity_idx]);
		}
		free(task->enc_data);
		free(task);
	}

	free(cmd_data);
	spdk_bdev_free_io(bdev_io);

}


static void
bdev_raid_read(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);

	rbdev->stats.num_reads++;

	//printf("bdev_raid_read %lu %lu,\n", bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}


		struct bdev_raid_read_task *task = malloc(sizeof(*task));
		task->parent_io_cmd = bdev_io;
		task->parent_io_channel = ch;
		task->num_issued = bdev_io->u.bdev.num_blocks;
		task->num_complete = 0;
	

	uint64_t stripe_num, dev_num;
	if (rbdev->num_drives == rbdev->num_data_drives_healthy + rbdev->num_parity) {

	for (unsigned int i = 0; i < bdev_io->u.bdev.num_blocks; i++) {
		stripe_num = (bdev_io->u.bdev.offset_blocks + i) / rbdev->stripe_size_blks;
		dev_num = (bdev_io->u.bdev.offset_blocks + i) % rbdev->stripe_size_blks;

		//printf("reading block stripe %lu dev %lu\n", stripe_num, dev_num);
		int ret = spdk_bdev_read_blocks(rbdev->drives[dev_num].desc,
					rbdev->drives[dev_num].ch,
					bdev_io->u.bdev.iovs[0].iov_base + (i * rbdev->bdev.blocklen),
					stripe_num,
					1,
					bdev_raid_read_done,
					task);
		if (ret != 0) {
			printf("failed to issue read\n");
			exit(-1);
		}

	}
	} else {
		// Construct
		// No RMW
		char **enc_data = calloc(rbdev->num_drives, sizeof (char *));
		//char *enc_parity1 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);
		//char *enc_parity2 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);
		int to_issue = task->num_issued = rbdev->num_data_drives_healthy + rbdev->num_parity;
		int issued = 0;

		assert(bdev_io->u.bdev.iovcnt == 1);
		for (i = 0; i < rbdev->num_drives - rbdev->num_parity; i++) {
			enc_data[i] = bdev_io->u.bdev.iovs[0].iov_base + (i * rbdev->bdev.blocklen);
		}

		for (; i < rbdev->num_drives; i++) {
			enc_data[i] = malloc(rbdev->bdev.blocklen);
		}

		task->enc_data = enc_data;
		
		for (i = 0; i < rbdev->num_drives; i++) {
			if (rbdev->drive_status[i] != 0) {
				task->err_list[i] = 1;
				continue;
			} else {
				task->err_list[i] = 0;
			}
			uint64_t stripe_num = (bdev_io->u.bdev.offset_blocks)
				/ rbdev->stripe_size_blks;
			struct cmd_data *cmd_data = malloc(sizeof *cmd_data);
			memset(cmd_data, 0, sizeof(*cmd_data));
			cmd_data->task = task;
			
			int ret = spdk_bdev_read_blocks(rbdev->drives[i].desc,
					rbdev->drives[i].ch,
					enc_data[i],
					stripe_num,
					1,
					bdev_raid_read_rec_done, cmd_data);
			if (ret != 0) {
				printf("Failed to issue read\n");
				exit(-1);
			}
			issued++;
		}
		assert(to_issue == issued);
	}
}

struct bdev_raid_write_task {
	int num_issued;
	int num_complete;
	struct raid_io_channel *parent_io_channel;
	struct spdk_bdev_io    *parent_io_cmd;

	unsigned char **enc_data;
};


static void
bdev_raid_write_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct cmd_data *cmd_data = cb_arg;
	struct bdev_raid_write_task *task = cmd_data->task;

	task->num_complete++;

//	printf("num issued %d num complete %d\n", task->num_issued, task->num_complete);

	if (task->num_issued == task->num_complete) {
		struct raid_bdev *rbdev = SPDK_CONTAINEROF(task->parent_io_cmd->bdev,
				struct raid_bdev, bdev);
		spdk_bdev_io_complete(task->parent_io_cmd, bdev_io->status);
		for (int parity_idx = rbdev->num_drives - rbdev->num_parity;
				parity_idx < rbdev->num_drives; parity_idx++) {
			free(task->enc_data[parity_idx]);
		}
		free(task->enc_data);
		free(task);
	}

	free(cmd_data);
	spdk_bdev_free_io(bdev_io);
}

static void
bdev_raid_write(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);
	int num_to_issue, num_issued = 0;
	rbdev->stats.num_writes++;
	
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	struct bdev_raid_write_task *task = malloc(sizeof(*task));
	task->parent_io_cmd = bdev_io;
	task->parent_io_channel = ch;
       num_to_issue = task->num_issued = rbdev->num_data_drives_healthy + rbdev->num_parity;
	task->num_complete = 0;

	//printf("Write : offset %lu blocks %lu\n", bdev_io->u.bdev.offset_blocks,
	//		bdev_io->u.bdev.num_blocks);

		// N Data - 2 parity
	if (bdev_io->u.bdev.offset_blocks % rbdev->stripe_size_blks == 0 &&
			bdev_io->u.bdev.num_blocks == rbdev->stripe_size_blks) {
		// No RMW
		unsigned char **enc_data = malloc(sizeof (void *) * (rbdev->num_drives));
		//char *enc_parity1 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);
		//char *enc_parity2 = spdk_dma_malloc(rbdev->bdev.blocklen, 0, NULL);

		assert(bdev_io->u.bdev.iovcnt == 1);
		for (i = 0; i < rbdev->num_drives - rbdev->num_parity; i++) {
			enc_data[i] = bdev_io->u.bdev.iovs[0].iov_base + (i * rbdev->bdev.blocklen);
		}

		for (; i < rbdev->num_drives; i++) {
			enc_data[i] = malloc(rbdev->bdev.blocklen);
		}
		
		ec_encode_data(rbdev->bdev.blocklen, rbdev->num_drives - rbdev->num_parity,
				rbdev->num_parity, rbdev->ec.g_tables, enc_data,
				&enc_data[rbdev->num_drives - rbdev->num_parity]);

		task->enc_data = enc_data;
		for (i = 0; i < rbdev->num_drives; i++) {
			if (rbdev->drive_status[i] != 0) {
				continue;
			}
			uint64_t stripe_num = (bdev_io->u.bdev.offset_blocks)
				/ rbdev->stripe_size_blks;
			struct cmd_data *cmd_data = malloc(sizeof *cmd_data);
			memset(cmd_data, 0, sizeof(*cmd_data));
			cmd_data->task = task;
			
			//printf("writing block stripe %lu dev %lu crc %d\n", stripe_num, i,
			//		crc32_ieee(0, enc_data[i], rbdev->bdev.blocklen));
			int ret = spdk_bdev_write_blocks(rbdev->drives[i].desc,
					rbdev->drives[i].ch,
					enc_data[i],
					stripe_num,
					1,
					bdev_raid_write_done, cmd_data);
			if (ret != 0) {
				printf("Failed to issue write\n");
				exit(-1);
			}
			num_issued++;
		}
		assert(num_issued == num_to_issue);

	} else {
		printf("unsupported\n");
		assert(0);
	}
}

static void
bdev_raid_write_zeroes(struct raid_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	int i = 0;
	struct raid_bdev *rbdev = SPDK_CONTAINEROF(bdev_io->bdev, struct raid_bdev, bdev);
	
	
	if (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks >
			rbdev->bdev.blockcnt) {
		printf("out of bounds\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	struct bdev_raid_write_task *task = malloc(sizeof(*task));
	task->parent_io_cmd = bdev_io;
	task->parent_io_channel = ch; 
	task->num_issued = rbdev->num_drives;
	task->num_complete = 0;

	for (i = 0; i < rbdev->num_drives; i++) {
		//printf("issuing write zeroes to base drive offset %u num_blks %u\n",
				//bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
		int ret = spdk_bdev_write_zeroes(rbdev->drives[i].desc, rbdev->drives[i].ch,
				bdev_io->u.bdev.offset_blocks * rbdev->bdev.blocklen,
				bdev_io->u.bdev.num_blocks * rbdev->bdev.blocklen,
				bdev_raid_write_done, task);
		if (ret != 0) {
			printf("Failed to issue write zeros\n");
			exit(-1);
		}
	}
}


static void
bdev_raid_submit_request(struct spdk_io_channel *_ch, struct spdk_bdev_io *bdev_io)
{
	struct raid_io_channel *ch = spdk_io_channel_get_ctx(_ch);

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		if (bdev_io->u.bdev.iovs[0].iov_base == NULL) {
			spdk_bdev_io_get_buf(bdev_io, bdev_raid_read,
				     bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);
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
		int parity_level, int num_drives, const char **drives,
		int num_faults, int *faulty_drives)
{
	struct raid_bdev *bdev;
	int rc, fault_idx = 0;
	int num_parity;

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


	if (parity_level > 0 && parity_level <= 3) {
		bdev->num_parity = parity_level;
		num_parity = parity_level;
	} else {
		printf("Unsupported");
		exit(-1);
	}

	int m = num_drives;
	int k = num_drives - num_parity;
	unsigned char *encode_matrix = malloc(m * k);
	unsigned char *decode_matrix = malloc(m * k);
	unsigned char *invert_matrix = malloc(m * k);
	unsigned char *g_tables = malloc(m * k * 32);

	if (encode_matrix == NULL ||
			decode_matrix == NULL ||
			invert_matrix == NULL ||
			g_tables == NULL ) {
		printf("failed to allocate memory");
		exit(-1);
	}

	gf_gen_rs_matrix(encode_matrix, m, k);
	ec_init_tables(k, m - k, &encode_matrix[k * k], g_tables);

	bdev->ec.encode_matrix = encode_matrix;
	bdev->ec.decode_matrix = decode_matrix;
	bdev->ec.invert_matrix = invert_matrix;
	bdev->ec.g_tables = g_tables;
	bdev->stripe_size_blks = num_drives - num_parity;
	bdev->stripe_size_bytes = (num_drives - num_parity) * block_size;
	bdev->parity_size_bytes = num_parity * block_size;
	bdev->parity_size_blks = num_parity;
	bdev->num_data_drives_healthy = num_drives - num_parity - num_faults;

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
		bdev->drives[i].ch = NULL;
		if (i == faulty_drives[fault_idx]) {
			printf("Marking drive %d as faulty\n", i);
			bdev->drive_status[i] = 1;
			fault_idx++;
		} else {
			bdev->drive_status[i] = 0;
		}
	}

	bdev->num_drives = num_drives;
	bdev->parity_level = parity_level;
	bdev->num_faulty_drives = num_faults;


	printf("Create RAID Device: Name %s\n", bdev->bdev.name);
	printf("Create RAID Device: Level %d\n", bdev->parity_level);
	printf("Create RAID Device: Drives %d\n", bdev->num_drives);
	printf("Create RAID Device: Faulty Drives %d\n", bdev->num_faulty_drives);
	printf("Create RAID Device: Healthy Data Drives %d\n", bdev->num_data_drives_healthy);

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
	int num_drives = 0, parity_level = -1;
	const char *drives[RAID_DRIVES_MAX];
	int faulty_drives[RAID_DRIVES_MAX];
	int num_faults = 0;

	for (i = 0; i < RAID_DRIVES_MAX; i++) {
		faulty_drives[i] = -1;
	}

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
	if ((val = spdk_conf_section_get_nval(sp, "Dev", 0)) != NULL) {
		name = spdk_conf_section_get_nmval(sp, "Dev", i, 0);
		if (name == NULL) {
			SPDK_ERRLOG("Raid entry %d: Name must be provided\n", i);
		}

		val = spdk_conf_section_get_nmval(sp, "Dev", i, 1);
		if (val == NULL) {
			SPDK_ERRLOG("Raid entry %d: Size in MB must be provided\n", i);
		}

		errno = 0;
		size_in_mb = strtoull(val, NULL, 10);
		if (errno) {
			SPDK_ERRLOG("Raid entry %d: Invalid size in MB %s\n", i, val);
		}

		val = spdk_conf_section_get_nmval(sp, "Dev", i, 2);
		if (val == NULL) {
			block_size = 512;
		} else {
			errno = 0;
			block_size = (int)strtol(val, NULL, 10);
			if (errno) {
				SPDK_ERRLOG("Raid entry %d: Invalid block size %s\n", i, val);
				rc = EINVAL;
				goto end;
			}
		}

		num_blocks = size_in_mb * (1024 * 1024) / block_size;
		printf("Dev %d\n", i);
	} else {
		printf("Dev config not provided\n");
		exit(-1);
	}

	if ((val = spdk_conf_section_get_nval(sp, "Base", 0)) != NULL) {

		val = spdk_conf_section_get_nmval(sp, "Base", 0, 0);
		if (val == NULL) {
			printf("Raid level not provided");
			rc = EINVAL;
			goto err;
		} else {
			errno = 0;
			parity_level = (int)strtol(val, NULL, 10);
			if (errno) {
				SPDK_ERRLOG("Raid entry %d: Invalid Raid level %s\n", i, val);
				rc = EINVAL;
				goto err;
			}

			printf("parity Level %d\n", parity_level);
		}

		val = spdk_conf_section_get_nmval(sp, "Base", 0, 1);
		if (val == NULL) {
			printf("Number of Drives not provided");
			rc = EINVAL;
			goto err;
		} else {
			errno = 0;
			num_drives = (int)strtol(val, NULL, 10);
			if (errno) {
				SPDK_ERRLOG("Raid entry %d: Invalid Number of drive %s\n", i, val);
				rc = EINVAL;
				goto err;
			}
			printf("Number of Drives in the RAID Group %d\n", num_drives);
		}

		for (int j = 0; j < num_drives; j++) {
			val = spdk_conf_section_get_nmval(sp, "Base", 0, 2 + j);
			if (val == NULL) {
				printf("Drive name not provided");
				rc = EINVAL;
				goto err;
			} else {
				errno = 0;
				drives[j] = val;
			}
		}
	} else {
		printf("Base config not provided\n");
		exit(-1);
	}

	if ((val = spdk_conf_section_get_nval(sp, "Fault", 0)) != NULL) {
		val = spdk_conf_section_get_nmval(sp, "Fault", 0, 0);
		if (val == NULL) {
			printf("Num faulty drives not provided");
			rc = EINVAL;
			goto err;
		} else {
			errno = 0;
			num_faults = (int)strtol(val, NULL, 10);
			if (errno) {
				SPDK_ERRLOG("Raid entry %d: Invalid fault %s\n", i, val);
				rc = EINVAL;
				goto err;
			}

			printf("Num Faulty Drives %d\n", num_faults);
		}

		int k = 0;
		for (int j = 0; j < num_faults; j++) {
			val = spdk_conf_section_get_nmval(sp, "Fault", 0, 1 + j);
			if (val == NULL) {
				printf("Drive num not provided");
				rc = EINVAL;
				goto err;
			} else {
				errno = 0;
				faulty_drives[k] = (int)strtol(val, NULL, 10);
				k++;
				if (errno) {
					SPDK_ERRLOG("Raid entry %d: Invalid fault %s\n", i, val);
					rc = EINVAL;
					goto err;
				}
			}
		}
	} else {
		printf("Fault config not provided\n");
	}


	for (i = 0; i < num_drives; i++) {
		printf("Raid group Drive[%d] %s\n", i, drives[i]);
	}

	bdev = create_raid_bdev(name, num_blocks, block_size, parity_level, num_drives, drives, num_faults, faulty_drives);
	if (bdev == NULL) {
		SPDK_ERRLOG("Could not create raid bdev\n");
		rc = EINVAL;
		goto err;
	}

end:
	return rc;

err:
	exit(-1);
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
