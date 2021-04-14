/*
 * Copyright (c) 2017 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <psample.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#define min(a, b) (((a) > (b)) ? (b) : (a))
#define DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))
#define HD_LINE_BYTES 16

static char printable(char c)
{
	return isprint((int) c) ? c : '.';
}

static void hexdump_buf(__u8 *msg, int len)
{
	int index;
	int line;
	int i;

	for (line = 0; line < DIV_ROUND_UP(len, HD_LINE_BYTES); line++) {
		int line_chars;

		printf("0x%04hhx:  ", line * HD_LINE_BYTES);

		line_chars = min(HD_LINE_BYTES, len - line * HD_LINE_BYTES);
		for (i = 0; i < line_chars; i++) {
			index = line * HD_LINE_BYTES + i;
			printf("%02hhx ", msg[index]);
		}

		for (i = 0; i < (HD_LINE_BYTES - line_chars); i++)
			printf("   ");

		printf(" ");
		for (i = 0; i < line_chars; i++) {
			index = line * HD_LINE_BYTES + i;
			printf("%c", printable(msg[index]));
		}

		printf("\n");
	}
}

static int show_group_cb(const struct psample_group *group, void *data)
{
	bool *first_run = (bool *)data;

	if (*first_run) {
		*first_run = false;
		printf("%-15s %-15s %-15s\n", "Group Num", "Refcount",
		       "Group Seq");
	}

	printf("%-15d %-15d %-15d\n", group->num, group->refcount, group->seq);
	return 0;
}

static int show_message_cb(const struct psample_msg *msg, void *data)
{
	bool verbose = *(bool *) data;

	if (psample_msg_group_exist(msg))
		printf("group %d ", psample_msg_group(msg));
	if (psample_msg_iif_exist(msg))
		printf("in-ifindex %d ", psample_msg_iif(msg));
	if (psample_msg_oif_exist(msg))
		printf("out-ifindex %d ", psample_msg_oif(msg));
	if (psample_msg_origsize_exist(msg))
		printf("origsize %d ", psample_msg_origsize(msg));
	if (psample_msg_rate_exist(msg))
		printf("sample-rate %d ", psample_msg_rate(msg));
	if (psample_msg_seq_exist(msg))
		printf("seq %d ", psample_msg_seq(msg));
	if (psample_msg_out_tc_exist(msg))
		printf("out-tc %u ", psample_msg_out_tc(msg));
	if (psample_msg_out_tc_occ_exist(msg))
		printf("out-tc-occ %llu ", psample_msg_out_tc_occ(msg));
	if (psample_msg_latency_exist(msg))
		printf("latency %llu ", psample_msg_latency(msg));
	if (psample_msg_timestamp_exist(msg)) {
		time_t tv_sec;
		struct tm *tm;
		char *tstr;
		__u64 ts;

		ts = psample_msg_timestamp(msg);
		tv_sec = ts / 1000000000;
		tm = localtime(&tv_sec);

		tstr = asctime(tm);
		tstr[strlen(tstr) - 1] = 0;
		printf("timestamp %s %09" PRId64 " nsec ", tstr,
		       ts % 1000000000);
	}
	if (psample_msg_proto_exist(msg))
		printf("protocol 0x%x ", psample_msg_proto(msg));

	if (verbose && psample_msg_data_exist(msg)) {
		int data_len = psample_msg_data_len(msg);

		printf("data len %d\n", data_len);
		hexdump_buf(psample_msg_data(msg), data_len);
	}

	printf("\n");
	fflush(stdout);
	return 0;
}

static int show_config_cb(const struct psample_config *config, void *data)
{
	bool verbose = *(bool *) data;

	switch (psample_config_cmd(config)) {
	case PSAMPLE_CMD_NEW_GROUP:
		printf("created ");
		break;
	case PSAMPLE_CMD_DEL_GROUP:
		printf("deleted ");
		break;
	default:
		return 0;
	}

	if (psample_config_group_exist(config))
		printf("group %d ", psample_config_group(config));
	if (psample_config_group_seq_exist(config))
		printf("with current seq %d ",
		       psample_config_group_seq(config));

	printf("\n");
	return 0;
}

enum command {
	COMMAND_UNSET,
	COMMAND_LIST_GROUPS,
	COMMAND_MONITOR,
	COMMAND_WRITE,
};

static struct argp_option options[] = {
	{"list-groups", 'l', 0, 0, "list the current groups" },
	{"monitor", 'm', 0, 0, "monitor sample packets (default)" },
	{"no-config", 'c', 0, 0,
			"when monitoring, don't show config notifications" },
	{"no-sample", 's', 0, 0,
			"when monitoring, don't show sample notifications" },
	{"group", 'g', "GROUP_NUM", 0, "for monitor, filter by group" },
	{"verbose", 'v', 0, 0, "print the packet data" },
	{"write", 'w', "OUT_FILE", 0, "write sampled packets to file" },
	{ 0 }
};

struct psample_tool_options {
	enum command cmd;
	int group;
	bool verbose;
	bool no_config;
	bool no_sample;
	const char *out_file;
};

static const char *cmd_str_get(enum command cmd)
{
	switch (cmd) {
	case COMMAND_LIST_GROUPS:
		return "list-groups";
	case COMMAND_MONITOR:
		return "monitor";
	case COMMAND_WRITE:
		return "write";
	default:
		return "unknown command";
	}
}

static void
forbid_several_commands(enum command current_cmd, enum command new_cmd,
			struct argp_state *state)
{
	if (current_cmd == COMMAND_UNSET)
		return;

	printf("Cant put both %s and %s\n", cmd_str_get(current_cmd),
	       cmd_str_get(new_cmd));
	argp_usage(state);
}

static void
forbid_argument(bool argument, const char *argument_str, enum command cmd,
		struct argp_state *state)
{
	if (!argument)
		return;

	printf("Cant put both %s and %s\n", argument_str, cmd_str_get(cmd));
	argp_usage(state);
}

static void frobid_no_sample_with_no_config(bool no_sample, bool no_config,
					    struct argp_state *state)
{
	if (!no_sample || !no_config)
		return;

	printf("Cant put both no-sample and no-config\n");
	argp_usage(state);
}

static void
validate_arguments(struct psample_tool_options *arguments,
		   struct argp_state *state)
{
	switch (arguments->cmd) {
	case COMMAND_LIST_GROUPS:
		forbid_argument(arguments->no_config, "no-config",
				arguments->cmd, state);
		forbid_argument(arguments->no_sample, "no-sample",
				arguments->cmd, state);
		break;
	case COMMAND_MONITOR:
		frobid_no_sample_with_no_config(arguments->no_sample,
						arguments->no_config, state);
		break;
	case COMMAND_WRITE:
		forbid_argument(arguments->no_config, "no-config",
				arguments->cmd, state);
		forbid_argument(arguments->no_sample, "no-sample",
				arguments->cmd, state);
		forbid_argument(arguments->verbose, "verbose",
				arguments->cmd, state);
		if (arguments->group >= 0) {
			printf("Cant put both group and write\n");
			argp_usage(state);
		}
		break;
	}
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we know is a pointer to
	 * our arguments structure.
	 */
	struct psample_tool_options *arguments = state->input;

	switch (key) {
	case 'l':
		forbid_several_commands(arguments->cmd, COMMAND_LIST_GROUPS,
					state);
		arguments->cmd = COMMAND_LIST_GROUPS;
		break;
	case 'm':
		forbid_several_commands(arguments->cmd, COMMAND_MONITOR, state);
		arguments->cmd = COMMAND_MONITOR;
		break;
	case 'w':
		forbid_several_commands(arguments->cmd, COMMAND_WRITE, state);
		arguments->cmd = COMMAND_WRITE;
		arguments->out_file = arg;
		break;
	case 'v':
		arguments->verbose = true;
		break;
	case 'g':
		arguments->group = atoi(arg);
		break;
	case 'c':
		arguments->no_config = true;
		break;
	case 's':
		arguments->no_sample = true;
		break;
	case ARGP_KEY_END:
		if (arguments->cmd == COMMAND_UNSET)
			arguments->cmd = COMMAND_MONITOR;
		validate_arguments(arguments, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char doc[] = "Tool for monitoring psample packets";

static struct argp argp = { options, parse_opt, NULL, doc };

int main(int argc, char **argv)
{
	struct psample_tool_options arguments = {0};
	struct psample_handle *handle;
	bool first_run = true;
	int err = 0;

	arguments.group = -1;
	arguments.out_file = NULL;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	psample_set_log_level(PSAMPLE_LOG_INFO);

	handle = psample_open();
	if (!handle)
		return -1;

	switch (arguments.cmd) {
	case COMMAND_MONITOR:
		if (arguments.group != -1)
			psample_bind_group(handle, arguments.group);

		if (arguments.no_sample)
			psample_dispatch(handle, NULL, NULL, show_config_cb,
					 &arguments.verbose, true);
		else if (arguments.no_config)
			psample_dispatch(handle, show_message_cb,
					 &arguments.verbose, NULL, NULL, true);
		else
			psample_dispatch(handle, show_message_cb,
					 &arguments.verbose, show_config_cb,
					 &arguments.verbose, true);
		break;
	case COMMAND_LIST_GROUPS:
		psample_group_foreach(handle, show_group_cb, &first_run);
		break;
	case COMMAND_WRITE:
		err = psample_pcap_init(arguments.out_file, handle);
		if (err)
			break;

		psample_write_pcap_dispatch(handle);
		psample_pcap_fini(handle);
		break;
	}

	psample_close(handle);

	return err;
}
