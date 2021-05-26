/*
 *   mnlg.h	Generic Netlink helpers for libmnl
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@mellanox.com>
 */

#ifndef _MNLG_H_
#define _MNLG_H_

#include <libmnl/libmnl.h>

struct mnlg_socket;

char *mnlg_socket_buf_get(struct mnlg_socket *nlg);
uint32_t mnlg_socket_id_get(struct mnlg_socket *nlg);
struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
				  uint16_t flags);
struct nlmsghdr *mnlg_ctrl_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
				       uint16_t flags);
int mnlg_socket_send(struct mnlg_socket *nlg, const struct nlmsghdr *nlh);
int mnlg_mnl_socket_recvfrom(struct mnlg_socket *nlg);
int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data);
int mnlg_socket_group_add(struct mnlg_socket *nlg, const char *group_name);
int mnlg_socket_setsockopt(struct mnlg_socket *nlg, int optname, void *optval,
			   socklen_t optlen);
struct mnlg_socket *mnlg_socket_open(const char *family_name, uint8_t version);
void mnlg_socket_close(struct mnlg_socket *nlg);
int mnlg_socket_get_fd(struct mnlg_socket *nlg);

#endif /* _MNLG_H_ */
