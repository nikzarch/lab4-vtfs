#ifndef VTFS_HTTP_H
#define VTFS_HTTP_H

#include <linux/inet.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <net/sock.h>


int64_t vtfs_http_call(const char *token, const char *method,
                            char *response_buffer, size_t buffer_size,
                            size_t arg_size, ...);

void encode(const char *, char *);

#endif // VTFS_HTTP_H
