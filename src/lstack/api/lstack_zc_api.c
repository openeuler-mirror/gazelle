#include <lwip/sockets.h>
#include <lwip/tcp.h>
#include <lwipgz_sock.h>
#include <lwip/pbuf.h>
#include <lwip/lwipgz_posix_api.h>
#include <lwip/api.h>
#include <stdint.h>
#include <stdio.h>

#include "common/gazelle_base_func.h"
#include "lstack_log.h"
#include "lstack_lwip.h"
#include "lstack_preload.h"
#include "lwipgz_log.h"

static ssize_t lwip_rtc_zc_recv(int fd, struct pbuf ** pbuf, size_t len, int flags,
                                struct sockaddr *addr, socklen_t *addrlen)
{
    u8_t apiflags = NETCONN_NOAUTORCVD;
    struct lwip_sock *sock;
    ssize_t recvd = 0;
    ssize_t recv_left = (len <= SSIZE_MAX) ? (ssize_t)len : SSIZE_MAX;
    struct pbuf **head_pbuf_ptr = pbuf;
    struct pbuf *prev_pbuf = NULL;
    struct pbuf *p = NULL;

    sock = lwip_get_socket(fd);
    if (!sock) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d sock is NULL errno=%d\n", fd, errno);
        GAZELLE_RETURN(EINVAL);
    }

    if (flags & MSG_DONTWAIT) {
        apiflags |= NETCONN_DONTBLOCK;
    }

    if (*head_pbuf_ptr != NULL) {
        prev_pbuf = *head_pbuf_ptr;
        while (prev_pbuf->next)
            prev_pbuf = prev_pbuf->next;
        prev_pbuf->next = NULL;
    }

    do {
        err_t err;
        u16_t copylen;

        /* Check if there is data left from the last recv operation. */
        if (sock->lastdata.pbuf) {
            p = sock->lastdata.pbuf;
        } else {
            /* No data was left from the previous operation, so we try to get
                 some from the network. */
            err = netconn_recv_tcp_pbuf_flags(sock->conn, &p, apiflags);

            if (err != ERR_OK) {
                if (recvd > 0) {
                    /* already received data, return that (this trusts in getting the same error from
                         netconn layer again next time netconn_recv is called) */
                    goto lwip_recv_tcp_done;
                }
                /* We should really do some error checking here. */
                // LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recv_tcp: p == NULL, error is \"%s\"!\n",
                //                                                         lwip_strerr(err)));
                set_errno(err_to_errno(err));
                if (err == ERR_CLSD) {
                    return 0;
                } else {
                    return -1;
                }
            }
            LWIP_ASSERT("p != NULL", p != NULL);
            sock->lastdata.pbuf = p;
        }


        if (recv_left > p->tot_len) {
            copylen = p->tot_len;
        } else {
            copylen = (u16_t)recv_left;
        }
        if (recvd > SSIZE_MAX - copylen) {
            /* overflow */
            copylen = (u16_t)(SSIZE_MAX - recvd);
        }

        if (unlikely(prev_pbuf == NULL)) {
            prev_pbuf = p;
            *head_pbuf_ptr = p;
        } else {
            prev_pbuf->next = p;
            prev_pbuf = p;
            prev_pbuf->next = NULL;
        }

        recvd += copylen;

        /* TCP combines multiple pbufs for one recv */
        recv_left -= copylen;

        /* Unless we peek the incoming message... */
        if ((flags & MSG_PEEK) == 0) {
            /* ... check if there is data left in the pbuf */
            if (p->tot_len - copylen > 0) {
                // sock->lastdata.pbuf = pbuf_free_header(p, copylen);
            } else {
                sock->lastdata.pbuf = NULL;
                // pbuf_free(p);
            }
        }
        apiflags |= NETCONN_DONTBLOCK | NETCONN_NOFIN;
    } while ((recv_left > 0) && !(flags & MSG_PEEK));

lwip_recv_tcp_done:
    if (apiflags & NETCONN_NOAUTORCVD) {
        if ((recvd > 0) && !(flags & MSG_PEEK)) {
            /* ensure window update after copying all data */
            netconn_tcp_recvd(sock->conn, (size_t)recvd);
        }
    }

    /*The protocol stack has finished operating the current pbuf*/
    p = *head_pbuf_ptr;
    while (p != NULL) {
        p->ref = 0;
        p = p->next;
    }

    set_errno(0);
    return recvd;
}

static ssize_t lwip_zc_send(int32_t fd, const void *buf, size_t len, int32_t flags)
{
    struct lwip_sock *sock;
    err_t err;
    u8_t write_flags;
    size_t written;

    sock = lwip_get_socket(fd);
    if (!sock) {
        return -1;
    }

    write_flags = (u8_t)(NETCONN_NOCOPY |
                        ((flags & MSG_MORE) ? NETCONN_MORE : 0) |
                        ((flags & MSG_DONTWAIT) ? NETCONN_DONTBLOCK : 0));
    written = 0;
    err = netconn_write_partly(sock->conn, buf, len, write_flags, &written);

    set_errno(err_to_errno(err));
    return (err == ERR_OK ? (ssize_t)written : -1);
}

ssize_t rtc_zc_read(int s, struct pbuf **p, size_t len)
{
    return lwip_rtc_zc_recv(s, p, len, 0, NULL, NULL);
}

ssize_t rtc_zc_write(int s, const void *p, size_t len)
{
    return lwip_zc_send(s, p, len, 0);
}

ssize_t rtc_zc_recv(int s, struct pbuf **p, size_t len, int flags)
{
    return lwip_rtc_zc_recv(s, p, len, flags, NULL, NULL);
}

ssize_t rtc_zc_send(int s, const void *p, size_t len, int flags)
{
    return lwip_zc_send(s, p, len, flags);
}

static inline ssize_t do_zc_read(int s, struct pbuf **p, size_t len)
{
    if (p == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if(len == 0) {
        return 0;
    }

    if (select_sock_posix_path(lwip_get_socket(s)) == POSIX_LWIP) {
        return rtc_zc_read(s, p, len);
    }
    LSTACK_LOG(ERR, LSTACK, "posix_api doesn't support zero copy\n");
    GAZELLE_RETURN(ENOSYS);
}

static inline ssize_t do_zc_write(int s, const void *mem, size_t size)
{
    if (select_sock_posix_path(lwip_get_socket(s)) == POSIX_LWIP) {
        return rtc_zc_write(s, mem, size);
    }
    LSTACK_LOG(ERR, LSTACK, "posix_api doesn't support zero copy\n");
    GAZELLE_RETURN(ENOSYS);
}

static inline ssize_t do_zc_recv(int s, struct pbuf **p, size_t len, int flags)
{
    if (select_sock_posix_path(lwip_get_socket(s)) == POSIX_LWIP) {
        return rtc_zc_recv(s, p, len, flags);
    }
    LSTACK_LOG(ERR, LSTACK, "posix_api doesn't support zero copy\n");
    GAZELLE_RETURN(ENOSYS);
}

static inline ssize_t do_zc_send(int s, const void *p, size_t len, int flags)
{
    if (select_sock_posix_path(lwip_get_socket(s)) == POSIX_LWIP) {
        return rtc_zc_send(s, p, len, flags);
    }
    LSTACK_LOG(ERR, LSTACK, "posix_api doesn't support zero copy\n");
    GAZELLE_RETURN(ENOSYS);
}

uint32_t pbuf_get_len(struct pbuf *p)
{
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "p=%p pbuf is NULL\n", p);
        GAZELLE_RETURN(EINVAL);
    }
    return p->len;
}

uint32_t pbuf_get_tot_len(struct pbuf *p)
{
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "p=%p pbuf is NULL\n", p);
        GAZELLE_RETURN(EINVAL);
    }
    return p->tot_len;
}

void* pbuf_get_payload(struct pbuf *p)
{
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "p=%p pbuf is NULL\n", p);
        return NULL;
    }
    return p->payload;
}

struct pbuf* pbuf_get_next(struct pbuf *p)
{
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "p=%p pbuf is NULL\n", p);
        return NULL;
    }
    return p->next;
}

uint32_t pbuf_get_ref(struct pbuf *p)
{
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "p=%p pbuf is NULL\n", p);
        GAZELLE_RETURN(EINVAL);
    }
    return p->ref;
}

/* Exposed zero-copy interface */
ssize_t zc_read(int s, struct pbuf **p, size_t len)
{
    return do_zc_read(s, p, len);
}

ssize_t zc_write(int s, const void *p, size_t len)
{
    return do_zc_write(s, p, len);
}

ssize_t zc_recv(int s, struct pbuf **p, size_t len, int flags)
{
    return do_zc_recv(s, p, len, flags);
}

ssize_t zc_send(int s, const void *p, size_t len, int flags)
{
    return do_zc_send(s, p, len, flags);
}

/*
 * Free pbuf chain partially or completely based on received length.
 * 
 * This function is used to free a chain of pbufs:
 * - If pbuf->ref is 0, the pbuf will be completely freed
 * - For partial receive case, only free the used portion of pbufs
 *
 * @param s          Socket descriptor
 * @param p          Pointer to pbuf chain to be freed
 * @param recvd_len  Length of data that was actually received/processed
 *
 * @return  0 on success
 *          EINVAL for invalid parameters (NULL pbuf, invalid recvd_len)
 */
int gazelle_free(int s, struct pbuf *p, const size_t recvd_len)
{
    if (!p || recvd_len <= 0 || recvd_len > p->tot_len) {
        GAZELLE_RETURN(EINVAL);
    }

    uint32_t curr = 0;
    while (p != NULL && p->ref == 0) {
        if (p->len + curr <= recvd_len) {
            do_lwip_free_pbuf(p);
            p = p->next;
            curr += p->len;
        } else {
            do_lwip_free_pbuf_header(s, p, recvd_len - curr);
            break;
        }
    }

    return 0;
}