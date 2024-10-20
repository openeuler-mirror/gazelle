#ifndef _GAZELLE_ZC_API_H_
#define _GAZELLE_ZC_API_H_
/* This header file contains the socket API exposed by gazelle to users. */

struct pbuf;
enum pbuf_layer;
enum pbuf_type;

extern uint32_t pbuf_get_len(struct pbuf *p);
extern uint32_t pbuf_get_tot_len(struct pbuf *p);
extern void* pbuf_get_payload(struct pbuf *p);
extern struct pbuf* pbuf_get_next(struct pbuf *p);
extern uint32_t pbuf_get_ref(struct pbuf *p);

extern ssize_t zc_read(int s, void *mem, size_t len);
extern ssize_t zc_write(int s, void *p, size_t len);
extern ssize_t zc_recv(int s, struct pbuf **p, size_t len, int flags);
extern ssize_t zc_send(int s, struct pbuf **p, size_t len, int flags);

extern int gazelle_free(int s, struct pbuf *p, const size_t recvd_len);

#endif /* _GAZELLE_ZC_API_H_ */
