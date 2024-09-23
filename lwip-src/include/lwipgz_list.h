/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

#ifndef __LWIPGZ_LIST_H__
#define __LWIPGZ_LIST_H__

/* double circular linked list */
struct list_node {
    struct list_node *prev;
    struct list_node *next;
};

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member));})
#endif /* container_of */

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_for_each_node(node, n, head) \
    for (node = (head)->next, n = (node)->next; \
         node != (head); \
         node = n, n = (node)->next)

static inline unsigned list_get_node_count(const struct list_node *h)
{
    const struct list_node *node, *n;
    unsigned count = 0;
    list_for_each_node(node, n, h) {
        ++count;
    }
    return count;
}

static inline int list_node_null(const struct list_node *n)
{
    return (n->prev == NULL) || (n->next == NULL);
}

static inline int list_head_empty(const struct list_node *h)
{
    return h == h->next;
}

static inline void list_init_head(struct list_node *h)
{
    h->prev = h;
    h->next = h;
}

static inline void list_init_node(struct list_node *n)
{
    n->prev = NULL;
    n->next = NULL;
}

/* add node befor head, means at tail */
static inline void list_add_node(struct list_node *n, struct list_node *head)
{
    n->next = head;
    n->prev = head->prev;
    head->prev->next = n;
    head->prev = n;
}

static inline void __list_del_node(struct list_node *n)
{
    struct list_node *prev = n->prev;
    struct list_node *next = n->next;
    next->prev = prev;
    prev->next = next;
}

static inline void list_del_node(struct list_node *n)
{
    if (list_node_null(n)) {
        return;
    }
    __list_del_node(n);
    list_init_node(n);
}

#endif /* __LWIPGZ_LIST_H__ */
