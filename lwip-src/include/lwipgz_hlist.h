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

#ifndef __LWIPGZ_HLIST_H__
#define __LWIPGZ_HLIST_H__

#include "lwipgz_list.h"

#define HLIST_QUICKLY_FIND 0

struct hlist_node {
    /**
     * @pprev: point the previous node's next pointer
     */
    struct hlist_node *next;
    struct hlist_node **pprev;

#if HLIST_QUICKLY_FIND
    /* quickly find the hlist_head */
    struct hlist_head *head;
#endif /* HLIST_QUICKLY_FIND */
};

struct hlist_head {
    struct hlist_node *first;
#if HLIST_QUICKLY_FIND
    struct hlist_node *tail;
#endif /* HLIST_QUICKLY_FIND */
};

/**
 * hlist_entry - iterate over list of given type
 * @ptr:    the &hlist_node within the struct.
 * @type:   the struct type.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * hlist_for_each_entry - iterate over list of given type
 * @tpos:   the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member) \
    for (pos = (head)->first; \
        pos && ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
        pos = (pos)->next)

static inline void hlist_init_head(struct hlist_head *h)
{
    h->first = NULL;
#if HLIST_QUICKLY_FIND
    h->tail = NULL;
#endif /* HLIST_QUICKLY_FIND */
}

static inline void hlist_init_node(struct hlist_node *n)
{
    n->next = NULL;
    n->pprev = NULL;
#if HLIST_QUICKLY_FIND
    n->head = NULL;
#endif /* HLIST_QUICKLY_FIND */
}

static inline int hlist_head_empty(const struct hlist_head *h)
{
    return h->first == NULL;
}

static inline int hlist_node_null(const struct hlist_node *n)
{
    return n->pprev == NULL;
}

static inline void hlist_del_node(struct hlist_node *n)
{
    if (hlist_node_null(n)) {
        return;
    }

    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;

#if HLIST_QUICKLY_FIND
    if (n->head->tail == n) {
        if (n->head->first == n) {
            n->head->tail = NULL;
        } else {
            n->head->tail = hlist_entry(pprev, struct hlist_node, next);
        }
    }
#endif /* HLIST_QUICKLY_FIND */

    *pprev = next;
    if (next != NULL) {
        next->pprev = pprev;
    }

    hlist_init_node(n);
}

/**
 * hlist_add_head - add node at the beginning of the hlist
 * @n: new node
 * @head: hlist head to add it after
 */
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *head)
{
    struct hlist_node *first = head->first;

    n->next = first;
    if (first != NULL) {
        first->pprev = &n->next;
    }

    head->first = n;
    n->pprev = &head->first;

#if HLIST_QUICKLY_FIND
    n->head = head;
    if (head->tail == NULL)
        head->tail = n;
#endif /* HLIST_QUICKLY_FIND */
}

/**
 * hlist_add_before - add node before next node
 * @n: new node
 * @next: node in the hlist
 */
static inline void hlist_add_before(struct hlist_node *n, struct hlist_node *next)
{
    n->pprev = next->pprev;
    n->next = next;
    next->pprev = &n->next;
    *(n->pprev) = n;

#if HLIST_QUICKLY_FIND
    n->head = next->head;
#endif /* HLIST_QUICKLY_FIND */
}

/**
 * hlist_add_after - add node after prev node
 * @n: new node
 * @prev: node in the hlist
 */
static inline void hlist_add_after(struct hlist_node *n, struct hlist_node *prev)
{
    n->next = prev->next;
    prev->next = n;
    n->pprev = &prev->next;
    if (n->next != NULL) {
        n->next->pprev = &n->next;
    }

#if HLIST_QUICKLY_FIND
    n->head = prev->head;
    if (prev->head->tail == prev)
        prev->head->tail = n;
#endif /* HLIST_QUICKLY_FIND */
}

#if HLIST_QUICKLY_FIND
/**
 * hlist_add_tail - add node at the tail of the hlist
 * @n: new node
 * @head: hlist head to add it tail
 */
static inline void hlist_add_tail(struct hlist_node *n, struct hlist_head *head)
{
    hlist_add_after(n, head->tail);
}
#endif /* HLIST_QUICKLY_FIND */

#endif /* __LWIPGZ_HLIST_H__ */
