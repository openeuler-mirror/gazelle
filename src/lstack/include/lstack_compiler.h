/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/

#ifndef _GAZELLE_COMPILER_H_
#define _GAZELLE_COMPILER_H_

#ifdef __GNUC__

#ifndef likely
#define likely(x)    __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)   __builtin_expect(!!(x), 0)
#endif

#ifndef __clz__
#define __clz__(x)    __builtin_clz(x)
#endif

#else // __GNUC__

#define likely(x)    (x)
#define unlikely(x)  (x)

#ifndef __clz__
#error "You have to provide __clz__ to return the number "\
"of leading 0-bits in x, starting at the most signification bit position."
#endif

#endif // __GNUC__

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x)   (*(volatile typeof(x) *)&(x))
#endif

#endif /* GAZELLE_COMPILER_H */
