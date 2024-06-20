# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

SRC = lstack_preload.c lstack_init.c lstack_cfg.c lstack_dpdk.c lstack_control_plane.c lstack_stack_stat.c lstack_lwip.c lstack_protocol_stack.c lstack_thread_rpc.c lstack_virtio.c lstack_port_map.c
$(eval $(call register_dir, core, $(SRC)))

