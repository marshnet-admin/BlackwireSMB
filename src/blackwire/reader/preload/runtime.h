/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include "source.h"
#include <cstdint>
#include <atomic>
/* Two-phase source-owned initialization. Original-op preparation uses the
 * unchanged hook resolver/table, then required metadata loads before patches. */
int bp_prepare_originals_and_metadata();
int bp_release_unpatched_metadata(); /* failed-start owner; no residual detour */
enum : unsigned {BP_INIT_ENTER=1,BP_INIT_PREPASS=2,BP_INIT_METADATA=3,BP_INIT_INDEX=4,BP_INIT_TARGETS=5,BP_INIT_INSTALL=6,BP_INIT_RELEASE=7};
void bp_init_report(unsigned,int64_t); /* bounded numeric snapshot; outside HookLock */
bool bp_metadata_prepare();
bool bp_runtime_metadata_ready();
/* Source-owned Ampr worker calls. No SMB or allocation in open/match. */
bool bp_worker_initialize();
int bp_worker_priority(int upstream);
void bp_worker_priority_report(int upstream,int requested,int result);
void bp_worker_finish();
bool bp_runtime_ready();
bool bp_runtime_failed();
int bp_runtime_match(const char*,size_t,uint64_t,uint32_t*);
int64_t bp_runtime_read(uint32_t,uint64_t,void*,size_t,const std::atomic<bool>*,struct bp_read_witness*);
void bp_runtime_report_read(const struct bp_read_witness*,int64_t); /* copied snapshot; outside pack lock */
/* Source worker only, outside the pack lock: one bounded idle read-ahead step. */
bool bp_runtime_prefetch_pending();
void bp_runtime_prefetch_step();
/* Request latency telemetry and slicing; single source worker only. */
#define BP_RUNTIME_SLICE_BYTES (256u*1024u)
struct bp_request_sample {uint32_t id;uint64_t bytes,queued_ns,start_ns,service_ns,done_ns;uint8_t priority,work_class;bool failed;};
uint64_t bp_runtime_now_ns();
bool bp_runtime_slicing_ready();
void bp_runtime_note_queue(uint32_t depth); /* called under the pack lock; no I/O */
void bp_runtime_record_request(const struct bp_request_sample*);
/* Two-lane pack workers. start/stop run on each worker thread; read_job
 * routes small/medium reads of the lane owner to its own source and every
 * other read to the primary source under its mutex. */
void bp_worker_start(uint32_t worker,uint32_t workers);
void bp_worker_stop(uint32_t worker);
int64_t bp_runtime_read_job(uint32_t worker,bool bulk,uint32_t,uint64_t,void*,size_t,const std::atomic<bool>*,struct bp_read_witness*);
int bp_lane_release(); /* after workers stop; releases the lane source and its heap cache */
void bp_runtime_cancel();
int bp_runtime_release(); /* joined worker and no metadata users required */
/* Only a BOTH-absent home failure; release must already prove no detour or
 * source owner remains. Uses existing libkernel lookup, never SystemService. */
int bp_home_startup_failure(int release_result);
