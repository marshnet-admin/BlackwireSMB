/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "runtime.h"
#include "first_read.h"
#include "home_client.h"
#include "ampr_libkernel_hook.h"
#include "ampr_debug_log.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_sync.h"
#include "ampr_emu_runtime_memory.h"
#include "../bw/streamreader/cache.h"
#include <_kernel.h>
#include <sys/dmem.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "../bw/library/reader_selection.h"
#include "../bw/library/reader_projection.h"
}
namespace {
std::atomic<unsigned> status{0},metadata_users{0};
std::atomic<bool> canceled{false},finished{true},metadata_ready{false};
bp_source *source{};
bp_first_read first_read{}; // only the one source worker touches this
// BP_CACHE_BACKING_BEGIN
// Dedicated CPU-only module-lifetime storage, separate from Ampr's shared
// index/scratch pool. Only the one admitted source worker borrows this buffer.
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t cache_storage[BW_CACHE_BYTES];
static std::atomic<bp_source*> cache_owner{nullptr};
// BP_CACHE_BACKING_END
// Only the single source worker sets/reads this borrowed, in-flight job flag.
// Existing pack ownership retains the job until its completion publication.
const std::atomic<bool> *job_cancel{};
// Idle read-ahead, owned by the single source worker. A stream qualifies after
// two forward reads of the same file; one bounded step runs per idle check.
constexpr unsigned kPrefetchStreams=4;
constexpr uint64_t kPrefetchAhead=8u*1024u*1024u,kPrefetchStep=256u*1024u,kPrefetchGap=1024u*1024u;
struct PrefetchStream {uint32_t id{};uint64_t next{},ahead{},used{};unsigned hits{};bool active{},done{};};
PrefetchStream prefetch_streams[kPrefetchStreams]{};
uint64_t prefetch_clock{};
alignas(64) static uint8_t prefetch_buffer[kPrefetchStep];
struct GameReadStats {uint64_t reads{},bytes{},ns{},prefetch_steps{},prefetch_bytes{},prefetch_ns{};} game_stats{};
static uint64_t monotonic_ns(){struct timespec t{};return clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0?0:(uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;}
// Per-request latency, keyed by scheduler class (0 small, 1 medium, 2 large).
// Histogram bin i holds [2^i,2^(i+1)) microseconds; percentiles report upper bounds.
constexpr unsigned kLatClasses=3,kLatPriorities=4,kLatBins=32,kLatFiles=128,kSizeBins=24;
struct LatWindow {uint64_t n{},bytes{},bins[kLatBins]{},max_total{},max_queue{},max_service{},over16{},over33{},over100{},failed{};};
struct LatFile {uint32_t id{};uint64_t reads{},bytes{},small_reads{},slow_small{},max_us{};bool used{};};
struct LatState {
    LatWindow window[kLatClasses]{},session[kLatClasses]{};
    uint64_t prio_n[kLatPriorities]{},prio_slow[kLatPriorities]{};
    uint64_t size_bins[kSizeBins]{},last_log{},windows{};uint32_t depth_peak{},session_depth_peak{};
    LatFile files[kLatFiles]{};
} lat{};
static unsigned log2_bin(uint64_t v,unsigned limit){unsigned b=0;while(v>1&&b<limit-1){v>>=1;b++;}return b;}
static unsigned long long lat_pct(const LatWindow& w,unsigned percent){
    if(!w.n)return 0;uint64_t rank=(w.n*percent+99)/100,seen=0;
    for(unsigned i=0;i<kLatBins;i++){seen+=w.bins[i];if(seen>=rank)return 1ull<<(i+1);}
    return ~0ull;
}
static void lat_add(LatWindow& w,uint64_t bytes,uint64_t total,uint64_t queue,uint64_t service,bool failed){
    w.n++;w.bytes+=bytes;w.bins[log2_bin(total,kLatBins)]++;
    if(total>w.max_total)w.max_total=total;if(queue>w.max_queue)w.max_queue=queue;if(service>w.max_service)w.max_service=service;
    w.over16+=total>16000;w.over33+=total>33000;w.over100+=total>100000;w.failed+=failed;
}
static void lat_log(const char *scope,const LatWindow (&set)[kLatClasses],uint32_t depth){
    static const char *const names[kLatClasses]={"small","medium","large"};
    for(unsigned c=0;c<kLatClasses;c++){
        const LatWindow& w=set[c];if(!w.n)continue;
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LAT1] scope=%s cls=%s n=%llu kib=%llu p50us=%llu p95us=%llu p99us=%llu maxus=%llu qmaxus=%llu smaxus=%llu gt16=%llu gt33=%llu gt100=%llu failed=%llu depthPeak=%u",
            scope,names[c],(unsigned long long)w.n,(unsigned long long)(w.bytes>>10),lat_pct(w,50),lat_pct(w,95),lat_pct(w,99),
            (unsigned long long)w.max_total,(unsigned long long)w.max_queue,(unsigned long long)w.max_service,
            (unsigned long long)w.over16,(unsigned long long)w.over33,(unsigned long long)w.over100,(unsigned long long)w.failed,depth);
    }
}
static void lat_log_window(){
    lat_log("window",lat.window,lat.depth_peak);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LAT1] scope=priority n0=%llu slow0=%llu n1=%llu slow1=%llu n2=%llu slow2=%llu n3=%llu slow3=%llu",
        (unsigned long long)lat.prio_n[0],(unsigned long long)lat.prio_slow[0],(unsigned long long)lat.prio_n[1],(unsigned long long)lat.prio_slow[1],
        (unsigned long long)lat.prio_n[2],(unsigned long long)lat.prio_slow[2],(unsigned long long)lat.prio_n[3],(unsigned long long)lat.prio_slow[3]);
    for(auto& w:lat.window)w=LatWindow{};
    for(unsigned i=0;i<kLatPriorities;i++)lat.prio_n[i]=lat.prio_slow[i]=0;
    lat.depth_peak=0;
}
static void lat_file(uint32_t id,uint64_t bytes,bool small,bool slow,uint64_t total){
    LatFile *slot=nullptr,*victim=&lat.files[0];
    for(auto& f:lat.files){if(f.used&&f.id==id){slot=&f;break;}if(!f.used||f.reads<victim->reads)victim=&f;}
    if(!slot){slot=victim;*slot=LatFile{};slot->id=id;slot->used=true;}
    slot->reads++;slot->bytes+=bytes;slot->small_reads+=small;slot->slow_small+=small&&slow;if(total>slot->max_us)slot->max_us=total;
}
static void lat_report_session(){
    lat_log("session",lat.session,lat.session_depth_peak);
    char sizes[400];int at=0;
    for(unsigned i=12;i<kSizeBins&&at>=0&&at<(int)sizeof sizes;i++)
        at+=snprintf(sizes+at,sizeof sizes-at," k%u=%llu",(1u<<i)>>10,(unsigned long long)lat.size_bins[i]);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_SIZE1] under4k=%llu%s",
        (unsigned long long)(lat.size_bins[0]+lat.size_bins[1]+lat.size_bins[2]+lat.size_bins[3]+lat.size_bins[4]+lat.size_bins[5]+lat.size_bins[6]+lat.size_bins[7]+lat.size_bins[8]+lat.size_bins[9]+lat.size_bins[10]+lat.size_bins[11]),sizes);
    bool reported[kLatFiles]{};
    for(unsigned rank=0;rank<8;rank++){
        int best=-1;
        for(unsigned i=0;i<kLatFiles;i++){
            const LatFile& f=lat.files[i];if(!f.used||reported[i])continue;
            if(best<0||f.slow_small>lat.files[best].slow_small||(f.slow_small==lat.files[best].slow_small&&f.reads>lat.files[best].reads))best=(int)i;
        }
        if(best<0)break;reported[best]=true;const LatFile& f=lat.files[best];
        char path[160];if(!source||bp_source_path(source,f.id,path,sizeof path))snprintf(path,sizeof path,"?");
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_FILE1] rank=%u id=%u reads=%llu mib=%llu small=%llu slowSmall=%llu maxus=%llu path=%s",
            rank,f.id,(unsigned long long)f.reads,(unsigned long long)(f.bytes>>20),(unsigned long long)f.small_reads,
            (unsigned long long)f.slow_small,(unsigned long long)f.max_us,path);
    }
}
struct Ops {int(*open)(const char*,int,...);int(*stat)(int,struct stat*);ssize_t(*pread)(int,void*,size_t,off_t);int(*close)(int);} ops{};
int current(void*){return canceled.load()||(job_cancel&&job_cancel->load())? -1:0;}
// Two pack workers share the primary source (large reads, read-ahead, first
// read) under primary_mutex. The reserved small-read worker also owns a second
// lane: its own source, SMB connection and heap cache, never touched by others.
static AmprMutex& primary_mutex(){static AmprMutex m;return m;}
static AmprMutex& lat_mutex(){static AmprMutex m;return m;}
constexpr size_t kLaneCacheBytes=16u*1024u*1024u;
constexpr uint32_t kNoWorker=UINT32_MAX;
bp_source *lane_source{};
std::atomic<unsigned> lane_status{0}; // 0 none, 2 admitted, 4 ready, 5 failed, 6 finished
std::atomic<uint32_t> lane_owner{kNoWorker},primary_owner{kNoWorker};
uint8_t *lane_storage{};
const std::atomic<bool> *lane_cancel{}; // lane owner only
int lane_current(void*){return canceled.load()||(lane_cancel&&lane_cancel->load())? -1:0;}
struct LaneStats {uint64_t reads{},bytes{},ns{},fallbacks{},last_log{};} lane_stats{};
// BP_INPUT_DIAGNOSTIC_BEGIN
struct InitFailure {unsigned input{},operation{},field{};int64_t result{};int error{};uint64_t actual{},expected{};} init_failure{};
static bool input_fail(unsigned input,unsigned operation,int64_t result,int error,unsigned field=0,uint64_t actual=0,uint64_t expected=0){
    if(!init_failure.operation)init_failure={input,operation,field,result,error,actual,expected};
    return false;
}
struct PrivateWait {bool started{};uint64_t begin{},last{};} private_wait{};
struct HomeStartup {bool active{},inputs_released{true},release_unknown{};uint64_t deadline{},last{};char run[33]{};} home_start{};
static bool private_clock(unsigned input,uint64_t& out){
    struct timespec stamp{};int result=clock_gettime(CLOCK_MONOTONIC,&stamp);int saved=errno;
    if(result)return input_fail(input,14,result,saved);
    if(stamp.tv_sec<0||stamp.tv_nsec<0||stamp.tv_nsec>=1000000000L||
       (uint64_t)stamp.tv_sec>(UINT64_MAX-999999u)/1000000u)return input_fail(input,16,0,0);
    out=(uint64_t)stamp.tv_sec*1000000u+(uint64_t)stamp.tv_nsec/1000u;
    return true;
}
static bool home_window(unsigned input){
    if(!home_start.active)return true;
    uint64_t at;if(!private_clock(input,at))return false;
    if(at<home_start.last||at>=home_start.deadline)return input_fail(input,16,0,0,3,at,home_start.deadline);
    home_start.last=at;return true;
}
static bool private_window(unsigned input,int denied_result,int denied_error){
    if(home_start.active)return home_window(input);
    uint64_t now;if(!private_clock(input,now))return false;
    if(!private_wait.started)private_wait={true,now,now};
    if(now<private_wait.last)return input_fail(input,16,0,0);
    private_wait.last=now;
    if(now-private_wait.begin>=10000000u){
        if(denied_error==EACCES)return input_fail(input,1,denied_result,denied_error);
        return input_fail(input,16,0,0,2,now-private_wait.begin,10000000u);
    }
    return true;
}
static bool input_open(unsigned input,const char *path,int& fd){
    if((home_start.active||private_wait.started)&&(input==2||input==3)&&!private_window(input,0,0))return false;
    for(;;){
        fd=ops.open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);int saved=errno;
        if(fd>=0)return true;
        if((saved!=EACCES&&!(home_start.active&&saved==ENOENT))||(input!=2&&input!=3))return input_fail(input,1,fd,saved);
        // A normal launcher may assign private files after it has the actual
        // game PID/UID. Only initial private EACCES waits; fresh named checks
        // below still fail immediately. Only a BOTH-absent home claim also
        // waits for ENOENT, under its immutable shared20s deadline.
        if(current(nullptr))return input_fail(input,5,-1,0);
        if(!private_window(input,fd,saved))return false;
        int result=usleep(20000);int delay_error=errno;
        if(result)return input_fail(input,15,result,delay_error);
        if(current(nullptr))return input_fail(input,5,-1,0);
        if(!private_window(input,fd,saved))return false;
    }
}
bool same(const struct stat& a,const struct stat& b){
    return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&
        a.st_nlink==b.st_nlink&&a.st_size==b.st_size&&a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&
        a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
static bool identity_fail(unsigned input,const struct stat& expected,const struct stat& actual){
    // Only already-read fields; identify the same first unequal comparison.
#define BP_STAT_FIELD(n,member) if(expected.member!=actual.member)return input_fail(input,9,0,0,n,(uint64_t)actual.member,(uint64_t)expected.member)
    BP_STAT_FIELD(10,st_dev);BP_STAT_FIELD(11,st_ino);BP_STAT_FIELD(12,st_mode);BP_STAT_FIELD(13,st_uid);BP_STAT_FIELD(14,st_nlink);BP_STAT_FIELD(15,st_size);
    BP_STAT_FIELD(16,st_mtim.tv_sec);BP_STAT_FIELD(17,st_mtim.tv_nsec);BP_STAT_FIELD(18,st_ctim.tv_sec);BP_STAT_FIELD(19,st_ctim.tv_nsec);
#undef BP_STAT_FIELD
    return input_fail(input,9,0,0);
}
struct Input {
    unsigned id;int fd{-1};struct stat captured{};void *bytes{};size_t size{};const char *path{};
    explicit Input(unsigned value):id(value){}
    bool named(){
        int n=ops.open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);int saved=errno;
        if(n<0)return input_fail(id,7,n,saved);
        struct stat st{};int result=ops.stat(n,&st);saved=errno;bool ok=result==0;
        if(!ok)input_fail(id,8,result,saved);
        else if(!same(captured,st)){identity_fail(id,captured,st);ok=false;}
        int rc=ops.close(n);saved=errno;if(rc!=0){home_start.release_unknown=true;input_fail(id,10,rc,saved);}return ok&&rc==0;
    }
    bool load(const char *name,size_t cap,unsigned mode){
        path=name;if(!input_open(id,path,fd))return false;int saved=errno;
        int result=ops.stat(fd,&captured);saved=errno;if(result)return input_fail(id,2,result,saved);
        if(!S_ISREG(captured.st_mode))return input_fail(id,3,0,0,1,(uint64_t)(captured.st_mode&S_IFMT),S_IFREG);
        if(captured.st_size<=0)return input_fail(id,3,0,0,2,(uint64_t)captured.st_size,1);
        if((uint64_t)captured.st_size>cap)return input_fail(id,3,0,0,3,(uint64_t)captured.st_size,cap);
        if((captured.st_mode&07777)!=mode)return input_fail(id,3,0,0,4,captured.st_mode&07777,mode);
        if(captured.st_nlink>1)return input_fail(id,3,0,0,5,captured.st_nlink,1);
        size=(size_t)captured.st_size;bytes=std::malloc(size);saved=errno;if(!bytes)return input_fail(id,4,0,saved);
        for(size_t at=0;at<size;){
            if(current(nullptr))return input_fail(id,5,-1,0);
            size_t want=size-at;if(want>65536)want=65536;
            ssize_t got=ops.pread(fd,(char*)bytes+at,want,(off_t)at);saved=errno;
            if(got<=0||(size_t)got>want)return input_fail(id,6,got,saved,0,got>0?(uint64_t)got:0,want);
            at+=(size_t)got;
        }
        struct stat after{};result=ops.stat(fd,&after);saved=errno;if(result)return input_fail(id,2,result,saved);
        return same(captured,after)?named():identity_fail(id,captured,after);
    }
    bool stable(){
        if(fd<0)return input_fail(id,2,fd,0);
        struct stat now{};int result=ops.stat(fd,&now);int saved=errno;if(result)return input_fail(id,2,result,saved);
        return same(captured,now)?named():identity_fail(id,captured,now);
    }
    bool clear(){bool ok=true;if(bytes){volatile unsigned char *p=(volatile unsigned char*)bytes;for(size_t i=0;i<size;i++)p[i]=0;std::free(bytes);bytes=nullptr;}if(fd>=0){int result=ops.close(fd);int saved=errno;ok=result==0;if(!ok){home_start.release_unknown=true;input_fail(id,11,result,saved);}fd=-1;}return ok;}
};
// BP_INPUT_DIAGNOSTIC_END
// BP_HOME_ADMISSION_BEGIN
using HomeNotice=int(*)(int,void*,size_t,int);
using HomeExit=void(*)(int);
static HomeNotice home_notice{};
static HomeExit home_exit{};
static bool private_inputs_for_launch(Input& map){
    const char *paths[]={"/app0/fakelib2/blackwire-reader.selection","/app0/fakelib2/blackwire-reader.share"};
    unsigned absent=0;bool valid=true;
    // Probe both names without following links. EACCES continues the existing
    // normal Play wait; it never authorizes a claim or replacement.
    for(unsigned i=0;i<2;i++){
        int fd=ops.open(paths[i],O_RDONLY|O_NOFOLLOW|O_NONBLOCK);int saved=errno;
        if(fd>=0){int rc=ops.close(fd);int error=errno;if(rc){input_fail(i+2,11,rc,error);valid=false;}}
        else if(saved==ENOENT)absent|=1u<<i;
        else if(saved!=EACCES){input_fail(i+2,1,fd,saved);valid=false;}
    }
    if(!valid)return false;
    if(!absent)return true; // ordinary Play: original loading/10s wait follows
    if(absent!=3)return input_fail(0,17,-1,0,1,absent,3);
    home_start.active=true;home_start.inputs_released=false;
    uint64_t at;if(!private_clock(0,at)||at>(uint64_t)INT64_MAX-20000000u)return input_fail(0,16,-1,0);
    home_start.deadline=at+20000000u;home_start.last=at;
    // Existing provider/handle resolver; no dependency load or HookLock here.
    home_notice=reinterpret_cast<HomeNotice>(amprResolveLibkernelFunction("sceKernelSendNotificationRequest"));
    home_exit=reinterpret_cast<HomeExit>(amprResolveLibkernelFunction("_exit"));
    if(!home_notice||!home_exit)return input_fail(0,18,-1,0,0,(home_notice?1u:0u)|(home_exit?2u:0u),3);
    if(!map.stable()||!home_window(0))return false;
    uint8_t hash[32]{};bw_home_client_map_sha256(map.bytes,map.size,hash);
    int result=!home_window(0)?-1:bw_home_client_claim((int32_t)getpid(),hash,home_start.deadline,home_start.run);
    std::memset(hash,0,sizeof hash);
    if(result){
        static bool reported;
        if(!reported){
            reported=true;int saved=errno;struct bw_home_client_failure failure{};bw_home_client_diagnostic(&failure);
            sce::Ampr::Emu::kernelDebugLogf("[BWREAD_HOME_CLIENT1] stage=%u detail=%u raw=%lld errno=%d status=%u",
                failure.stage,failure.detail,(long long)failure.raw,failure.error,failure.http_status);
            errno=saved;
        }
        return input_fail(0,19,result,0);
    }
    return map.stable()&&home_window(0);
}
static bool private_selection_bound(const Input& selection){
    if(!home_start.active)return true;
    struct bw_reader_selection checked{};
    int parsed=bw_reader_selection_parse(&checked,selection.bytes,selection.size);
    bool same_run=!parsed&&!std::memcmp(checked.run,home_start.run,33);
    std::memset(&checked,0,sizeof checked);
    return same_run?home_window(2):input_fail(2,20,-1,0);
}
// BP_HOME_ADMISSION_END
bool metadata_guard(){int result=current(nullptr);return result==0?home_window(0):input_fail(0,5,result,0);}
bool metadata_admit(Input& map,Input& selection,Input& share){
    struct bw_reader_selection selected{};int parsed=bw_reader_selection_parse(&selected,selection.bytes,selection.size);
    if(!parsed&&bw_reader_selection_is_projection(&selected)){
        Input projection(4);bool ok=false;
        if(projection.load("/app0/fakelib2/blackwire-reader.projection",BW_READER_PROJECTION_LIMIT,0600)&&
           map.stable()&&selection.stable()&&share.stable()&&metadata_guard()){
            int result=bp_source_admit_projection(&source,map.bytes,map.size,selection.bytes,selection.size,share.bytes,share.size,
                projection.bytes,projection.size,current,nullptr);int saved=errno;
            ok=result==0&&projection.stable()&&map.stable()&&selection.stable()&&share.stable()&&metadata_guard();
            if(result)input_fail(4,13,result,saved);
            if(ok&&bp_source_admit_projection(&lane_source,map.bytes,map.size,selection.bytes,selection.size,share.bytes,share.size,
                projection.bytes,projection.size,lane_current,nullptr))lane_source=nullptr;
        }
        bool closed=projection.clear();return ok&&closed;
    }
    int result=parsed?-1:bp_source_admit(&source,map.bytes,map.size,selection.bytes,selection.size,share.bytes,share.size,current,nullptr);int saved=errno;
    if(result==0&&bp_source_admit(&lane_source,map.bytes,map.size,selection.bytes,selection.size,share.bytes,share.size,lane_current,nullptr))lane_source=nullptr;
    return result==0?true:input_fail(0,13,result,saved);
}
}
bool bp_metadata_prepare(){
    if(metadata_ready.load())return !canceled.load();
    if(cache_owner.load())return false; // no new source may borrow an active backing
    unsigned expected=0;if(!status.compare_exchange_strong(expected,1))return false;
    Input map(1),selection(2),share(3);bool ok=false;
    ops.open=ampr_fixed_kernel_slot<decltype(ops.open)>(kAmprLibkernelHook_open);
    ops.stat=ampr_fixed_kernel_slot<decltype(ops.stat)>(kAmprLibkernelHook_fstat);
    ops.pread=ampr_fixed_kernel_slot<decltype(ops.pread)>(kAmprLibkernelHook_pread);
    ops.close=ampr_fixed_kernel_slot<decltype(ops.close)>(kAmprLibkernelHook_close);
    unsigned mask=(ops.open?1u:0u)|(ops.stat?2u:0u)|(ops.pread?4u:0u)|(ops.close?8u:0u);
    if(mask!=15)input_fail(0,12,-1,0,0,mask,15);
    if(ops.open&&ops.stat&&ops.pread&&ops.close&&metadata_guard()&&
       map.load("/app0/blackwire.files",40u*1024u*1024u,0644)&&
       private_inputs_for_launch(map)&&
       selection.load("/app0/fakelib2/blackwire-reader.selection",4096,0600)&&
       share.load("/app0/fakelib2/blackwire-reader.share",4096,0600)&&
       private_selection_bound(selection)&&
       metadata_admit(map,selection,share)&&
       map.stable()&&selection.stable()&&share.stable()&&metadata_guard())ok=true;
    bool map_closed=map.clear(),selection_closed=selection.clear(),share_closed=share.clear();
    home_start.inputs_released=map_closed&&selection_closed&&share_closed&&!home_start.release_unknown;
    ok=ok&&map_closed&&selection_closed&&share_closed;
    if(!ok&&source){bp_source_close(source);source=nullptr;}
    if(!ok&&lane_source){bp_source_close(lane_source);lane_source=nullptr;}
    if(ok&&lane_source)lane_status.store(2);
    if(ok)metadata_ready.store(true);
    status.store(ok?2u:5u);return ok;
}
int bp_home_startup_failure(int released){
    if(!home_start.active)return 0;
    struct {char unused[45],message[3075];} notification{};
    const char *message=(released||!home_start.inputs_released)?
        "Blackwire startup cleanup is unconfirmed. Close this game normally.":
        "Blackwire could not prepare this launch. Start Blackwire, check its status, then try again.";
    size_t size=std::strlen(message);std::memcpy(notification.message,message,size+1);
    int notice=home_notice?home_notice(0,&notification,sizeof notification,0):-1;
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_HOME1] event=startup-refused released=%d inputsReleased=%u notification=%d exitResolved=%u",
        released,home_start.inputs_released?1u:0u,notice,home_exit?1u:0u);
    if(released||!home_start.inputs_released||!home_exit)return -1;
    // Kernel own-process exit only, after unpatched state was discharged.
    // A returned or unresolved call is not reported as a successful close.
    home_exit(0);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_HOME1] event=own-exit-returned");
    return -1;
}
void bp_init_report(unsigned phase,int64_t result){
    static unsigned attempts;
    if(attempts>=7)return;
    attempts++;int saved=errno;
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_INIT1] phase=%u result=%lld input=%u op=%u raw=%lld errno=%d field=%u actual=%llu expected=%llu",
        phase,(long long)result,init_failure.input,init_failure.operation,(long long)init_failure.result,init_failure.error,init_failure.field,
        (unsigned long long)init_failure.actual,(unsigned long long)init_failure.expected);
    errno=saved;
}
// BP_LIVE_DIAGNOSTIC_BEGIN
// One DATA worker owns this reporter and its source snapshots. No new thread,
// file/socket observation, retries or source authority is introduced here.
struct BpLiveReport {
    uint64_t last_ns{},last_payload{};unsigned seen_stages{};
    bool have_clock{},poison_reported{},read_failure_reported{};
};
static BpLiveReport live_report{};
static void bp_runtime_source_progress(void*,const struct bp_source_progress *d,const struct bp_source_performance *p){
    if(!d||!p)return;const int saved=errno;
    struct timespec stamp{};uint64_t now=0;bool clock_ok=!clock_gettime(CLOCK_MONOTONIC,&stamp)&&stamp.tv_sec>=0&&stamp.tv_nsec>=0&&stamp.tv_nsec<1000000000L&&
        (uint64_t)stamp.tv_sec<=(UINT64_MAX-999999999u)/1000000000u;
    if(clock_ok){now=(uint64_t)stamp.tv_sec*1000000000u+(uint64_t)stamp.tv_nsec;if(live_report.have_clock&&now<live_report.last_ns)clock_ok=false;}
    bool fresh_poison=d->first_poison.valid&&!live_report.poison_reported;
    bool fresh_read_failure=d->first_failed_read.valid&&!live_report.read_failure_reported;
    unsigned bit=d->stage<32?(1u<<d->stage):0;
    bool first_stage=d->in_flight&&bit&&!(live_report.seen_stages&bit);
    bool elapsed=clock_ok&&live_report.have_clock&&now-live_report.last_ns>=UINT64_C(5000000000);
    bool bytes=clock_ok&&live_report.have_clock&&now-live_report.last_ns>=UINT64_C(1000000000)&&p->payload_bytes>=live_report.last_payload&&p->payload_bytes-live_report.last_payload>=UINT64_C(67108864);
    if(fresh_poison){
        live_report.poison_reported=true;const struct bp_source_failure& f=d->first_poison;
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_FAIL1] kind=source seq=%llu stage=%u raw=%lld errno=%d errnoObserved=%u ntStatus=%u ntStatusObserved=%u",
            (unsigned long long)f.sequence,f.stage,(long long)f.raw,f.error,f.error_observed,f.ntstatus,f.ntstatus_observed);
    }
    if(fresh_read_failure){
        live_report.read_failure_reported=true;const struct bp_logical_failure& f=d->first_failed_read;
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_FAIL1] kind=read mapId=%u offset=%llu requested=%llu result=%lld poisoned=%u",
            f.map_id,(unsigned long long)f.offset,(unsigned long long)f.requested,(long long)f.result,f.poisoned);
    }
    if(first_stage||fresh_poison||fresh_read_failure||elapsed||bytes){
        live_report.seen_stages|=bit;live_report.last_payload=p->payload_bytes;
        if(clock_ok){live_report.last_ns=now;live_report.have_clock=true;}
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_PROGRESS1] seq=%llu stage=%u inFlight=%u opRaw=%lld errnoObserved=%u poisoned=%u reads=%llu ok=%llu failed=%llu requested=%llu completed=%llu payload=%llu hitBytes=%llu clockValid=%u",
            (unsigned long long)d->sequence,d->stage,d->in_flight,(long long)d->raw,d->error_observed,d->poisoned,
            (unsigned long long)p->reads,(unsigned long long)p->completed_reads,(unsigned long long)p->failed_reads,(unsigned long long)p->requested_bytes,
            (unsigned long long)p->completed_bytes,(unsigned long long)p->payload_bytes,(unsigned long long)p->cache_hit_bytes,clock_ok?1u:0u);
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_PROGRESS1] hits=%llu misses=%llu evictions=%llu resident=%llu runs=%llu blocks=%llu maxRead=%llu namedNs=%llu heldNs=%llu openNs=%llu closeNs=%llu preadNs=%llu readNs=%llu readCpuNs=%llu preadCpuNs=%llu pollWaitNs=%llu serviceNs=%llu serviceCpuNs=%llu",
            (unsigned long long)p->cache_hits,(unsigned long long)p->cache_misses,(unsigned long long)p->cache_evictions,(unsigned long long)p->cache_resident,
            (unsigned long long)p->coalesced_runs,(unsigned long long)p->coalesced_blocks,(unsigned long long)p->largest_pread_request,
            (unsigned long long)p->named_stat.nanoseconds,(unsigned long long)p->held_stat.nanoseconds,(unsigned long long)p->open.nanoseconds,
            (unsigned long long)p->close.nanoseconds,(unsigned long long)p->pread.nanoseconds,(unsigned long long)p->read.nanoseconds,
            (unsigned long long)p->read_cpu_ns,(unsigned long long)p->pread_cpu_ns,(unsigned long long)p->poll_wait_ns,
            (unsigned long long)p->service_wall_ns,(unsigned long long)p->service_cpu_ns);
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_PREFETCH1] gameReads=%llu gameBytes=%llu gameNs=%llu steps=%llu bytes=%llu ns=%llu rcvbuf=%llu",
            (unsigned long long)game_stats.reads,(unsigned long long)game_stats.bytes,(unsigned long long)game_stats.ns,
            (unsigned long long)game_stats.prefetch_steps,(unsigned long long)game_stats.prefetch_bytes,(unsigned long long)game_stats.prefetch_ns,
            (unsigned long long)p->socket_rcvbuf);
    }
    errno=saved;
}
// BP_LIVE_DIAGNOSTIC_END
int bp_worker_priority(int upstream){return bp_source_worker_priority(source,upstream);}
void bp_worker_priority_report(int upstream,int requested,int result){
    const int saved=errno;
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_SCHED1] upstream=%d requested=%d result=%d",upstream,requested,result);
    errno=saved;
}
bool bp_worker_initialize(){
    unsigned expected=2;
    if(!metadata_ready.load()||!status.compare_exchange_strong(expected,3))return false;
    finished.store(false);
    int guard_raw=current(nullptr);int guard_error=errno;
    unsigned guard_stage=guard_raw?1u:0u;
    bool attempted=!guard_raw;bp_source *unowned=nullptr;
    bool borrowed=attempted&&source&&cache_owner.compare_exchange_strong(unowned,source);
    int result=!attempted?-ECANCELED:!borrowed?-EBUSY:bp_source_connect_with_storage(source,cache_storage,sizeof cache_storage);
    bool ok=false;
    if(attempted&&result==0){guard_raw=current(nullptr);guard_error=errno;guard_stage=guard_raw?2u:0u;ok=!guard_raw;}
    struct bp_connect_diagnostic diagnostic{};bp_source_connect_diagnostic(source,&diagnostic);
    if(ok)bp_source_observe(source,bp_runtime_source_progress,nullptr);
    status.store(ok?4u:5u);
    int saved=errno;sce::Ampr::Emu::kernelDebugLogf("[BWREAD1] event=worker-connect initAttempted=%u result=%d ready=%u connectStage=%u connectRaw=%d connectErrno=%d optionsReturned=%u connectNtStatus=%u connectNtStatusValid=%u workerGuardStage=%u workerGuardRaw=%d workerGuardErrno=%d",attempted?1u:0u,result,ok?1u:0u,diagnostic.stage,diagnostic.raw,diagnostic.error,diagnostic.options_returned,diagnostic.ntstatus,diagnostic.ntstatus_valid,guard_stage,guard_stage?guard_raw:0,guard_stage?guard_error:0);errno=saved;
    return ok;
}
static void bp_runtime_report_performance(){
    if(!source)return;
    int saved=errno;struct bp_source_performance p{};bp_source_performance(source,&p);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_PERF1] reads=%llu ok=%llu failed=%llu canceled=%llu requested=%llu completed=%llu hitBytes=%llu payload=%llu hits=%llu misses=%llu evictions=%llu resident=%llu scratch=%llu maxRead=%llu",
        (unsigned long long)p.reads,(unsigned long long)p.completed_reads,(unsigned long long)p.failed_reads,(unsigned long long)p.canceled_reads,
        (unsigned long long)p.requested_bytes,(unsigned long long)p.completed_bytes,(unsigned long long)p.cache_hit_bytes,(unsigned long long)p.payload_bytes,
        (unsigned long long)p.cache_hits,(unsigned long long)p.cache_misses,(unsigned long long)p.cache_evictions,(unsigned long long)p.cache_resident,
        (unsigned long long)p.scratch_bytes,(unsigned long long)p.largest_pread_request);
    // Pairs are attempted calls / total monotonic nanoseconds. Read is inclusive;
    // do not add its component metadata/payload times to that inclusive total.
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_PERF1] callsNs named=%llu/%llu held=%llu/%llu open=%llu/%llu close=%llu/%llu pread=%llu/%llu read=%llu/%llu runs=%llu blocks=%llu clockFaults=%llu",
        (unsigned long long)p.named_stat.calls,(unsigned long long)p.named_stat.nanoseconds,(unsigned long long)p.held_stat.calls,(unsigned long long)p.held_stat.nanoseconds,
        (unsigned long long)p.open.calls,(unsigned long long)p.open.nanoseconds,(unsigned long long)p.close.calls,(unsigned long long)p.close.nanoseconds,
        (unsigned long long)p.pread.calls,(unsigned long long)p.pread.nanoseconds,(unsigned long long)p.read.calls,(unsigned long long)p.read.nanoseconds,
        (unsigned long long)p.coalesced_runs,(unsigned long long)p.coalesced_blocks,(unsigned long long)p.clock_failures);
    errno=saved;
}
void bp_worker_finish(){
    canceled.store(true);status.store(6);
    bp_runtime_report_performance();
    if(source)(void)bp_source_disconnect(source);
    bp_source *owner=source;if(owner)(void)cache_owner.compare_exchange_strong(owner,nullptr);
    finished.store(true);
}
bool bp_runtime_metadata_ready(){return metadata_ready.load()&&!canceled.load();}
bool bp_runtime_ready(){return status.load()==4&&!canceled.load();}
bool bp_runtime_failed(){return status.load()>=5;}
int bp_runtime_match(const char *path,size_t length,uint64_t bytes,uint32_t *id){
    metadata_users.fetch_add(1);
    int result=bp_runtime_metadata_ready()?bp_source_match(source,path,length,bytes,id):-1;
    if(result==1&&bp_runtime_failed())result=-1;
    metadata_users.fetch_sub(1);return result;
}
int64_t bp_runtime_read(uint32_t id,uint64_t at,void *out,size_t size,const std::atomic<bool> *cancel,struct bp_read_witness *witness){
    if(witness)*witness={};
    if(!bp_runtime_ready())return canceled.load()?-ECANCELED:-EIO;
    job_cancel=cancel;uint64_t began=monotonic_ns();
    int64_t result=!first_read.emitted&&witness?bp_source_read_observed(source,id,at,out,size,witness):bp_source_read(source,id,at,out,size);
    job_cancel=nullptr;
    uint64_t ended=monotonic_ns();game_stats.reads++;if(ended>=began&&began)game_stats.ns+=ended-began;
    if(result>0){
        game_stats.bytes+=(uint64_t)result;uint64_t end=at+(uint64_t)result;
        PrefetchStream *slot=nullptr,*victim=&prefetch_streams[0];
        for(auto& s:prefetch_streams){if(s.active&&s.id==id){slot=&s;break;}if(!s.active||s.used<victim->used)victim=&s;}
        if(slot&&at+kPrefetchGap>=slot->next&&at<=slot->next+kPrefetchGap){
            if(end>slot->next)slot->next=end;if(slot->ahead<slot->next)slot->ahead=slot->next;slot->hits++;
        }else{if(!slot)slot=victim;*slot=PrefetchStream{id,end,end,0,1,true,false};}
        slot->used=++prefetch_clock;
    }
    return result;
}
static PrefetchStream *prefetch_candidate(){
    if(!bp_runtime_ready()||!first_read.emitted)return nullptr;
    PrefetchStream *best=nullptr;
    for(auto& s:prefetch_streams)if(s.active&&!s.done&&s.hits>=2&&s.ahead<s.next+kPrefetchAhead&&(!best||s.ahead-s.next<best->ahead-best->next))best=&s;
    return best;
}
bool bp_runtime_prefetch_pending(){AmprLockGuard guard(primary_mutex());return prefetch_candidate()!=nullptr;}
void bp_runtime_prefetch_step(){
    AmprLockGuard guard(primary_mutex());
    PrefetchStream *s=prefetch_candidate();if(!s)return;
    uint64_t began=monotonic_ns();job_cancel=nullptr;
    int64_t got=bp_source_read(source,s->id,s->ahead,prefetch_buffer,kPrefetchStep);
    uint64_t ended=monotonic_ns();if(ended>=began&&began)game_stats.prefetch_ns+=ended-began;
    game_stats.prefetch_steps++;
    if(got>0){s->ahead+=(uint64_t)got;game_stats.prefetch_bytes+=(uint64_t)got;}else s->done=true;
}
uint64_t bp_runtime_now_ns(){return monotonic_ns();}
bool bp_runtime_slicing_ready(){return bp_runtime_ready()&&first_read.emitted;}
void bp_runtime_note_queue(uint32_t depth){
    AmprLockGuard guard(lat_mutex());
    if(depth>lat.depth_peak)lat.depth_peak=depth;if(depth>lat.session_depth_peak)lat.session_depth_peak=depth;
}
void bp_runtime_record_request(const struct bp_request_sample *s){
    if(!s||!s->queued_ns)return;
    AmprLockGuard guard(lat_mutex());
    uint64_t total=s->done_ns>s->queued_ns?(s->done_ns-s->queued_ns)/1000u:0;
    uint64_t queue=s->start_ns>s->queued_ns?(s->start_ns-s->queued_ns)/1000u:0;
    uint64_t service=s->service_ns/1000u;
    unsigned c=s->work_class<kLatClasses?s->work_class:1u,prio=s->priority<kLatPriorities?s->priority:kLatPriorities-1u;
    lat_add(lat.window[c],s->bytes,total,queue,service,s->failed);lat_add(lat.session[c],s->bytes,total,queue,service,s->failed);
    lat.prio_n[prio]++;lat.prio_slow[prio]+=total>33000;
    lat.size_bins[log2_bin(s->bytes,kSizeBins)]++;
    lat_file(s->id,s->bytes,c==0,total>16000,total);
    if(!lat.last_log)lat.last_log=s->done_ns;
    // Game exit kills the process without a worker stop, so session totals
    // are re-emitted every sixth window instead of only at shutdown.
    if(s->done_ns>=lat.last_log+5000000000ull){
        lat_log_window();lat.last_log=s->done_ns;
        if(++lat.windows%6==0)lat_report_session();
    }
}
void bp_runtime_report_read(const struct bp_read_witness *witness,int64_t completed){
    AmprLockGuard guard(primary_mutex());
    int saved=errno;char line[512];
    if(bp_first_read_format(&first_read,witness,completed,current(nullptr),line,sizeof line)>0)
        sce::Ampr::Emu::kernelDebugLogf("%s",line);
    errno=saved;
}
static void lane_start(uint32_t worker){
    if(lane_status.load()!=2||!metadata_ready.load()||canceled.load()){
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LANE1] event=unavailable worker=%u status=%u",worker,lane_status.load());return;
    }
    // The game heap refuses this size; AMPR's own pool backs its worker buffers.
    size_t granted=0;
    lane_storage=static_cast<uint8_t*>(ampr_internal_amm_pool_alloc(kLaneCacheBytes,&granted,"bw.lane.cache",false,64u));
    if(lane_storage&&granted<kLaneCacheBytes){(void)ampr_internal_amm_pool_free(lane_storage,"bw.lane.cache.short");lane_storage=nullptr;}
    int result=lane_storage?bp_source_connect_with_storage(lane_source,lane_storage,kLaneCacheBytes):-ENOMEM;
    lane_status.store(result?5u:4u);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LANE1] event=connect worker=%u result=%d cacheMiB=%u",worker,result,(unsigned)(kLaneCacheBytes>>20));
}
static void lane_log(uint64_t now){
    if(now<lane_stats.last_log+5000000000ull)return;
    lane_stats.last_log=now;struct bp_source_performance p{};bp_source_performance(lane_source,&p);
    sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LANE1] reads=%llu bytes=%llu ns=%llu fallbacks=%llu payload=%llu hits=%llu misses=%llu serviceNs=%llu pollWaitNs=%llu status=%u",
        (unsigned long long)lane_stats.reads,(unsigned long long)lane_stats.bytes,(unsigned long long)lane_stats.ns,(unsigned long long)lane_stats.fallbacks,
        (unsigned long long)p.payload_bytes,(unsigned long long)p.cache_hits,(unsigned long long)p.cache_misses,
        (unsigned long long)p.service_wall_ns,(unsigned long long)p.poll_wait_ns,lane_status.load());
}
void bp_worker_start(uint32_t worker,uint32_t workers){
    uint32_t none=kNoWorker;
    if(workers>1&&worker==0&&lane_owner.compare_exchange_strong(none,worker))lane_start(worker);
    none=kNoWorker;
    if((workers<=1||worker+1==workers)&&primary_owner.compare_exchange_strong(none,worker)){
        AmprLockGuard guard(primary_mutex());(void)bp_worker_initialize();
    }
}
int64_t bp_runtime_read_job(uint32_t worker,bool bulk,uint32_t id,uint64_t at,void *out,size_t size,const std::atomic<bool> *cancel,struct bp_read_witness *witness){
    if(!bulk&&worker==lane_owner.load()&&lane_status.load()==4&&!canceled.load()){
        lane_cancel=cancel;uint64_t began=monotonic_ns();
        int64_t result=bp_source_read(lane_source,id,at,out,size);
        lane_cancel=nullptr;uint64_t ended=monotonic_ns();
        lane_stats.reads++;if(ended>=began&&began)lane_stats.ns+=ended-began;if(result>0)lane_stats.bytes+=(uint64_t)result;
        if(result>=0||result==-ECANCELED){lane_log(ended);return result;}
        // A failed lane is retired; this and later reads use the primary.
        lane_status.store(5);lane_stats.fallbacks++;
        sce::Ampr::Emu::kernelDebugLogf("[BWREAD_LANE1] event=retired result=%lld",(long long)result);
    }
    AmprLockGuard guard(primary_mutex());
    uint32_t none=kNoWorker;
    if(status.load()==2&&primary_owner.compare_exchange_strong(none,worker))(void)bp_worker_initialize();
    return bp_runtime_read(id,at,out,size,cancel,witness);
}
void bp_worker_stop(uint32_t worker){
    if(worker==lane_owner.load()&&lane_source){
        unsigned state=lane_status.load();if(state==4||state==5)(void)bp_source_disconnect(lane_source);lane_status.store(6);
    }
    if(worker==primary_owner.load()){AmprLockGuard guard(primary_mutex());bp_worker_finish();}
}
int bp_lane_release(){
    if(lane_owner.load()!=kNoWorker&&lane_status.load()==4)return -1;
    int result=lane_source?bp_source_close(lane_source):0;lane_source=nullptr;
    if(lane_storage)(void)ampr_internal_amm_pool_free(lane_storage,"bw.lane.cache");lane_storage=nullptr;return result;
}
void bp_runtime_cancel(){canceled.store(true);status.store(6);}
int bp_runtime_release(){
    bp_runtime_cancel();if(metadata_users.load()||cache_owner.load()||(source&&!finished.load()))return -1;
    metadata_ready.store(false);int result=bp_source_close(source);source=nullptr;return result;
}
