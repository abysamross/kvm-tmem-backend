#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/cleancache.h>
#include <linux/tmem.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
//#include <linux/spinlock.h>
#include "bloom_filter.h"
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/kthread.h>

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>

#include "ktb.h"
#include "network_tcp.h"

#define mtp_debug 0
#define mtp_debug_spl 0
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

/* evict == 0 -> static eviction, evict == 1 -> dynamic eviction
   static int evict = 0;
   module_param(evict, int, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
   MODULE_PARM_DESC(evict, "Argument that specifies eviction policy");
   */
static int delaytff = 120;
static int delaykrf = 180;
int dynamic_eviction = 0;
int static_eviction = 1;
int bflt_bit_size = 268435456;
int timed_fwd_filter_stopped = 0;
int ktb_eviction_thread_stopped = 0;
uint64_t system_unique_pages = 0;
int64_t sevict_count = 0;
int64_t devict_count = 0;

void *test_page_vaddr;

static struct tmem_client *ktb_all_clients[MAX_CLIENTS];
struct task_struct *fwd_bflt_thread = NULL;
struct task_struct *ktb_eviction_thread = NULL;
struct bloom_filter* tmem_system_bloom_filter;
struct kmem_cache* tmem_page_descriptors_cachep;
struct kmem_cache* tmem_page_content_desc_cachep;
struct kmem_cache* tmem_objects_cachep;
static struct kobject *kvm_tmem_bknd_devict;
struct page *test_page;
struct tmem_page_content_descriptor *test_pcd;
//struct kmem_cache* tmem_object_nodes_cachep;

struct tmem_system_view tmem_system;

/*
   struct rb_root pcd_tree_roots[256]; 
   rwlock_t pcd_tree_rwlocks[256]; 
   DEFINE_RWLOCK(id_rwlock);
   */
/******************************************************************************/ 
/*                                                      List global variables */
/******************************************************************************/ 
//DEFINE_SPINLOCK(client_list_lock);
/******************************************************************************/ 
/*                                                  End list global variables */
/******************************************************************************/ 

/******************************************************************************/ 
/*                                                           Debuggging flags */
/******************************************************************************/ 
int debug_ktb_new_pool = 0;
int debug_ktb_destroy_pool = 0;
int debug_ktb_put_page = 0;
int debug_ktb_dup_put_page = 0;
int debug_ktb_get_page = 0;
int debug_ktb_remotified_get_page = 0;
int debug_ktb_flush_page = 0;
int debug_ktb_flush_object = 0;
int debug_pcd_associate = 0;
int debug_pcd_remote_associate = 0;
int debug_pcd_disassociate = 0;
int debug_ktb_destroy_client = 0;
int debug_tmem_pool_destroy_objs = 0;
int debug_tmem_pgp_destroy = 0;
int debug_tmem_pgp_free = 0;
int debug_tmem_pgp_free_data = 0;
int debug_custom_radix_tree_destroy = 0;
int debug_custom_radix_tree_node_destroy = 0;
int debug_update_bflt = 0;
int debug_bloom_filter_add = 0;
int debug_bloom_filter_check = 0;
int debug_timed_fwd_filter = 0;
int debug_ktb_remotify_puts = 0;
int debug_pcd_add_to_remote_tree = 0;
int debug_tmem_pcd_status_update = 0;
int debug_ktb_remote_get = 0;
int debug_tmem_remotified_copy_to_client = 0;

int show_msg_ktb_new_pool = 0;
int show_msg_ktb_destroy_pool = 0;
int show_msg_ktb_put_page = 0;
int show_msg_ktb_dup_put_page = 0;
int show_msg_ktb_get_page = 0;
int show_msg_ktb_remotified_get_page = 0;
int show_msg_ktb_flush_page = 0;
int show_msg_ktb_flush_object = 0;
int show_msg_pcd_associate = 0;
int show_msg_pcd_remote_associate = 0;
int show_msg_pcd_disassociate = 0;
int show_msg_ktb_destroy_client = 0;
int show_msg_tmem_pool_destroy_objs = 0;
int show_msg_tmem_pgp_destroy = 0;
int show_msg_tmem_pgp_free = 0;
int show_msg_tmem_pgp_free_data = 0;
int show_msg_custom_radix_tree_destroy = 0;
int show_msg_custom_radix_tree_node_destroy = 0;
int show_msg_update_bflt = 0;
int show_msg_bloom_filter_add = 0;
int show_msg_bloom_filter_check = 0;
int show_msg_timed_fwd_filter = 0;
int show_msg_ktb_remotify_puts = 0;
int show_msg_pcd_add_to_remote_tree = 0;
int show_msg_tmem_pcd_status_update = 0;
int show_msg_ktb_remote_get = 0;
int show_msg_tmem_remotified_copy_to_client = 0;
/******************************************************************************/ 
/*                                                       End debuggging flags */
/******************************************************************************/ 

/******************************************************************************/ 
/*                                                         Debugfs files/vars */
/******************************************************************************/ 
struct dentry *root = NULL;
u64 test_remotify;
u64 test_remotify_succ;
u64 test_remotify_fail;

u64 test_remotified_get;
u64 test_remotified_get_succ;
u64 test_remotified_get_fail;

u64 tmem_puts;
u64 succ_tmem_puts;
u64 failed_tmem_puts;

u64 tmem_remotify_puts;
u64 succ_tmem_remotify_puts;
u64 failed_tmem_remotify_puts;
/***************************/
u64 tmem_gets;
u64 succ_tmem_gets;
u64 failed_tmem_gets;

u64 tmem_remotified_gets;
u64 succ_tmem_remotified_gets;
u64 failed_tmem_remotified_gets;

u64 gets_from_remote;
u64 succ_gets_from_remote;
u64 failed_gets_from_remote;
/***************************/
u64 tmem_dedups;
u64 succ_tmem_dedups;
u64 failed_tmem_dedups;

u64 tmem_remote_dedups;
u64 succ_tmem_remote_dedups;
u64 failed_tmem_remote_dedups;
/***************************/
u64 tmem_invalidates;
u64 succ_tmem_invalidates;
u64 failed_tmem_invalidates;

u64 tmem_inode_invalidates;
u64 succ_tmem_inode_invalidates;
u64 failed_tmem_inode_invalidates;

u64 tmem_page_invalidates;
u64 succ_tmem_page_invalidates;
u64 failed_tmem_page_invalidates;
/******************************************************************************/ 
/*                                                     End Debugfs files/vars */
/******************************************************************************/ 

static ssize_t devict_read(struct kobject *kobj, struct kobj_attribute *attr,
                char *buf)
{
        return sprintf(buf, "%lld\n", devict_count);

}

static ssize_t devict_write(struct kobject *kobj, struct kobj_attribute *attr,
                const char *buf, size_t count)
{
        int ret;
        ret = kstrtoll(buf, 10, &devict_count);
        if(ret < 0)
                return ret;

        return count;
}

static ssize_t dynamic_eviction_read(struct kobject *kobj, struct kobj_attribute
                *attr, char *buf)
{
        return sprintf(buf, "%d\n", dynamic_eviction);

}

static ssize_t dynamic_eviction_write(struct kobject *kobj, struct kobj_attribute
                *attr, const char *buf, size_t count)
{
        int ret;
        ret = kstrtoint(buf, 10, &dynamic_eviction);
        if(ret < 0)
                return ret;

        return count;
}

static struct kobj_attribute devict_count_attribute = 
__ATTR(devict_count, 0664, devict_read, devict_write);

static struct kobj_attribute dynamic_eviction_attribute = 
__ATTR(dynamic_eviction, 0664, dynamic_eviction_read, dynamic_eviction_write);

static struct attribute *devict_attrs[] = {
        &devict_count_attribute.attr,
        &dynamic_eviction_attribute.attr,
        NULL,
};

static struct attribute_group devict_attr_group = {
        .attrs  = devict_attrs,
};
/******************************************************************************/
/*			                          bloom filter transfer thread*/
/******************************************************************************/
int timed_fwd_filter(void* data)
{
        int ret;
        unsigned long jleft = 0;
        unsigned long long rdtscstart = 0;
        unsigned long long rdtscstop = 0;

        struct bloom_filter *bflt = (struct bloom_filter *)data;

        //DECLARE_WAIT_QUEUE_HEAD(timed_fflt_wait);

        allow_signal(SIGKILL|SIGSTOP);

        //set_freezable();

        /*
           while(!kthread_should_stop())
           {
           */
        set_current_state(TASK_INTERRUPTIBLE);

        jleft = schedule_timeout(delaytff*HZ);

        if(can_show(timed_fwd_filter))
                pr_info("*** mtp | Bloom filter transfer timer expired!"
                                " TIMER VALUE: %lu secs | timed_fwd_filter"
                                " *** \n", (jleft/HZ));

        /*for now reset these counters
          tmem_remote_dedups = 0;
          succ_tmem_remote_dedups = 0;
          failed_tmem_remote_dedups = 0;
          */
        //__set_current_state(TASK_RUNNING);

        /*
           if(signal_pending(current))
           {
           goto exit_timed_fwd_filter;
           }
           */
        rdtscll(rdtscstart);
        ret = tcp_client_fwd_filter(bflt);
        rdtscll(rdtscstop);
        pr_info("rdtscll:timed_fwd_filter: %llu\n",
                (rdtscstop - rdtscstart));

        if( ret < 0)
        {
                if(can_show(timed_fwd_filter))
                        pr_info(" *** mtp | tcp_client_fwd_filter 2"
                                        " attmepts failed |"
                                        " timed_fwd_filter *** \n");
        }
        //remote_puts();
        //set_current_state(TASK_INTERRUPTIBLE);
        /*
           }
           */
        //__set_current_state(TASK_RUNNING);

exit_timed_fwd_filter:

        timed_fwd_filter_stopped = 1;
        return 0;
        //do_exit(0);
}

int start_fwd_filter(struct bloom_filter *bflt)
{
        fwd_bflt_thread = 
                kthread_run((void *)timed_fwd_filter, (void *)bflt, "fwd_bflt");

        if(fwd_bflt_thread == NULL)
                return -1;

        get_task_struct(fwd_bflt_thread);

        return 0;
}
/******************************************************************************/
/*			                      End bloom filter transfer thread*/
/******************************************************************************/

/******************************************************************************/
/*			                                       eviction thread*/
/******************************************************************************/
int ktb_remotify_puts(void);
int start_eviction_thread(void)
{
        ktb_eviction_thread = 
                kthread_run((void *)ktb_remotify_puts, NULL, "ktb_eviction_thread");

        if(ktb_eviction_thread == NULL)
        {
                pr_info(" *** mtp | could not start eviction thread |"
                                " start_eviction_thread ***\n");
                return -1;
        }

        get_task_struct(ktb_eviction_thread);

        return 0;
}
/******************************************************************************/
/*			                                   End eviction thread*/
/******************************************************************************/
/******************************************************************************/
/*							  ktb helper functions*/
/******************************************************************************/
//Get a client with client ID if one exists
struct tmem_client* ktb_get_client_by_id(int client_id)
{
        //struct tmem_client* client = &ktb_host;
        struct tmem_client* client = NULL;

        //return NULL if Max number of clients exceeded
        if (client_id >= MAX_CLIENTS)
                goto out;

        //return a pointer to a client 
        client = ktb_all_clients[client_id];
out:
        return client;
}

void show_client_pool_info(struct tmem_client* client, struct tmem_pool* pool)
{
        struct tmem_client* tmp_cli = pool->associated_client;
        //pr_info("\nClient Info\n");
        //pr_info("***********\n");
        //pr_info("Client refcount: %d\n", client->refcount.counter);
        //pr_info("tmp_cli->refcount.counter %d\n", tmp_cli->refcount.counter);
        //pr_info("-------------------\n");

        pr_info("\nPool Info via Client\n");
        pr_info("*********\n");

        pr_info("pool->pool_id: %u\n", pool->pool_id);
        pr_info("client->this_client_all_pools[pool->pool_id]->pool_id): %u\n",
                        client->this_client_all_pools[pool->pool_id]->pool_id);
        pr_info("tmp_cli->this_client_all_pools[pool->id]->pool_id %u\n",
                        tmp_cli->this_client_all_pools[pool->pool_id]->pool_id);

        //pr_info("pool->refcount: %d\n", pool->refcount.counter);
        //pr_info("client->this_client_all_pools[pool->pool_id]->refcount.counter):
        //%d\n", client->this_client_all_pools[pool->pool_id]->refcount.counter);

        pr_info("pool->uuid[0]: %llu\n", pool->uuid[0]);
        pr_info("client->this_client_all_pools[pool->pool_id]->uuid[0]): %llu\n",
                        client->this_client_all_pools[pool->pool_id]->uuid[0]);

        pr_info("pool->uuid[1]: %llu\n", pool->uuid[1]);
        pr_info("client->this_client_all_pools[pool->pool_id]->uuid[1]): %llu\n",
                        client->this_client_all_pools[pool->pool_id]->uuid[1]);
        pr_info("-------------------\n");
}
/******************************************************************************/
/*						   End of ktb helper functions*/
/******************************************************************************/

/******************************************************************************/
/*                           					 KTB FUNCTIONS*/
/******************************************************************************/
static int ktb_create_client(int client_id)
{
        struct tmem_client *client = NULL;

        if (client_id >= MAX_CLIENTS)
                goto out;

        client = ktb_get_client_by_id(client_id);

        /*a client already present at that id*/
        if(client != NULL)
                goto out;

        client = kmalloc(sizeof(struct tmem_client), GFP_ATOMIC);

        if(client == NULL)
                goto out;

        memset(client, 0, sizeof(struct tmem_client));

        client->client_id = client_id;
        client->allocated = 1;

        //INIT_LIST_HEAD(&client->remote_sharing_candidate_list);
        //INIT_LIST_HEAD(&client->local_only_list);

        ktb_all_clients[client_id] = client;
        return 0;
out:
        return -1;
}

static int ktb_destroy_client(int client_id)
{
        int poolid = -1;
        struct tmem_pool *pool = NULL;
        struct tmem_client *client = NULL;
        int ret = -1;

        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_destroy_client))
                        pr_info(" *** mtp: %s %s %d | No such client possible: "
                                        "%d | ktb_destroy_client *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);

                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_destroy_client))
                        pr_info(" *** mtp: %s %s %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_destroy_client *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        for(poolid = 0, ret = 0; poolid < MAX_POOLS_PER_CLIENT; poolid++)
        {
                if(client->this_client_all_pools[poolid] != NULL)
                {
                        pool = client->this_client_all_pools[poolid];
                        tmem_flush_pool(pool, client_id);
                        client->this_client_all_pools[poolid] = NULL;
                        ret++;
                }
        }

        if(ret == 0)
        {
                if(can_debug(ktb_destroy_client))
                        pr_info(" *** mtp: %s %s %d | client: %d does not have "
                                        "any valid pools | ktb_destroy_client *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
        }

        client->allocated = 0;
        kfree(client);
        ktb_all_clients[client_id] = NULL;

        if(can_show(ktb_destroy_client))
                pr_info(" *** mtp | successfully destroyed client: %d, flushed:"
                                " %d pools | ktb_destroy_client *** \n ",
                                client_id, ret);
out:
        return ret;
}
//static int ktb_flush_object(struct tmem_pool* pool, struct tmem_oid* oidp)
static unsigned long int ktb_flush_object(int client_id, int32_t pool_id, \
                struct tmem_oid *oidp)
{
        struct tmem_object_root *obj;
        struct tmem_pool *pool;
        struct tmem_client *client;
        unsigned int oidp_hash = tmem_oid_hash(oidp);
        int ret = -1;

        tmem_invalidates++;
        tmem_inode_invalidates++;

        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_flush_object))
                        pr_info(" *** mtp: %s %s %d | No such client possible: "
                                        "%d | ktb_flush_object*** \n ",
                                        __FILE__, __func__, __LINE__, client_id);

                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_flush_object))
                        pr_info(" *** mtp: %s %s %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_flush_object*** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        pool = client->this_client_all_pools[pool_id];

        if(unlikely(pool == NULL))
        {
                if(can_debug(ktb_flush_object))
                        pr_info(" *** mtp: %s %s %d | Client: %d doesn't have "
                                        "a valid POOL | ktb_flush_object*** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        obj = tmem_obj_find(pool,oidp);

        if(obj == NULL)
        {
                if(can_debug(ktb_flush_object))
                        pr_info(" *** mtp: %s %s %d | could not find the "
                                        "object: %llu %llu %llu rooted at rb_tree "
                                        "slot: %u in pool: %u of client: %u | "
                                        "ktb_flush_object*** \n",
                                        __FILE__, __func__, __LINE__,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);
                goto out;
        }


        write_lock(&pool->pool_rwlock);
        tmem_obj_destroy(obj);
        write_unlock(&pool->pool_rwlock);

        if(can_show(ktb_flush_object))
                pr_info(" *** mtp | successfully deleted object: %llu %llu %llu"
                                " rooted at rb_tree slot: %u of pool: %u of client: %u "
                                " ktb_flush_object*** \n", oidp->oid[2], oidp->oid[1],
                                oidp->oid[0], oidp_hash, pool->pool_id,
                                pool->associated_client->client_id);

        succ_tmem_invalidates++;
        succ_tmem_inode_invalidates++;
        return 0;

out:
        failed_tmem_invalidates++;
        failed_tmem_inode_invalidates++;
        return ret;
}

//static unsigned long int ktb_flush_page(struct tmem_pool *pool, struct
//tmem_oid *oidp, uint32_t index)
static unsigned long int ktb_flush_page(int client_id, int32_t pool_id, \
                struct tmem_oid *oidp, uint32_t index)
{
        struct tmem_object_root *obj;
        struct tmem_page_descriptor *pgp;
        struct tmem_pool *pool;
        struct tmem_client *client;
        unsigned int oidp_hash = tmem_oid_hash(oidp);
        int ret = -1;

        tmem_invalidates++;
        tmem_page_invalidates++;

        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_flush_page))
                        pr_info(" *** mtp: %s %s %d | No such client possible: "
                                        "%d | ktb_flush_page *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);

                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_flush_page))
                        pr_info(" *** mtp: %s %s %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_flush_page *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        pool = client->this_client_all_pools[pool_id];

        //pool = ktb_get_pool_by_id(client_id, pool_id);

        if(unlikely(pool == NULL))
        {
                if(can_debug(ktb_flush_page))
                        pr_info(" *** mtp: %s %s %d | Client: %d doesn't have "
                                        "a valid POOL | ktb_flush_page *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        obj = tmem_obj_find(pool,oidp);

        if (obj == NULL)
        {
                if(can_debug(ktb_flush_page))
                        pr_info(" *** mtp: %s %s %d | could not find the "
                                        "object: %llu %llu %llu rooted at rb_tree "
                                        "slot: %u in pool: %u of client: %u | "
                                        "ktb_flush_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                goto out;
        }

        pgp = tmem_pgp_delete_from_obj(obj, index);

        if (pgp == NULL)
        {
                if(can_debug(ktb_flush_page))
                        pr_info(" *** mtp: %s %s %d | could not delete page "
                                        "descriptor for page with index: %u of object: "
                                        "%llu %llu %llu rooted at rb_tree slot: %u of "
                                        "pool: %u of client: %u | ktb_flush_page *** \n",
                                        __FILE__, __func__, __LINE__, index,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                spin_unlock(&obj->obj_spinlock);
                goto out;
        }

        tmem_pgp_delist_free(pgp);
        //tmem_pgp_free(pgp);

        if(obj->pgp_count == 0)
        {
                write_lock(&pool->pool_rwlock);
                tmem_obj_free(obj);
                write_unlock(&pool->pool_rwlock);
        }
        else
        {
                spin_unlock(&obj->obj_spinlock);
        }
        if(can_show(ktb_flush_page))
                pr_info(" *** mtp | successfully deleted page with index: %u "
                                "from object: %llu %llu %llu rooted at rb_tree slot: %u"
                                " of pool: %u of client: %u | ktb_flush_page *** \n",
                                index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                oidp_hash, pool->pool_id, client->client_id);

        succ_tmem_invalidates++;
        succ_tmem_page_invalidates++;
        return 0;

out:
        failed_tmem_invalidates++;
        failed_tmem_page_invalidates++;
        return (unsigned long)ret;
}

int ktb_remote_get(struct page *page, uint8_t firstbyte,\
                uint64_t id)
{
        int ret = 0;
        //unsigned long index = (unsigned long) id;
        void *vaddr1, *vaddr2;
        struct tmem_page_content_descriptor *pcd;
        struct radix_tree_root *root = 
                &(tmem_system.pcd_remote_tree_roots[firstbyte]);

        vaddr1 = page_address(page);
        memset(vaddr1, 0, PAGE_SIZE);

        if(can_show(ktb_remote_get))
                pr_info(" *** mtp | Looking for remote page with remote id: %llu"
                                " in pcd_remote_tree_roots[%u] | ktb_remote_get ***\n",
                                id, firstbyte);

        read_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
        read_lock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));
        gets_from_remote++;
        /*
         * you may or may not delete this page from the pcd_remote_tree_roots
         * radix tree. Better let it remain there itself. It's of no consequence
         * and most ly you just loose one unique remote_id to it. More important
         * point is the removal of this pcd and it's memory will happen only
         * when no more local VMs refer to it.
         */
        pcd = (struct tmem_page_content_descriptor *)radix_tree_lookup(root,
                        id);

        if(pcd == NULL)
        {
                ret = -1;
                failed_gets_from_remote++;
                goto rget_unlock;
        }
        /*
         * shoud not be a remotified page.
         */
        BUG_ON(pcd->status == 2);
        vaddr2 = page_address(pcd->system_page);
        memcpy(vaddr1, vaddr2, PAGE_SIZE);
        succ_gets_from_remote++;

        if(can_show(ktb_remote_get))
                pr_info(" *** mtp | remote page: %llu was present in"
                                " pcd_remote_tree_roots[%u] | ktb_remote_get ***\n", id,
                                firstbyte);

rget_unlock:

        read_unlock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));
        read_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
        return ret;
}

int ktb_remotified_get_page(struct page *page, char *ip, uint8_t firstbyte, 
                uint64_t remote_id)
{
        int ret = -1;
        struct remote_server *rs_tmp;

        if(can_show(ktb_remotified_get_page))
                pr_info(" *** mtp | trying to get remotified page from: %s, with id:"
                                " %llu having firstbyte: %u,| ktb_remotified_get_page ***\n",
                                ip, remote_id, firstbyte);

        down_read(&rs_rwmutex);
        //read_lock(&rs_rwspinlock);
        if(can_debug(ktb_remotified_get_page))
                pr_info(" *** mtp | down_read SUCC: trying to get remotified page "
                                " from: %s, with id: %llu having firstbyte: %u,|"
                                " ktb_remotified_get_page ***\n", ip, remote_id, firstbyte);
        if(!(list_empty(&rs_head)))
        {
                list_for_each_entry(rs_tmp, &(rs_head), rs_list)
                {
                        //up_read(&rs_rwmutex);
                        //read_unlock(&rs_rwspinlock);

                        if(strcmp(rs_tmp->rs_ip, ip) == 0)
                        {
                                int rr = 0;
                                unsigned long long rdtscstart;
                                unsigned long long rdtscstop;

                                if(can_show(ktb_remotified_get_page))
                                        pr_info(" *** mtp | found remote server"
                                                        " info:\n | ip-> %s | port-> %d"
                                                        " | ktb_remotified_get_page"
                                                        " ***\n", rs_tmp->rs_ip,
                                                        rs_tmp->rs_port);

                                rdtscll(rdtscstart);
                                rr = 
                                tcp_client_no_wait_remotified_get(rs_tmp,page,\
                                                firstbyte,remote_id);
                                rdtscll(rdtscstop);
                                pr_info("rdtscll:tcp_client_no_wait_remotified_"
                                        "get %llu\n", (rdtscstop - rdtscstart));

                                if(rr < 0)
                                {
                                        if(can_show(ktb_remotified_get_page))
                                                pr_info(" *** mtp | page with"
                                                                " firsbyte:" " %u,"
                                                                " remote id: %llu was"
                                                                " NOT FOUND with RS: %s"
                                                                " | ktb_remotified_get_"
                                                                " page ***\n", 
                                                                firstbyte, remote_id,
                                                                rs_tmp->rs_ip);
                                }
                                else
                                {
                                        ret = 0;
                                        if(can_show(ktb_remotified_get_page))
                                                pr_info(" *** mtp | page with"
                                                                " firsbyte: %u, remote"
                                                                " id: %llu was FOUND"
                                                                " with RS: %s | ktb_"
                                                                " remotified_get_page"
                                                                " ***\n", firstbyte,
                                                                remote_id,rs_tmp->rs_ip);
                                }

                                up_read(&rs_rwmutex);
                                if(can_debug(ktb_remotified_get_page))
                                        pr_info(" *** mtp | up_read SUCC: trying to"
                                                        " get remotified page from: %s, with"
                                                        " id: %llu having firstbyte: %u,|"
                                                        " ktb_remotified_get_page ***\n", ip,
                                                        remote_id, firstbyte);
                                return ret;
                        }
                        //read_lock(&rs_rwspinlock);
                        //down_read(&rs_rwmutex);
                }
        }
        //else
        //read_unlock(&rs_rwspinlock);
        up_read(&rs_rwmutex);
        if(can_debug(ktb_remotified_get_page))
                pr_info(" *** mtp | up_read SUCC: trying to"
                                " get remotified page from: %s, with"
                                " id: %llu having firstbyte: %u,|"
                                " ktb_remotified_get_page ***\n", ip,
                                remote_id, firstbyte);
        return ret;
}

static unsigned long int ktb_get_page(int client_id, int32_t pool_id, \
                struct tmem_oid *oidp, uint32_t index, struct page *client_page)
{
        struct tmem_pool* pool;
        struct tmem_object_root *obj = NULL;
        struct tmem_page_descriptor *pgp = NULL;
        struct tmem_client *client = NULL;
        unsigned int oidp_hash = tmem_oid_hash(oidp);
        int rc = -1;

        //pool->gets++;
        tmem_gets++;

        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s %s %d | No such client possible: "
                                        "%d | ktb_get_page *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s %s %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_get_page *** \n ",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }

        pool = client->this_client_all_pools[pool_id];

        //pool = ktb_get_pool_by_id(client_id, pool_id);

        if(unlikely(pool == NULL))
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s, %s, %d | Client: %d doesn't have"
                                        " a valid POOL | ktb_get_page *** \n",
                                        __FILE__, __func__, __LINE__, client_id);
                goto out;
        }


        if(can_show(ktb_get_page))
                pr_info(" *** mtp | Searching for object: %llu %llu %llu at "
                                "rb_tree slot: %u of pool: %u of client: %u | "
                                "ktb_get_page *** \n",
                                oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                oidp_hash, pool->pool_id, client->client_id);

        obj = tmem_obj_find(pool,oidp);

        if ( obj == NULL )
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s, %s, %d | object: %llu %llu %llu"
                                        " does not exist | ktb_get_page*** \n",
                                        __FILE__, __func__, __LINE__,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0]);
                goto out;
        }

        if(can_show(ktb_get_page))
                pr_info(" *** mtp | object: %llu %llu %llu found at "
                                "rb_tree slot: %u of pool: %u of client: %u | "
                                "ktb_get_page *** \n",
                                oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                oidp_hash, pool->pool_id, client->client_id);

        ASSERT_SPINLOCK(&obj->obj_spinlock);
        pgp = tmem_pgp_delete_from_obj(obj, index);

        if ( pgp == NULL )
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s %s %d | could not delete ktb pgp "
                                        "for index: %u, object: %llu %llu %llu, rooted "
                                        "at rb_tree slot: %u of pool: %u of client: %u "
                                        "| ktb_get_page *** \n",
                                        __FILE__, __func__, __LINE__, index,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                spin_unlock(&obj->obj_spinlock);
                goto out;
        }

        ASSERT(pgp->size != -1);

        /*If local dedup is enabled*/
        if(kvm_tmem_dedup_enabled && (pgp->firstbyte != NOT_SHAREABLE))
                rc = tmem_pcd_copy_to_client(client_page, pgp);
        else
                rc = tmem_copy_to_client(client_page, pgp->tmem_page);

        if ( rc < 0 )
        {
                rc = -1;
                goto bad_copy;
        }

        if(can_show(ktb_get_page))
                pr_info(" *** mtp | copied contents of index: %u, object: "
                                "%llu %llu %llu having firstbyte: %u, rooted at "
                                "rb_tree slot: %u of pool: %u of client: %u | "
                                "ktb_get_page *** \n", index, oidp->oid[2], oidp->oid[1],
                                oidp->oid[0], pgp->firstbyte, oidp_hash, pool->pool_id,
                                client->client_id);

        tmem_pgp_delist_free(pgp);
        //tmem_pgp_free(pgp);

        /*I doubt if any part of the previous code dcrements obj->pgp_count*/
        if (obj->pgp_count == 0)
        {
                write_lock(&pool->pool_rwlock);
                tmem_obj_free(obj);
                obj = NULL;
                write_unlock(&pool->pool_rwlock);
        }

        if ( obj != NULL )
        {
                spin_unlock(&obj->obj_spinlock);
        }
        else
        {
                if(can_debug(ktb_get_page))
                        pr_info(" *** mtp: %s %s %d | Index: %u, Object:  "
                                        " %llu %llu %llu rooted at rb_tree slot: %u of "
                                        "pool: %u of client: %u destroyed | "
                                        "ktb_get_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);
        }

        if(can_show(ktb_get_page))
                pr_info(" *** mtp | Successfully served page at index: %u, "
                                "object: %llu %llu %llu rooted at rb_tree slot: %u of "
                                "pool: %u of client: %u | ktb_get_page *** \n",
                                index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                oidp_hash, pool->pool_id, client->client_id);

        succ_tmem_gets++;
        return 0;

bad_copy:
        spin_unlock(&obj->obj_spinlock);
out:
        failed_tmem_gets++;
        return (unsigned long)rc;
}

int ktb_remotify_puts(void)
{
        uint64_t succ_count = 0;
        uint64_t count = 0;
        int evict_status = 0;
        unsigned long jleft = 0;
        unsigned long long rdtscstart;
        unsigned long long rdtscstop;
        struct tmem_page_content_descriptor *pcd = NULL;
        struct tmem_page_content_descriptor *nexpcd = NULL;

        allow_signal(SIGKILL|SIGSTOP);
        //DECLARE_WAIT_QUEUE_HEAD(remotify_wait);
        /* 
         * NOTE: a pcd that is in rscl is ensured to be not in pcd_remote_tree
         * i.e not being shared by any remote machine or for that matter not
         * even by any other local VM.
         */

        /*
         * for_each_pcd_in_rscl
         * {
         *      for_each_remote_server
         *      {
         *              check_bloom_filter
         *              {
         *                      if_hit
         *                      {
         *                              snd_page();
         *
         *                              if_remote_match
         *                              {
         *                                      update_ref_for_this_pcd;
         *                                      release_page;
         *                                      break;
         *                              }
         *                      }
         *
         *              }
         *
         *      }
         * }
         pr_info(" *** mtp | started eviction thread |"
         " ktb_remotify_puts ***\n");
         */
        /*
restartthread:

while(!kthread_should_stop())
{
*/
        /*
           pr_info(" *** mtp | eviction thread firing |"
           " ktb_remotify_puts ***\n");
           */

        set_current_state(TASK_INTERRUPTIBLE);

        jleft = schedule_timeout(delaykrf*HZ);

        rdtscll(rdtscstart);

        if(can_show(ktb_remotify_puts)) 
                pr_info(" *** mtp | Timeout Expired: %lu |"
                                " ktb_remotify_puts ***\n", jleft);

        //__set_current_state(TASK_RUNNING);

        /*
           if(signal_pending(current))
           goto exit_remotify;
           */

        /*
           if((dynamic_eviction == 1) && (devict_count != 0))
           {
           evict_status = 2;
           */
        /*
         * if dynamic eviction count > system_unique_pages we
         * would like to limit it to system_unique_pages. But is
         * system_unique_pages > REDUCE_SYS_PAGES_BY then limit
         * dynamic eviction count to REDUCE_SYS_PAGES_BY as we
         * want to avoid too many evictions from keeping the
         * eviction thread busy using up cpu.
         */
        /*
           if(devict_count >= system_unique_pages)
           {
        //devict_count = system_unique_pages;
        (system_unique_pages >= REDUCE_SYS_PAGES_BY)?\
        (devict_count = REDUCE_SYS_PAGES_BY):
        (devict_count = system_unique_pages);
        }
        }
        */
        /*
           else if(static_eviction && (system_unique_pages>=MAX_SYS_PAGES))
           {
           */
        /*
         * for all other settings like:
         * - dynamic eviction being enabled but devict_count=0
         *   and system_unique_pages going above MAX_SYS_PAGES 
         * - dynamic eviction not set and system_unique_pages
         *   going above MAX_SYS_PAGES static eviction kicks in.
         *   as static eviction is always set.
         */
        /*
           evict_status = 1;
           sevict_count = REDUCE_SYS_PAGES_BY;
           }
           else
           {
           goto restartthread;
           }
           */

        //read_lock(&(tmem_system.system_list_rwlock));
        write_lock(&(tmem_system.system_list_rwlock));
        if(can_debug(ktb_remotify_puts))
                pr_info("system_list_rwlock LOCKED ktb_remotify_puts\n");

        if(list_empty(&(tmem_system.remote_sharing_candidate_list)))
        {
                //read_unlock(&(tmem_system.system_list_rwlock));
                write_unlock(&(tmem_system.system_list_rwlock));
                if(can_debug(ktb_remotify_puts))
                        pr_info(" system_list_rwlock UNLOCKED"
                                        " ktb_remotify_puts \n");
                /*
                   goto restartthread;
                   */
                goto exit_remotify;
        }

        list_for_each_entry_safe(pcd, nexpcd,\
                        &(tmem_system.remote_sharing_candidate_list),\
                        system_rscl_pcds)
        {
                bool bloom_res;
                bool res = false;
                uint8_t firstbyte;
                struct remote_server *rs;
                struct page *page = alloc_page(GFP_ATOMIC);
                void *vaddr1, *vaddr2;
                uint64_t remote_id;

                count++;
                tmem_remotify_puts++;

                vaddr1 = page_address(page);
                memset(vaddr1, 0, PAGE_SIZE);

                if(can_debug(ktb_remotify_puts))
                        pr_info("new pcd address: %lx\n",
                                        (unsigned long)pcd);

                BUG_ON(pcd == NULL);
                BUG_ON(pcd->system_page == NULL);

                firstbyte = tmem_get_first_byte(pcd->system_page);

                /*
                   if(pcd->currently == DISASSOCIATING)
                   {
                   write_unlock(&(tmem_system.system_list_rwlock));
                   continue;
                   }
                   else
                   */
                /*
                 * to protect this pcd from deleted.
                 */
                pcd->currently = REMOTIFYING;

                //read_unlock(&(tmem_system.system_list_rwlock));
                write_unlock(&(tmem_system.system_list_rwlock));
                if(can_debug(ktb_remotify_puts))
                        pr_info("system_list_rwlock UNLOCKED"
                                        " ktb_remotify_puts \n");

                read_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
                if(can_debug(ktb_remotify_puts))
                        pr_info("pcd_tree_rwlocks[%u] LOCKED"
                                        " ktb_remotify_puts \n", firstbyte);

                vaddr2 = page_address(pcd->system_page);
                memcpy(vaddr1, vaddr2, PAGE_SIZE);

                if(can_debug(ktb_remotify_puts))
                        pr_info(" *** mtp | details of pcd to be"
                                        " remotified. firstbyte: %u, status:%d,"
                                        " remote_ip: %s, remote_id: %llu,"
                                        " sys_page: %s, currently: %d|"
                                        " ktb_remotify_puts ***\n",
                                        pcd->firstbyte, pcd->status,
                                        pcd->remote_ip, pcd->remote_id,
                                        (pcd->system_page == NULL)?
                                        "NULL":"NOT NULL",
                                        pcd->currently);

                if((pcd->pgp->obj->oid.oid[2] == 0) && 
                                (pcd->pgp->obj->oid.oid[1] == 0) &&
                                (pcd->pgp->obj->oid.oid[0] == 272842))
                {
                        test_remotify++;
                        if(can_debug(ktb_remotify_puts))
                                pr_info(" exp1A | remotifying page"
                                                " with index: %u of object:"
                                                " %llu %llu %llu rooted at rb_tree"
                                                " slot: %u of pool: %u of"
                                                " client: %u, having firstbyte: %u"
                                                " | *** \n", pcd->pgp->index,
                                                pcd->pgp->obj->oid.oid[2],
                                                pcd->pgp->obj->oid.oid[1],
                                                pcd->pgp->obj->oid.oid[0],
                                                tmem_oid_hash(&(pcd->pgp->obj->oid)),
                                                pcd->pgp->obj->pool->pool_id,
                                                pcd->pgp->obj->pool->associated_client->client_id,
                                                firstbyte);
                }
                else
                {
                        /*
                         * test for simultaneous full fledged operations
                         * at both ends.
                         */
                        read_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
                        if(can_debug(ktb_remotify_puts))
                                pr_info("pcd_tree_rwlocks[%u] UNLOCKED"
                                                " ktb_remotify_puts \n", firstbyte);
                        tmem_pcd_status_update(pcd, &nexpcd, firstbyte,
                                        0, "dummyip", 0,
                                        &res);
                        goto skiprsiter;
                }


                read_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
                if(can_debug(ktb_remotify_puts))
                        pr_info("pcd_tree_rwlocks[%u] UNLOCKED"
                                        " ktb_remotify_puts \n", firstbyte);

                //read_lock(&rs_rwspinlock);
                down_read(&rs_rwmutex);
                if((list_empty(&rs_head)))
                {
                        up_read(&rs_rwmutex);
                        /*
                           goto restartthread;
                           */
                        goto exit_remotify;
                }

                list_for_each_entry(rs, &(rs_head), rs_list)
                {
                        int bret = 0;
                        unsigned long long rdtscstart;
                        unsigned long long rdtscstop;

                        rdtscll(rdtscstart);
                        bret =
                        bloom_filter_check(rs->rs_bflt, &firstbyte, 1,\
                                        &bloom_res);
                        rdtscll(rdtscstop);
                        pr_info("rdtscll:bloom_filter_check: %llu\n",
                                        (rdtscstop - rdtscstart));

                        if(bret < 0)
                        {
                                if(can_show(ktb_remotify_puts))
                                        pr_info("*** mtp | checking for"
                                                        " rscl object in bloom"
                                                        " filter failed |"
                                                        " ktb_remotify_puts"
                                                        " *** \n");
                        }
                        else if(bloom_res == true)
                        {
                                int sret = 0;
                                unsigned long long rdtscstart;
                                unsigned long long rdtscstop;

                                if(can_show(ktb_remotify_puts))
                                        pr_info(" *** mtp | the rscl"
                                                        " object IS PRESENT in"
                                                        " BFLT of RS: %s |"
                                                        " ktb_remotify_puts"
                                                        " ***\n", rs->rs_ip);

                                rdtscll(rdtscstart);
                                sret = 
                                tcp_client_no_wait_snd_page(rs, page, &remote_id);
                                rdtscll(rdtscstop);
                                pr_info("rdtscll:tcp_client_no_wait_snd_page: %llu\n",
                                        (rdtscstop - rdtscstart));
                                /**/
                                if(sret < 0)
                                {
                                        if(can_show(ktb_remotify_puts))
                                                pr_info("*** mtp | page"
                                                                " was NOT FOUND"
                                                                " at RS:%s bflt"
                                                                " | ktb_remotif"
                                                                "y_puts ***\n", 
                                                                rs->rs_ip); 

                                }
                                else
                                {
                                        //succ_count++;
                                        if(can_show(ktb_remotify_puts))
                                                pr_info("*** mtp | page"
                                                                " was FOUND at"
                                                                " RS: %s, with"
                                                                " ID: %llu |"
                                                                " ktb_remotify_"
                                                                "puts *** \n",
                                                                rs->rs_ip,
                                                                remote_id);

                                        tmem_pcd_status_update
                                                (pcd,&nexpcd,firstbyte,remote_id,
                                                 rs->rs_ip, 1, &res);
                                        /* 
                                         * do not touch the ptr pcd until
                                         * the beginning of next
                                         * iteration, as
                                         * tmem_pcd_status_
                                         * update could have
                                         * disassociated this pcd.
                                         */
                                        if(can_debug(ktb_remotify_puts))
                                                pr_info("system_list_"
                                                                "rwlock LOCKED "
                                                                "ktb_remotify_"
                                                                "puts \n");
                                        break;
                                }
                        }
                        else
                        {
                                if(can_show(ktb_remotify_puts))
                                        pr_info(" *** mtp | the rscl"
                                                        " object is NOT PRESENT"
                                                        " in BFLT of RS: %s | "
                                                        "ktb_remotify_puts***\n"
                                                        ,rs->rs_ip);
                        }

                        tmem_pcd_status_update(pcd, &nexpcd, firstbyte,
                                        remote_id, rs->rs_ip, 0,
                                        &res);

                        if(can_debug(ktb_remotify_puts))
                                pr_info("system_list_rwlock LOCKED"
                                                " ktb_remotify_puts \n");
                        /* 
                         * do not touch the ptr pcd until
                         * the beginning of next
                         * iteration, as
                         * tmem_remotified_pcd_status_
                         * update could have
                         * disassociated this pcd.
                         */
                }
                up_read(&rs_rwmutex);
skiprsiter:
                __free_page(page);

                if((res == true) )
                {
                        succ_tmem_remotify_puts++;
                        succ_count++;

                        if((pcd->pgp->obj->oid.oid[2] == 0) && 
                                        (pcd->pgp->obj->oid.oid[1] == 0) &&
                                        (pcd->pgp->obj->oid.oid[0] == 272842))
                        {
                                test_remotify_succ++;
                                if(can_debug(ktb_remotify_puts))
                                        pr_info(" exp1B | successfully remotified page"
                                                        " with index: %u of object:"
                                                        " %llu %llu %llu rooted at rb_tree"
                                                        " slot: %u of pool: %u of"
                                                        " client: %u, having firstbyte: %u"
                                                        " | *** \n", pcd->pgp->index,
                                                        pcd->pgp->obj->oid.oid[2],
                                                        pcd->pgp->obj->oid.oid[1],
                                                        pcd->pgp->obj->oid.oid[0],
                                                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                                                        pcd->pgp->obj->pool->pool_id,
                                                        pcd->pgp->obj->pool->associated_client->client_id,
                                                        firstbyte);
                        }


                        /*
                           if(evict_status == 1) --sevict_count; else
                           if(evict_status == 2) --devict_count;
                           */
                } 
                else 
                { 
                        failed_tmem_remotify_puts++; 
                        if((pcd->pgp->obj->oid.oid[2] == 0) && 
                                        (pcd->pgp->obj->oid.oid[1] == 0) &&
                                        (pcd->pgp->obj->oid.oid[0] == 272842))
                        {
                                test_remotify_fail++;
                                if(can_debug(ktb_remotify_puts))
                                        pr_info(" exp1C | failed to remotify page"
                                                        " with index: %u of object:"
                                                        " %llu %llu %llu rooted at rb_tree"
                                                        " slot: %u of pool: %u of"
                                                        " client: %u, having firstbyte: %u"
                                                        " | *** \n", pcd->pgp->index,
                                                        pcd->pgp->obj->oid.oid[2],
                                                        pcd->pgp->obj->oid.oid[1],
                                                        pcd->pgp->obj->oid.oid[0],
                                                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                                                        pcd->pgp->obj->pool->pool_id,
                                                        pcd->pgp->obj->pool->associated_client->client_id,
                                                        firstbyte);
                        }
                }
                /*
NOTE: this is now being done from within the
tmem_remotified_pcd_status_update() function itself else
{
                 * hack_safe_nexpcd:3 to ensure that nexpcd
                 * points to a valid pcd I need to leave it
                 * locked and update the nexpcd as many pcd
                 * could have been removed from the list by
                 * pcd_disassociate()
                 write_lock(&(tmem_system.system_list_rwlock));
                 list_safe_reset_next(pcd, nexpcd,\
                 system_rscl_pcds);
                 if(can_debug(ktb_remotify_puts))
                 pr_info("system_list_rwlock LOCKED" "
                 ktb_remotify_puts \n"); }
                 */
if(can_show(ktb_remotify_puts)) { 
        pr_info(" *** mtp | #unique system pages: %llu,"
                        " dynamic_eviction enabled: %s,"
                        " dynamic_evict_count: %lld,"
                        " static_evict_count: %lld |"
                        " ktb_remotify_puts *** \n",
                        system_unique_pages,
                        dynamic_eviction?"yes":"no",
                        devict_count, sevict_count);

        pr_info(" *** mtp | #remote lookups: %llu|"
                        " ktb_remotify_puts *** \n", count); 

        pr_info(" *** mtp | remote lookups succeeded:"
                        " %llu| ktb_remotify_puts *** \n",
                        succ_count);
}

if(kthread_should_stop())
{
        /*
         * hack_safe_nexpcd:4
         * to ensure that nexpcd points to a valid pcd I
         * had left it locked
         */
        write_unlock(&(tmem_system.system_list_rwlock));
        if(can_debug(ktb_remotify_puts))
                pr_info("system_list_rwlock UNLOCKED"
                                " ktb_remotify_puts \n");
        ktb_eviction_thread_stopped = 1;
        return 0;
}

/*
   if(evict_status == 1)
   {
   if(sevict_count <= 0)
   {
   sevict_count = 0;
   evict_status = 0;
   */
/*
 * hack_safe_nexpcd:5 to ensure that
 * nexpcd points to a valid pcd I had
 * left it locked
 */
/*
   write_unlock(&\
   (tmem_system.system_list_rwlock));
   if(can_debug(ktb_remotify_puts))
   pr_info("system_list_rwlock"
   " UNLOCKED"
   " ktb_remotify_puts\n");
   goto restartthread;
   }
   }
   */
/*
   else if(evict_status == 2)
   {
   if(devict_count <= 0)
   {
   devict_count = 0;
   evict_status = 0;
   */
/*
 * hack_safe_nexpcd:6 to ensure that
 * nexpcd points to a valid pcd I had
 * left it locked
 */
/*
   write_unlock(&\
   (tmem_system.system_list_rwlock));
   pr_info("system_list_rwlock UNLOCKED"
   " ktb_remotify_puts \n");
   goto restartthread;
   }
   }
   */
//read_lock(&(tmem_system.system_list_rwlock));
//write_lock(&(tmem_system.system_list_rwlock));
//smp_mb();
}
//read_unlock(&(tmem_system.system_list_rwlock));
write_unlock(&(tmem_system.system_list_rwlock));
if(can_debug(ktb_remotify_puts))
        pr_info("system_list_rwlock UNLOCKED"
                        " ktb_remotify_puts \n");
        /*
           }
           */
        //__set_current_state(TASK_RUNNING);
exit_remotify:

ktb_eviction_thread_stopped = 1;

rdtscll(rdtscstop);
pr_info("rdtscll:ktb_remotify_puts: %llu\n",
                (rdtscstop - rdtscstart));
return 0;
}

static int ktb_dup_put_page(struct tmem_page_descriptor *pgp,\
                struct page* client_page)
{
        struct tmem_pool *pool;
        struct tmem_object_root *obj;
        struct tmem_client *client;
        struct tmem_page_descriptor *pgpfound = NULL;
        //unsigned long vaddr;
        int ret = -1;
        int fail;

        ASSERT(pgp != NULL);
        ASSERT(pgp->tmem_page != NULL);
        ASSERT(pgp->size != -1);

        obj = pgp->obj;

        ASSERT(obj != NULL);
        ASSERT_SPINLOCK(&obj->obj_spinlock);

        pool = obj->pool;

        ASSERT(pool != NULL);

        client = pool->associated_client;

        //copy_uncompressed:
        if(can_show(ktb_dup_put_page))
                pr_info(" *** mtp | Page with index: %u, object: %llu %llu %llu"
                                " already exists in pool: %u of client: %u | "
                                "ktb_dup_put_page *** \n",
                                pgp->index, obj->oid.oid[2], obj->oid.oid[1],
                                obj->oid.oid[0], pool->pool_id, client->client_id);

        if(pgp->tmem_page)
                tmem_pgp_free_data(pgp);
        //tmem_pgp_free_data(pgp, pool);

        //vaddr = (get_zeroed_page(GFP_ATOMIC));
        //pgp->tmem_page = virt_to_page(vaddr);
        pgp->tmem_page = alloc_page(GFP_ATOMIC);

        if(pgp->tmem_page == NULL)
        {
                if(can_debug(ktb_dup_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not add page "
                                        "descriptor for " "index: %u, object: %llu %llu"
                                        "%llu of pool: %u of " "client: %u into the "
                                        "object | ktb_dup_put_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        pgp->index, obj->oid.oid[2], obj->oid.oid[1],
                                        obj->oid.oid[0], pool->pool_id,
                                        client->client_id);
                fail = 0;
                goto failed_dup;
        }

        pgp->size = 0;

        ret = tmem_copy_from_client(pgp->tmem_page, client_page);

        if(ret < 0)
        {
                if(can_debug(ktb_dup_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not copy contents"
                                        " of page with index: %u, object: %llu %llu "
                                        "%llu of pool: %u of client: %u | "
                                        "ktb_dup_put_page *** \n",
                                        __FILE__, __func__, __LINE__, pgp->index,
                                        obj->oid.oid[2], obj->oid.oid[1],
                                        obj->oid.oid[0], pool->pool_id,
                                        client->client_id);
                fail = 0;
                goto bad_copy;
        }

        if(kvm_tmem_dedup_enabled)
        {
                int temp;
                unsigned long long rdtscstart;
                unsigned long long rdtscstop;

                rdtscll(rdtscstart);
                temp = pcd_associate(pgp, 0);
                rdtscll(rdtscstop);
                pr_info("rdtscll:pcd_associate: %llu\n",
                        (rdtscstop - rdtscstart));

                if(temp == -ENOMEM)
                {
                        if(can_debug(ktb_dup_put_page))
                                pr_info(" *** mtp: %s, %s, %d | could not "
                                                "associate page descriptor of index: "
                                                "%u, object: %llu %llu %llu of pool: "
                                                "%u of client: %u with any existing "
                                                "descriptor | ktb_dup_put_page *** \n",
                                                __FILE__, __func__, __LINE__,
                                                pgp->index,
                                                obj->oid.oid[2],obj->oid.oid[1],
                                                obj->oid.oid[0], pool->pool_id,
                                                client->client_id); fail = 0;

                        goto failed_dup;
                }
        }

        //done:
        /* successfully replaced data, clean up and return success */
        spin_unlock(&obj->obj_spinlock);
        if(can_show(ktb_dup_put_page))
                pr_info(" *** mtp | successfully inserted page with index: %u, "
                                "of object: %llu %llu %llu in pool: %u of client: %u | "
                                "ktb_dup_put_page *** \n",
                                pgp->index, obj->oid.oid[2], obj->oid.oid[1],
                                obj->oid.oid[0], pool->pool_id, client->client_id);

        succ_tmem_puts++;
        return 0;

bad_copy:

        //ASSERT(fail);
        goto cleanup;

failed_dup:
        /* couldn't change out the data, flush the old data and return
         * -ENOSPC instead of -ENOMEM to differentiate failed _dup_ put */
        //ASSERT(fail);
        ret = -ENOSPC;

cleanup:

        pgpfound = tmem_pgp_delete_from_obj(obj, pgp->index);
        ASSERT(pgpfound == pgp);

        tmem_pgp_delist_free(pgpfound);

        ASSERT(obj->pgp_count);
        if(obj->pgp_count == 0)
        {
                write_lock(&pool->pool_rwlock);
                tmem_obj_free(obj);
                write_unlock(&pool->pool_rwlock);
        }
        else
        {
                spin_unlock(&obj->obj_spinlock);
        }

        failed_tmem_puts++;
        return ret;
}

static unsigned long int ktb_put_page(int client_id, int32_t pool_id, \
                struct tmem_oid *oidp, uint32_t index, struct page *client_page)
{
        struct tmem_pool* pool;
        struct tmem_object_root* obj = NULL;
        struct tmem_client* client;
        int ret = -1;
        int test = 1;
        struct tmem_page_descriptor* pgp = NULL;
        int newobj = 0;
        //unsigned long vaddr;
        unsigned int oidp_hash = tmem_oid_hash(oidp);
        //unsigned long paddr;

        tmem_puts++;
        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | No such client possible"
                                        " : %d | ktb_put_page *** \n ",
                                        __FILE__, __func__, __LINE__, client->client_id);
                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_put_page *** \n ",
                                        __FILE__, __func__, __LINE__, client->client_id);

                goto out;
        }

        pool = client->this_client_all_pools[pool_id];

        //pool = ktb_get_pool_by_id(client_id, pool_id);

        if(unlikely(pool == NULL))
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | Client: %d doesn't have"
                                        " a valid POOL | ktb_put_page *** \n ",
                                        __FILE__, __func__, __LINE__, client->client_id);

                goto out;
        }


        if(can_show(ktb_put_page))
                pr_info(" *** mtp | Searching for object: %llu %llu %llu at "
                                "rb_tree slot: %u of pool: %u of client: %u | "
                                "ktb_put_page *** \n",
                                oidp->oid[2], oidp->oid[1], oidp->oid[0], oidp_hash,
                                pool->pool_id, client->client_id);

refind:

        //Get a locked reference to the object that we are looking for if it is
        //there
        obj = tmem_obj_find(pool, oidp);
        //I have a spinlocked object at this point, if obj != NULL

        //Handle case for obj already existing
        if(obj != NULL)
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s %s %d | Object: %llu %llu %llu "
                                        "already exists at rb_tree slot: %u of pool: %u"
                                        " of client: %u | ktb_put_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                pgp = tmem_pgp_lookup_in_obj(obj, index);

                //check if this index(page) of this obj(file) already exists
                //if it doesn't it is a new index(page) for an existing obj(file)
                if(pgp != NULL)
                {
                        return ktb_dup_put_page(pgp, client_page);
                }
                else
                {
                        if(can_show(ktb_put_page))
                                pr_info(" *** mtp | Object: %llu %llu %llu "
                                                "already exists at rb_tree slot: %u of "
                                                "pool: %u of client: %u | but index: %u"
                                                " is new | ktb_put_page *** \n",
                                                oidp->oid[2], oidp->oid[1],
                                                oidp->oid[0], oidp_hash, pool->pool_id,
                                                client->client_id, index);

                        //no puts allowed into a frozen pool (except dup puts)
                        //no idea what a frozen pool is
                        //if ( client->frozen )
                        //goto unlock_obj;
                }
        }
        else
        {
                if(can_show(ktb_put_page))
                        pr_info(" *** mtp | Object: %llu %llu %llu does not "
                                        "exist at rb_tree slot: %u of pool: %u of "
                                        "client: %u | ktb_put_page *** \n",
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                obj = tmem_obj_alloc(pool, oidp);
                //if(obj = tmem_obj_alloc(pool, oidp) == NULL)
                if(obj == NULL)
                {
                        //following line added later on, refcount incremented
                        //in ktb_get_pool_by_id.
                        //atomic_dec(&client->refcount);
                        if(can_debug(ktb_put_page))
                                pr_info(" *** mtp: %s, %s, %d | failed to "
                                                "allocate new object: %llu %llu %llu | "
                                                "ktb_put_page *** \n", __FILE__,
                                                __func__, __LINE__, oidp->oid[2],
                                                oidp->oid[1], oidp->oid[0]);

                        goto out;
                        //return -1;
                }

                //pr_info(" *** mtp | allocated new object: %llu %llu %llu | "
                //"ktb_put_page *** \n", oidp->oid[2], oidp->oid[1],oidp->oid[0]);

                write_lock(&pool->pool_rwlock);

                if(!tmem_obj_rb_insert(&pool->obj_rb_root[oidp_hash], obj))
                {

                        //Parallel callers may already allocated obj and inserted
                        //to obj_ktb_rb_root before us.
                        //tmem_free(obj, pool);
                        // kfree(obj);
                        if(can_show(ktb_put_page))
                                pr_info(" *** mtp | Object: %llu %llu %llu "
                                                "inserted by parallel caller at rb_tree"
                                                " slot: %u of pool: %u of client: %u "
                                                "| ktb_put_page *** \n",
                                                oidp->oid[2], oidp->oid[1],
                                                oidp->oid[0], oidp_hash,
                                                pool->pool_id, client->client_id);

                        kmem_cache_free(tmem_objects_cachep, obj);
                        write_unlock(&pool->pool_rwlock);
                        goto refind;
                }

                //successfully created and inserted a new object into one of the
                //rb tree bucket slot of this pool.
                //Locking this object.
                spin_lock(&obj->obj_spinlock);
                newobj = 1;
                write_unlock(&pool->pool_rwlock);

                if(can_show(ktb_put_page))
                        pr_info(" *** mtp | successfully inserted new object: "
                                        "%llu %llu %llu into rb_tree  root at slot: %u "
                                        "of pool: %u of client: %u | ktb_put_page ***\n",
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);
        }

        ASSERT_SPINLOCK(&obj->obj_spinlock);
        //I am here: temporarily unlocking the obj!!
        //Ideally I should unlock only after pgp and pcd operations.
        //Moving this unlock to original position; within label unlock_obj
        //spin_unlock(&obj->obj_spinlock);

        pgp = tmem_pgp_alloc(obj);

        if(pgp == NULL)
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not allocate "
                                        "tmem pgp for index: %u, object: %llu %llu %llu"
                                        " rooted rb_tree slot: %u of pool: %u of "
                                        "client: %u | ktb_put_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                goto unlock_obj;
        }

        ret = tmem_pgp_add_to_obj(obj, index, pgp);

        //warning, may result in partially built radix tree ("stump")
        if (ret == -ENOMEM || ret != 0)
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not add tmem pgp "
                                        "for index: %u, object: %llu %llu %llu rooted "
                                        "at rb_tree slot: %u of pool: %u of client: %u "
                                        "into the object | ktb_put_page *** \n",
                                        __FILE__, __func__, __LINE__, index,
                                        oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                test = 0;
                goto free_pgp;
        }

        pgp->index = index;
        pgp->size = 0;

        //copy_uncompressed:

        // pgp->pfp = alloc_page(GFP_KERNEL);
        //pgp->tmem_page = virt_to_page(get_zeroed_page(__GFP_HIGHMEM));

        //vaddr = (get_zeroed_page(GFP_ATOMIC));
        //pgp->tmem_page = virt_to_page(vaddr);
        pgp->tmem_page = alloc_page(GFP_ATOMIC);
        //check if the page being returned is already mapped or not
        //I think I still have to kmap or kmap_atomic to make sure that
        //a permenant or temporary mapping is available with the kernel.

        //paddr = __pa(vaddr);
        //pr_info(" *** mtp | vaddr: %lx | *** \n", vaddr);
        //pr_info(" *** mtp | paddr: %lx | *** \n", paddr);
        //pr_info(" *** mtp | ptovaddr: %lx | *** \n",
        //	  (unsigned long)__va(paddr));

        //pr_info(" *** mtp | comparision result: %d | *** \n",
        //(vaddr == (unsigned long)__va(paddr)));
        //ASSERT(vaddr == (unsigned long)__va(paddr));
        //ASSERT(PageHighMem(pgp->tmem_page));

        ASSERT(pgp->tmem_page);
        if (pgp->tmem_page == NULL)
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not add page "
                                        "descriptor for index: %u, object: %llu %llu "
                                        "%llu rooted at rb_tree slot: %u of pool: %u "
                                        "of client: %u into the object | "
                                        "ktb_put_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                ret = -ENOMEM;
                test = 0;
                goto del_pgp_from_obj;
        }

        // copy client page to host page
        ret = tmem_copy_from_client(pgp->tmem_page, client_page);

        if ( ret < 0 )
        {
                if(can_debug(ktb_put_page))
                        pr_info(" *** mtp: %s, %s, %d | could not copy contents"
                                        " of page with index: %u, object: %llu %llu "
                                        "%llu rooted at rb_tree slot: %u of pool: %u "
                                        "of client: %u | ktb_put_page *** \n",
                                        __FILE__, __func__, __LINE__,
                                        index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                        oidp_hash, pool->pool_id, client->client_id);

                test = 0;
                goto bad_copy;
        }

        if (kvm_tmem_dedup_enabled)
        {
                int dedup_ret = 0;
                unsigned long long rdtscstart;
                unsigned long long rdtscstop;

                rdtscll(rdtscstart);
                dedup_ret = pcd_associate(pgp, 0);
                rdtscll(rdtscstop);
                pr_info("rdtscll:pcd_associate: %llu\n",
                        (rdtscstop - rdtscstart));

                //if(pcd_associate(pgp, 0) == -ENOMEM)
                //pr_info("*** mtp | dedup_ret: %d | ktb_put_page ***\n",
                //        dedup_ret);

                /* Many pgps can point to the same system page (pcd), */
                /* pgps cannot be used to for remote dedup. Since using pgps can */
                /* result in setting the bits in bloom filter multiple times, an */
                /* overhead. */   

                if(dedup_ret == -ENOMEM)
                {
                        if(can_debug(ktb_put_page))
                                pr_info(" *** mtp: %s, %s, %d | could'nt "
                                                "associate page descriptor of index: "
                                                "%u, object: %llu %llu %llu rooted at "
                                                "rb_tree slot: %u of pool: %u of "
                                                "client: %u with any existing "
                                                "descriptor | ktb_put_page *** \n",
                                                __FILE__, __func__, __LINE__, index,
                                                oidp->oid[2], oidp->oid[1],
                                                oidp->oid[0], oidp_hash,
                                                pool->pool_id, client->client_id);

                        test = 0;
                        ret = -ENOMEM;
                        goto del_pgp_from_obj;
                }

                /*
                   else if(dedup_ret == 1)
                   {
                //no match found,
                //insert into client remote_sharing_candidate list
                //spin_lock(&(tmem_system.system_list_lock));
                write_lock(&(tmem_system.system_list_rwlock));

                list_add_tail(&(pgp->pcd->system_rscl_pcds),\
                &(tmem_system.remote_sharing_candidate_list));

                write_unlock(&(tmem_system.system_list_rwlock));
                //spin_unlock(&(tmem_system.system_list_lock));
                update_bflt(pgp);
                }
                */

                /*
                 * This is not needed as only the matched pcd is to be moved
                 * from the rscl to lol, which is done in pcd_associate().
                 else if(dedup_ret == 0)
                 {
                //if dedup successful insert into_local_only list.
                spin_lock(&(tmem_system.system_list_lock));
                list_add_tail(&(pgp->pcd->system_lol_pcds),\
                &(tmem_system.local_only_list));
                spin_unlock(&(tmem_system.system_list_lock));
                }
                */
        }
        else
        {
                /* 
                 * If no local dedup available
                 * insert into remote_sharing_candidate list.
                 * NOTE: remote dedup won't happen without local dedup.
                 */
                //spin_lock(&(tmem_system.system_list_lock));
                write_lock(&(tmem_system.system_list_rwlock));

                list_add_tail(&(pgp->pcd->system_rscl_pcds),\
                                &(tmem_system.remote_sharing_candidate_list));

                write_unlock(&(tmem_system.system_list_rwlock));
                //spin_unlock(&(tmem_system.system_list_lock));
                //update_bflt(pgp->pcd);
        }
        /*
           code to insert this object into various lists like the
           local_only_list, remote_sharing_candidate_list,
           remote_shared_list etc goes above this point.

           We can also add the pcd instead of the pgp. As the pgps are the unique
           entities than pgps. Then it becomes a host wide summary instead of per VM.
           */
        /*
           pr_info(" *** mtp | calling make_summary() | ktb_get_page *** \n");
           make_summary(client_id);
           */

        spin_unlock(&obj->obj_spinlock);
        if(can_show(ktb_put_page))
                pr_info(" *** mtp | successfully inserted page with index: %u, "
                                "of object: %llu %llu %llu at rb_tree slot: %u of pool:"
                                "  %u of client: %u | ktb_put_page *** \n",
                                index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
                                oidp_hash, pool->pool_id, client->client_id);

        succ_tmem_puts++;
        return 0;

bad_copy:
        //the below assert just checks if we got into bad_copy
        //ASSERT(test);
del_pgp_from_obj:
        //the 1st assert below just checks if we got into del_pgp_from_obj
        //after pcd_associate
        //ASSERT(test);
        //this checks if we got here after copy_from_client failed
        //ASSERT(pgp->tmem_page);
        ASSERT((obj != NULL) && (pgp != NULL) && (pgp->index != -1));
        tmem_pgp_delete_from_obj(obj, pgp->index);
free_pgp:
        //the below assert just checks if we got into free_pgp
        //ASSERT(test);
        tmem_pgp_free(pgp);
unlock_obj:
        if (newobj)
        {
                //int* hola = NULL;
                //ASSERT(hola);
                spin_unlock(&obj->obj_spinlock);
                write_lock(&pool->pool_rwlock);
                tmem_obj_free(obj);
                write_unlock(&pool->pool_rwlock);
        }
        else
        {
                //int* amigo = NULL;
                //ASSERT(amigo);
                spin_unlock(&obj->obj_spinlock);
        }
        //pool->no_mem_puts++;
out:
        failed_tmem_puts++;
        return (unsigned long int)ret;
}

static unsigned long int ktb_destroy_pool(int client_id, uint32_t pool_id)
{
        struct tmem_client* client = NULL;
        struct tmem_pool* pool;
        int ret = 0;

        if (pool_id >= MAX_POOLS_PER_CLIENT)
                goto out;

        client = ktb_get_client_by_id(client_id);

        if(unlikely(client == NULL))
        {
                if(can_debug(ktb_destroy_pool))
                        pr_info(" *** mtp: %s, %s, %d | No such client "
                                        "possible: %d | ktb_destroy_pool *** \n ",
                                        __FILE__, __func__, __LINE__,
                                        client->client_id);

                goto out;
        }

        if(unlikely(client->allocated == 0))
        {
                if(can_debug(ktb_destroy_pool))
                        pr_info(" *** mtp: %s, %s, %d | First time client: %d "
                                        "doing something other than NEW_POOL| "
                                        "ktb_destroy_pool *** \n ",
                                        __FILE__, __func__, __LINE__,
                                        client->client_id);

                goto out;
        }

        pool = client->this_client_all_pools[pool_id];

        //pool = ktb_get_pool_by_id(client_id, pool_id);

        if(unlikely(pool == NULL))
        {
                if(can_debug(ktb_destroy_pool))
                        pr_info(" *** mtp: %s, %s, %d | Client: %d doesn't have"
                                        " a valid POOL | ktb_destroy_pool *** \n ",
                                        __FILE__, __func__, __LINE__,
                                        client->client_id);

                goto out;
        }

        client->this_client_all_pools[pool_id] = NULL;

        tmem_flush_pool(pool, client_id);

        if(can_show(ktb_destroy_pool))
                pr_info(" *** mtp | Successfully destroyed pool: %d of client: "
                                "%d | ktb_destory_pool *** \n", pool_id, client_id);
        ret = 1;

out:
        return (unsigned long)ret;
}

static unsigned long int ktb_new_pool(int client_id, uint64_t uuid_lo,\
                uint64_t uuid_hi, uint32_t flags)
{
        int poolid  = -1;
        struct tmem_client *client = NULL;
        struct tmem_pool *pool; //*shpool;

        /*********************************/
        //int persistent = flags & TMEM_POOL_PERSIST;
        //int shared = flags & TMEM_POOL_SHARED;
        //int pagebits = (flags >> TMEM_POOL_PAGESIZE_SHIFT) &
        //TMEM_POOL_PAGESIZE_MASK;
        //int specversion = (flags >> TMEM_POOL_VERSION_SHIFT) &
        //TMEM_POOL_VERSION_MASK;

        //struct tmem_pool *pool, *shpool;
        //int i, first_unused_s_poolid;


        /*
           if ( this_cli_id == TMEM_CLI_ID_NULL )
           cli_id = current->domain->domain_id;
           else
           cli_id = this_cli_id;
           tmem_client_info("tmem: allocating %s-%s tmem pool for %s=%d...",
           persistent ? "persistent" : "ephemeral",
           shared ? "shared" : "private",
           tmem_cli_id_str, cli_id);
           */
        /**************************************/
        /*
           if ( specversion != TMEM_SPEC_VERSION )
           {
           pr_info("***failed... unsupported spec version***\n");
           goto out;
           }
           if ( shared && persistent )
           {
           pr_info("***unable to create a shared-persistant pool***\n");
           goto out;
           }
           if ( pagebits != (PAGE_SHIFT - 12) )
           {
           pr_info("failed... unsupported pagesize %d\n",1<<(pagebits+12));
           goto out;
           }
           */
        /******************************************/
        /*
           if ( flags & TMEM_POOL_PRECOMPRESSED )
           {
           tmem_client_err("failed precompression flag set but "
           "unsupported\n");
           return -EPERM;
           }
           if ( flags & TMEM_POOL_RESERVED_BITS )
           {
           tmem_client_err("failed... reserved bits must be zero\n");
           return -EPERM;
           }
           */
        /*********************************/

        //printk("MTP: ***ktb_new_pool***\n");

        /*Identify the client*/
        /*
           if(client_id == LOCAL_CLIENT)
           {
           pr_info("NEW LOCAL_CLIENT POOL\n");
           client = &ktb_host;
           }
           else
           */
        //pr_info(" *** MODULE | CURRENT ******** pid: %d, name: %s ******** INSERTED | "
        //"MODULE *** \n", current->pid, current->comm);

        client = ktb_get_client_by_id(client_id);

        /*If no such client found*/
        if(client == NULL)
        {
                if(debug(ktb_new_pool))
                        pr_info(" *** mtp: %s, %s, %d | Invalid Client| "
                                        "ktb_new_pool *** \n",
                                        __FILE__, __func__, __LINE__);
                goto out;
        }
        /*else*/
        //atomic_inc(&client->refcount);

        /*Allocate memory for new pool*/
        pool = kmalloc(sizeof(struct tmem_pool), GFP_ATOMIC);

        /*Exit if no memory allocated for new pool descriptor*/
        if(pool == NULL)
        {
                if(debug(ktb_new_pool))
                        pr_info(" *** mtp: %s, %s, %d | Pool creation failed : "
                                        "out of memory | ktb_new_pool *** \n",
                                        __FILE__, __func__, __LINE__);

                goto out;
        }
        /*Find first free pool index for this client*/
        for(poolid = 0; poolid < MAX_POOLS_PER_CLIENT; poolid++)
        {
                if(client->this_client_all_pools[poolid] == NULL)
                        break;
        }

        /*Check if no free pool index available for this client*/
        if(poolid >= MAX_POOLS_PER_CLIENT)
        {
                /*What is namestr?? */
                //pr_info("%s\n", namestr);
                if(debug(ktb_new_pool))
                        pr_info(" *** mtp: %s, %s, %d | Pool creation failed: "
                                        "Max pools allowed for client: %d exceeded | "
                                        "ktb_new_pool *** \n",
                                        __FILE__, __func__, __LINE__,
                                        client->client_id);

                kfree(pool);
                poolid = -1;
                goto out;
        }

        /*Else, update pool details*/
        //atomic_set(&pool->refcount, 0);
        pool->associated_client = client;
        pool->pool_id = poolid;
        pool->uuid[0] = uuid_lo;
        pool->uuid[1] = uuid_hi;
        pool->obj_count = 0;
        pool->obj_count_max = 0;

        tmem_new_pool(pool, flags);

        /*Update pool info in client details*/
        client->this_client_all_pools[poolid] = pool;

        /*What is namestr?? */
        //pr_info("%s\n", namestr);
        pr_info(" *** mtp | Created new %s tmem pool, id=%d, client=%d | "
                        "ktb_new_pool *** \n",
                        flags & TMEM_POOL_PERSIST ? "persistent":"ephemeral",
                        poolid, client_id);

        /*Debug: Show client and pool info*/
#if mtp_debug
        show_client_pool_info(client, pool);
#endif
out:
        //if(client != NULL)
        //	atomic_dec(&client->refcount);
        return (unsigned long int)poolid;
}
/******************************************************************************/
/*							     END KTB FUNCTIONS*/
/******************************************************************************/

/******************************************************************************/
/* 						    DEFINING kvm_host_tmem_ops*/
/******************************************************************************/
static struct kvm_host_tmem_ops ktb_ops = {
        .kvm_host_new_pool = ktb_new_pool,
        .kvm_host_put_page = ktb_put_page,
        .kvm_host_get_page = ktb_get_page,
        .kvm_host_flush_page = ktb_flush_page,
        .kvm_host_flush_object = ktb_flush_object,
        .kvm_host_destroy_pool = ktb_destroy_pool,
        /* 
         * Implement these, these are being called from 
         * destroy_client: 
         * arch/x86/kvm/x86.c, via kvm_tmem_backend (kvm_tmem.c).
         * create_client:
         * from kvm_tmem_backend (kvm_tmem.c)
         */
        .kvm_host_create_client = ktb_create_client,
        .kvm_host_destroy_client = ktb_destroy_client,
};
/******************************************************************************/
/* 				              END kvm_host_tmem_ops DEFINITION*/
/******************************************************************************/

/******************************************************************************/
/*				                               KTB MODULE INIT*/
/******************************************************************************/
static int __init ktb_main_init(void)
{
        int i;
        int ret;
        char *s = "kvm_tmem_bknd";
        /*
           uint8_t byte;
           bool bloom_res;
           */
        pr_info(" *** mtp | INSERTED ********kvm_tmem_bknd******** INSERTED |"
                        " ktb_main_init *** \n");
        /*
           BUG_ON(sizeof(struct cleancache_filekey) != sizeof(struct tmem_oid));
           pr_info(" *** MODULE | CURRENT ******** pid: %d, name: %s ********"
           " INSERTED | MODULE *** \n", current->pid, current->comm);
           */
        pr_info(" *** mtp | kvm_tmem_bknd_enabled: %d, use_cleancache: %d |"
                        " ktb_main_init *** \n", kvm_tmem_bknd_enabled, use_cleancache);

        if (kvm_tmem_bknd_enabled && use_cleancache)
        {
                pr_info(" *** mtp | Boot Parameter Working |"
                                " ktb_main_init *** \n");

                /*
                   if(evict == 0)
                   static_eviction = 1;
                   else if(evict == 1)
                   dynamic_eviction = 1;
                   */

                kvm_tmem_bknd_devict = 
                        kobject_create_and_add("kvm_tmem_bknd_devict", kernel_kobj);

                if(!kvm_tmem_bknd_devict)
                        goto sysfsfail;

                ret = 
                        sysfs_create_group(kvm_tmem_bknd_devict, &devict_attr_group);

                if(ret)
                {
                        kobject_put(kvm_tmem_bknd_devict);
                        goto sysfsfail;
                }

                goto sysfssucc;

sysfsfail:

                dynamic_eviction = 0;
                static_eviction = 1;

sysfssucc:
                /*
                   initialize bloom filter,
                   mention size of bit_map,
                   add the hash functions to be used by the bloom etc
                   size of bit_map = 2^28 or 32 MB
                tmem_system_bloom_filter = bloom_filter_new(bflt_bit_size);

                if(IS_ERR(tmem_system_bloom_filter))
                {
                        pr_info(" *** mtp | failed to allocate bloom_filter "
                                        "| ktb_main_init *** \n");

                        tmem_system_bloom_filter = NULL;
                        //set error flag
                        //goto init_bflt_fail;
                }
                else
                        pr_info(" *** mtp | successfully allocated bloom_filter"
                                        " | ktb_main_init *** \n");

                if(bloom_filter_add_hash_alg(tmem_system_bloom_filter,"crc32c"))
                {
                        pr_info(" *** mtp | Adding crc32c algo to bloom filter"
                                        "failed | ktb_main_init *** \n");

                        vfree(tmem_system_bloom_filter);
                        tmem_system_bloom_filter = NULL;
                        //goto init_bflt_alg_fail;
                }

                if(bloom_filter_add_hash_alg(tmem_system_bloom_filter,"sha1"))
                {
                        pr_info(" *** mtp | Adding sha1 algo to bloom filter"
                                        "failed | ktb_main_init *** \n");

                        vfree(tmem_system_bloom_filter);
                        tmem_system_bloom_filter = NULL;
                        //goto init_bflt_alg_fail;
                }

                if(tmem_system_bloom_filter != NULL)
                        bloom_filter_reset(tmem_system_bloom_filter);
                */

                tmem_page_descriptors_cachep =
                        kmem_cache_create("ktb_page_descriptors",\
                                        sizeof(struct tmem_page_descriptor), 0, 0, NULL);

                tmem_objects_cachep =
                        kmem_cache_create("ktb_tmem_objects",\
                                        sizeof(struct tmem_object_root), 0, 0, NULL);

                tmem_page_content_desc_cachep =
                        kmem_cache_create("ktb_page_content_descriptors",\
                                        sizeof(struct tmem_page_content_descriptor), 0, 0, NULL);

                if(kvm_tmem_dedup_enabled)
                {
                        for(i = 0; i < 256; i++)
                        {
                                tmem_system.pcd_tree_roots[i] = RB_ROOT;
                                INIT_RADIX_TREE(\
                                                &(tmem_system.pcd_remote_tree_roots[i]),\
                                                GFP_KERNEL);
                                //tmem_system.pcd_remotified_tree_roots[i] = 
                                //RADIX_TREE_INIT(GFP_KERNEL);
                                rwlock_init(&(tmem_system.pcd_tree_rwlocks[i]));
                                rwlock_init(\
                                                &(tmem_system.pcd_remote_tree_rwlocks[i]));
                                //rwlock_init(
                                //&(tmem_system.pcd_remotified_tree_rwlocks[i]));
                        }

                        INIT_LIST_HEAD(\
                                        &(tmem_system.remote_sharing_candidate_list));
                        INIT_LIST_HEAD(&(tmem_system.local_only_list));
                        INIT_LIST_HEAD(&(tmem_system.remote_shared_list));

                        rwlock_init(&(tmem_system.system_list_rwlock));
                        //INIT_LIST_HEAD(&(tmem_system.pcd_preorder_stack));
                        //spin_lock_init(&(tmem_system.system_list_lock));
                }
                /*
                 * test code to check the working of remote deduplication
                 * without starting any VMs.
                 test_pcd = 
                 kmem_cache_alloc(tmem_page_content_desc_cachep, GFP_ATOMIC);

                 test_page = alloc_page(GFP_ATOMIC);

                 if(test_page != NULL)
                 {
                 pr_info(" *** mtp | test_page allocated successfully | "
                 "network_server_init *** \n");
                 test_page_vaddr = page_address(test_page);
                 memset(test_page_vaddr, 0, PAGE_SIZE);
                 strcat(test_page_vaddr, 
                 "HOLA AMIGO, MI LLAMA ABY, Y TU?");
                 }

                 RB_CLEAR_NODE(&test_pcd->pcd_rb_tree_node);
                 INIT_LIST_HEAD(&test_pcd->system_rscl_pcds);
                 INIT_LIST_HEAD(&test_pcd->system_lol_pcds);

                 test_pcd->pgp = NULL;
                 test_pcd->system_page = test_page;
                 test_pcd->size = PAGE_SIZE;
                 test_pcd->pgp_ref_count = 0;

                 write_lock(&(tmem_system.system_list_rwlock));

                 list_add_tail(&(test_pcd->system_rscl_pcds),\
                 &(tmem_system.remote_sharing_candidate_list));

                 write_unlock(&(tmem_system.system_list_rwlock));

                 byte = tmem_get_first_byte(test_pcd->system_page);

                 if(bloom_filter_add(tmem_system_bloom_filter, &byte, 1))
                 pr_info(" *** mtp | adding test page to bloom filter"
                 " failed | ktb_main_init *** \n");

                 if(bloom_filter_check(tmem_system_bloom_filter,&byte,1,&bloom_res))
                 pr_info(" *** mtp | checking for test page to bloom"
                 "filter failed | ktb_main_init *** \n");

                 if(bloom_res == false)
                 pr_info(" *** mtp | the test page was not set in bloom"
                 " filter | ktb_main_init *** \n");
                 */
                /* register the tmem backend ops */
                kvm_host_tmem_register_ops(&ktb_ops);

                pr_info(" *** mtp | Cleancache enabled using: %s | "
                                "ktb_main_init *** \n", s);
                /*
                   tmem_object_nodes_cachep =
                   kmem_cache_create("ktb_object_nodes",
                   sizeof(struct tmem_object_node), 0, 0, NULL);

                   ktb_new_client(TMEM_CLIENT);
                   */
                /*
                //start the tcp server
                if(tmem_system_bloom_filter != NULL)
                {
                        if(network_server_init() != 0)
                        {
                                pr_info(" *** mtp | failed to start the tcp"
                                                " server | ktb_main_init *** \n");
                                //set error flag
                                //goto netfail;
                        }
                           //register the tcp server with the designated leader,
                           //who is hard coded for now.
                        else if(tcp_client_init() != 0)
                        {
                                int ret;
                                pr_info(" *** mtp | failed to register with the"
                                                " leader server | ktb_main_init ***\n");
                                if(tcp_acceptor_started && !tcp_acceptor_stopped)
                                {
                                        ret = 
                                                kthread_stop(tcp_server->accept_thread);

                                        if(!ret)
                                                pr_info(" *** mtp | stopping"
                                                                " tcp server accept "
                                                                "thread as local client"
                                                                " could not setup a"
                                                                " connection with"
                                                                " leader server |"
                                                                " ktb_main_init"
                                                                " *** \n");
                                }
                                if(tcp_listener_started && !tcp_listener_stopped)
                                { 
                                        ret = kthread_stop(tcp_server->thread);
                                        if(!ret)
                                                pr_info(" *** mtp | stopping"
                                                                " tcp server listening"
                                                                " thread as local"
                                                                " client could not"
                                                                " setup a connection"
                                                                " with leader server"
                                                                " | ktb_main_init"
                                                                " *** \n");

                                        if(tcp_server->listen_socket != NULL)
                                        {
                                                sock_release(tcp_server->listen_socket);
                                                tcp_server->listen_socket=NULL;
                                        }
                                }

                                kfree(tcp_conn_handler);
                                kfree(tcp_server);
                                //vfree(tmem_system_bloom_filter);
                                //vfree(bflt);
                                //goto netfail;
                        }
                        //else if(start_fwd_filter(tmem_system_bloom_filter)<0)
                        else
                        {
                                   //pr_info(" *** mtp | network server unable to"
                                   //" start timed_fwd_bflt_thread |"
                                   //" ktb_main_init *** \n");
                                if(start_eviction_thread() < 0)
                                        pr_info("***mtp | network server unable"
                                                        " to start ktb_eviction_thread|"
                                                        " ktb_main_init *** \n");

                                if(start_fwd_filter(tmem_system_bloom_filter) < 0)
                                        pr_info("***mtp | network server unable"
                                                        " to start timed_fwd_bflt_thread"
                                                        " | ktb_main_init *** \n");

                        }
                }
                */
        }

        /*
         * debugfs entries
         */
#ifdef CONFIG_DEBUG_FS
        root = debugfs_create_dir("kvm_tmem_bknd", NULL);

        if(root != NULL)
        {
                debugfs_create_u64("puts", S_IRUGO, root, &tmem_puts);
                debugfs_create_u64("puts_succ", S_IRUGO, root, &succ_tmem_puts);
                debugfs_create_u64("puts_failed", S_IRUGO, root,\
                                &failed_tmem_puts);

                debugfs_create_u64("remotify_puts", S_IRUGO, root,\
                                &tmem_remotify_puts);
                debugfs_create_u64("remotify_puts_succ", S_IRUGO, root,\
                                &succ_tmem_remotify_puts);
                debugfs_create_u64("remotify_puts_failed", S_IRUGO, root,\
                                &failed_tmem_remotify_puts);

                debugfs_create_u64("gets", S_IRUGO, root, &tmem_gets);
                debugfs_create_u64("gets_succ", S_IRUGO, root, &succ_tmem_gets);
                debugfs_create_u64("gets_failed", S_IRUGO, root,\
                                &failed_tmem_gets);

                debugfs_create_u64("remotified_gets", S_IRUGO, root,\
                                &tmem_remotified_gets);
                debugfs_create_u64("remotified_gets_succ", S_IRUGO, root,\
                                &succ_tmem_remotified_gets);
                debugfs_create_u64("remotified_gets_failed", S_IRUGO, root,\
                                &failed_tmem_remotified_gets);

                debugfs_create_u64("gets_from_remote", S_IRUGO, root,\
                                &gets_from_remote);
                debugfs_create_u64("gets_from_remote_succ", S_IRUGO, root,\
                                &succ_gets_from_remote);
                debugfs_create_u64("gets_from_remote_failed", S_IRUGO, root,\
                                &failed_gets_from_remote);

                debugfs_create_u64("dedups", S_IRUGO, root, &tmem_dedups);
                debugfs_create_u64("dedups_succ", S_IRUGO, root,\
                                &succ_tmem_dedups);
                debugfs_create_u64("dedups_failed", S_IRUGO, root,\
                                &failed_tmem_dedups);

                debugfs_create_u64("remote_dedups", S_IRUGO, root,\
                                &tmem_remote_dedups);
                debugfs_create_u64("remote_dedups_succ", S_IRUGO, root,\
                                &succ_tmem_remote_dedups);
                debugfs_create_u64("remote_dedups_failed", S_IRUGO, root,\
                                &failed_tmem_remote_dedups);

                debugfs_create_u64("invalidates", S_IRUGO, root,\
                                &tmem_invalidates);
                debugfs_create_u64("invalidates_succ", S_IRUGO, root,\
                                &succ_tmem_invalidates);
                debugfs_create_u64("invalidates_failed", S_IRUGO, root,\
                                &failed_tmem_invalidates);

                debugfs_create_u64("inode_invalidates", S_IRUGO, root,\
                                &tmem_inode_invalidates);
                debugfs_create_u64("inode_invalidates_succ", S_IRUGO, root,\
                                &succ_tmem_inode_invalidates);
                debugfs_create_u64("inode_invalidates_failed", S_IRUGO, root,\
                                &failed_tmem_inode_invalidates);

                debugfs_create_u64("page_invalidates", S_IRUGO, root,\
                                &tmem_page_invalidates);
                debugfs_create_u64("page_invalidates_succ", S_IRUGO, root,\
                                &succ_tmem_page_invalidates);
                debugfs_create_u64("page_invalidates_failed", S_IRUGO, root,\
                                &failed_tmem_page_invalidates);

                debugfs_create_u64("test_remotify", S_IRUGO, root,\
                                &test_remotify);
                debugfs_create_u64("test_remotify_succ", S_IRUGO, root,\
                                &test_remotify_succ);
                debugfs_create_u64("test_remotify_fail", S_IRUGO, root,\
                                &test_remotify_fail);

                debugfs_create_u64("test_remotified_get", S_IRUGO, root,\
                                &test_remotified_get);
                debugfs_create_u64("test_remotified_get_succ", S_IRUGO, root,\
                                &test_remotified_get_succ);
                debugfs_create_u64("test_remotified_get_fail", S_IRUGO, root,\
                                &test_remotified_get_fail);
        }
#endif
        /*
         * end debugfs entries
         */

        /*
         * debug(function): Specify functions you want to debug.
         * This enables debug messages on error conditions complete with
         * line number, function name and name of file.
         *
         * show_msg(function): Specify functions whose output msgs you wish
         * to see.
         * This enables output messages of functions of you interest.
         */

        //----------------------------
        //en/dis-able ktb_main.c debug
        //----------------------------
        /*
        debug(ktb_new_pool);
           debug(ktb_put_page);
           debug(ktb_dup_put_page);
           debug(ktb_get_page);
           debug(ktb_flush_page);
           debug(ktb_flush_object);
           debug(ktb_destroy_pool);
           debug(ktb_destroy_client);
           debug(ktb_remotify_puts);
           */
        //end en/dis-able ktb_main.c debug

        //-------------------------
        // en/dis-able tmem.c debug
        //-------------------------
        /*
           debug(pcd_associate);
           debug(tmem_pgp_free);
           debug(tmem_pgp_destroy);
           debug(tmem_pool_destroy_objs);
           debug(custom_radix_tree_destroy);
           debug(custom_radix_tree_node_destroy);
           debug(pcd_add_to_remote_tree);
           debug(pcd_remote_associate);
           debug(timed_fwd_filter);
        debug(tmem_pcd_status_update);
        debug(pcd_disassociate);
        debug(tmem_pgp_free_data);
        debug(ktb_remotify_puts);
        debug(ktb_remotified_get_page);
        debug(ktb_remote_get);
           */
        // end en/dis-able tmem.c debug

        //---------------------------
        //en/dis-able remote.c debug
        //---------------------------
        //debug(update_bflt);
        // end en/dis-able remote.c debug 

        //---------------------------
        //en/dis-able bloom_filter.c debug 
        //---------------------------
        //debug(bloom_filter_add);
        //debug(bloom_filter_check);
        // end en/dis-able bloom_filter.c debug 

        /******************************/

        //------------------------------
        // en/dis-able ktb_main.c output
        //------------------------------
        /*
        show_msg(ktb_new_pool);
           show_msg(ktb_put_page);
           show_msg(ktb_dup_put_page);
           show_msg(ktb_get_page);
           show_msg(ktb_flush_page);
           show_msg(ktb_flush_object);
           show_msg(ktb_destroy_pool);
           show_msg(ktb_destroy_client);
        show_msg(ktb_remotify_puts);
        show_msg(ktb_remotified_get_page);
        show_msg(ktb_remote_get);
           */
        //end en/dis-able ktb_main.c output

        //-------------------------
        //en/dis-able tmem.c output
        //-------------------------
        /*
        show_msg(tmem_pgp_free_data);
        show_msg(pcd_disassociate);
        show_msg(tmem_pcd_status_update);
        //show_msg(pcd_associate);
           show_msg(pcd_remote_associate);
           show_msg(timed_fwd_filter);
           show_msg(pcd_add_to_remote_tree);
           show_msg(tmem_pgp_free);
           show_msg(tmem_pgp_destroy);
           show_msg(tmem_pool_destroy_objs);
           show_msg(custom_radix_tree_destroy);
           show_msg(custom_radix_tree_node_destroy);
           */
        // end en/dis-able tmem.c output

        //---------------------------
        //en/dis-able remote.c output
        //---------------------------
        //show_msg(update_bflt);
        // end en/dis-able remote.c output

        //---------------------------
        //en/dis-able bloom_filter.c output
        //---------------------------
        //show_msg(bloom_filter_add);
        //show_msg(bloom_filter_check);
        // end en/dis-able bloom_filter.c output
        return 0;

        /*
netfail:
vfree(tmem_system_bloom_filter);
init_bflt_alg_fail:
vfree(tmem_system_bloom_filter);
init_bflt_fail:
return -1;
*/
}
/******************************************************************************/
/*			                                   END KTB MODULE INIT*/
/******************************************************************************/

/******************************************************************************/
/*						               KTB MODULE EXIT*/
/******************************************************************************/
static void __exit ktb_main_exit(void)
{
        int ret;
        int cli_id;
        int count = 0;
        //struct tmem_page_content_descriptor *pcd = NULL;
        struct list_head *pos = NULL;
        //struct list_head *pos_next = NULL;

        /* first set all the kvm_host_tmem_ops to NULL */
        kvm_host_tmem_deregister_ops();

        /* now you can reset pointers to actual functions here */ 
        ktb_ops.kvm_host_new_pool = NULL;
        ktb_ops.kvm_host_put_page = NULL;
        ktb_ops.kvm_host_get_page = NULL;
        ktb_ops.kvm_host_flush_page = NULL;
        ktb_ops.kvm_host_flush_object = NULL;
        ktb_ops.kvm_host_destroy_pool = NULL;
        ktb_ops.kvm_host_create_client = NULL;
        ktb_ops.kvm_host_destroy_client = NULL;


        /* 
         * remove the remaining pcds from the system_rs_pcds list and destroy
         * the pcds. The pcds from the system_lol_pcds and system_rscl_pcds list
         * will be removed as a part of pcd_disassociate which will be called
         * eventually as a result of ktb_destroy_client().  For pcds in
         * system_rs_pcds also the same happens?? Isn't it?
         write_lock(&(tmem_system.system_list_rwlock));
        //if(!list_empty(&pcd->system_rscl_pcds))
        if(!list_empty(&(tmem_system.remote_shared_list)))
        {
        list_for_each_safe(pos, pos_next,
        &(tmem_system.remote_shared_list))
        {
        pcd = 
        list_entry(pos, struct tmem_page_content_descriptor,
        system_rs_pcds);
        list_del_init(&(pcd->system_rs_pcds));
        kfree(pcd->remote_ip);
        kmem_cache_free(tmem_page_content_desc_cachep, pcd);
        }
        }
        write_unlock(&(tmem_system.system_list_rwlock));
        */
        if(kvm_tmem_bknd_devict)
                kobject_put(kvm_tmem_bknd_devict);

        /*
        mutex_lock(&timed_ff_mutex);
        if(fwd_bflt_thread != NULL)
        {
                if(!timed_fwd_filter_stopped)
                {
                        pr_info(" *** !! *** !! *** \n");
                        ret = kthread_stop(fwd_bflt_thread);

                        if(!ret)
                                pr_info(" *** mtp | timed forward filter thread"
                                                " stopped: %d | ktb_main_exit *** \n",
                                                ret);

                        if(fwd_bflt_thread != NULL)
                                put_task_struct(fwd_bflt_thread);
                }
        }
        mutex_unlock(&timed_ff_mutex);

        if(ktb_eviction_thread != NULL)
        {
                if(!ktb_eviction_thread_stopped)
                {
                        pr_info(" @@@@@@@@@@@@@@@@ \n");
                        ret = kthread_stop(ktb_eviction_thread);

                        if(!ret)
                                pr_info(" *** mtp | ktb eviction thread"
                                                " stopped: %d | ktb_main_exit *** \n",
                                                ret);

                        if(ktb_eviction_thread != NULL)
                                put_task_struct(ktb_eviction_thread);
                }
        }

        if(tmem_system_bloom_filter != NULL)
        {
                bloom_filter_reset(tmem_system_bloom_filter);

                if(bloom_filter_unref(tmem_system_bloom_filter))
                        pr_info(" *** mtp | tmem_system_bloom_filter removed"
                                        " successfully | ktb_main_exit \n");
                else
                        pr_info(" *** mtp | failed to remove"
                                        " tmem_system_bloom_filter"
                                        " | ktb_main_exit \n");
        }

        if(tcp_server != NULL &&  tcp_server->thread != NULL)
                network_server_exit();

        for(cli_id = 0; cli_id < MAX_CLIENTS; cli_id++)
                ktb_destroy_client(cli_id);
        */


        /* checking if all pcds are indeed deleted by a ktb_destroy_client call */
        //write_lock(&(tmem_system.system_list_rwlock));
        read_lock(&(tmem_system.system_list_rwlock));
        //if(!list_empty(&pcd->system_rscl_pcds))
        if(!list_empty(&(tmem_system.remote_shared_list)))
        {
                list_for_each(pos, &(tmem_system.remote_shared_list))
                {
                        count++;
                        /*
                           pcd = 
                           list_entry(pos, struct tmem_page_content_descriptor,
                           system_rs_pcds);
                           if(pcd == NULL)
                           continue;
                           list_del_init(&(pcd->system_rs_pcds));
                           kfree(pcd->remote_ip);
                           kmem_cache_free(tmem_page_content_desc_cachep, pcd);
                           */
                }
        }
        read_unlock(&(tmem_system.system_list_rwlock));
        //write_unlock(&(tmem_system.system_list_rwlock));

        pr_info("***mtp | RS pcds that still remained: %d | ktb_main_exit***\n",
                        count);

        count = 0;
        pos = NULL;

        read_lock(&(tmem_system.system_list_rwlock));
        //if(!list_empty(&pcd->system_rscl_pcds))
        if(!list_empty(&(tmem_system.local_only_list)))
        {
                list_for_each(pos, &(tmem_system.local_only_list))
                {
                        count++;
                        /*
                           pcd = 
                           list_entry(pos, struct tmem_page_content_descriptor,
                           system_lol_pcds);
                           if(pcd == NULL)
                           continue;
                           list_del_init(&(pcd->system_rs_pcds));
                           kfree(pcd->remote_ip);
                           kmem_cache_free(tmem_page_content_desc_cachep, pcd);
                           */
                }
        }
        read_unlock(&(tmem_system.system_list_rwlock));

        pr_info("***mtp| LOL pcds that still remained: %d | ktb_main_exit***\n",
                        count);

        count = 0;
        pos = NULL;


        read_lock(&(tmem_system.system_list_rwlock));
        //if(!list_empty(&pcd->system_rscl_pcds))
        if(!list_empty(&(tmem_system.remote_sharing_candidate_list)))
        {
                list_for_each(pos, &(tmem_system.remote_sharing_candidate_list))
                {
                        count++;
                        /*
                           pcd = 
                           list_entry(pos, struct tmem_page_content_descriptor,
                           system_lol_pcds);
                           if(pcd == NULL)
                           continue;
                           list_del_init(&(pcd->system_rs_pcds));
                           kfree(pcd->remote_ip);
                           kmem_cache_free(tmem_page_content_desc_cachep, pcd);
                           */
                }
        }
        read_unlock(&(tmem_system.system_list_rwlock));

        pr_info("***mtp| RS pcds that still remained: %d | ktb_main_exit***\n",
                        count);

        debugfs_remove_recursive(root);

        /* should free the kmem caches also before exiting */
        kmem_cache_destroy(tmem_page_content_desc_cachep);
        kmem_cache_destroy(tmem_objects_cachep);
        kmem_cache_destroy(tmem_page_descriptors_cachep);

        pr_info(" *** mtp | REMOVED *******kvm_tmem_bknd******* REMOVED |"
                        " ktb_main_exit *** \n");
}
/******************************************************************************/
/*							   END KTB MODULE EXIT*/
/******************************************************************************/
module_init(ktb_main_init)
module_exit(ktb_main_exit)
/******************************************************************************/
/*								END KTB MODULE*/
/******************************************************************************/
