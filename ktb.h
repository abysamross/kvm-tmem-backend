#ifndef _KTB_H_
#define _KTB_H_

#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/rbtree.h> 
#include <linux/radix-tree.h>
#include <linux/list.h>
#include <linux/tmem.h>

#define LOCAL_CLIENT ((uint16_t) - 1)
#define TMEM_CLIENT 1
#define MAX_CLIENTS 16
#define MAX_POOLS_PER_CLIENT 16
#define TMEM_POOL_PRIVATE_UUID	{ 0, 0 }
#define OBJ_HASH_BUCKETS 256
#define PAGE_HASH_MASK 256
#define OBJ_HASH_BUCKETS_MASK (OBJ_HASH_BUCKETS-1)
#define NOT_SHAREABLE ((uint16_t)-1UL)

#define MY_ASSERT

#ifdef MY_ASSERT
#define ASSERT(p) \
	do { \
		if (unlikely(!(p))) { \
			printk(KERN_ERR " *** mtp | Assertion failed! "\
					"%s, %s, %s,line=%d | *** \n", \
			#p, __FILE__, __func__, __LINE__); \
		} \
	} while (0)
#else
#define ASSERT(p) do { if ( 0 && (p) ); } while (0)
#endif

#define ASSERT_SPINLOCK(_l) ASSERT(spin_is_locked(_l))
#define ASSERT_WRITELOCK(_l) ASSERT(rw_is_write_locked(_l))

#define KTB_GFP_MASK \
         (__GFP_FS | __GFP_NORETRY | __GFP_NOMEMALLOC)


/******************************************************************************/
/*						   Declaration of debug macros*/			 	 
/******************************************************************************/
#define debug(f) (debug_##f = 1)
#define can_debug(f) (debug_##f == 1)
#define show_msg(f) (show_msg_##f = 1)
#define can_show(f) (show_msg_##f == 1)
/******************************************************************************/
/*					       End declaration of debug macros*/ 
/******************************************************************************/

/******************************************************************************/
/*				   Declaration of ktb data structures and api */ 
/******************************************************************************/

/******************************************************************************/
/*					    KTB CLIENT related data structures*/
/******************************************************************************/
struct tmem_client {
	/*Each pool corresponds to a fs in a client*/
	uint16_t client_id;
	struct tmem_pool *this_client_all_pools[MAX_POOLS_PER_CLIENT];
        //struct list_head remote_sharing_candidate_list;
        //struct list_head local_only_list;
	bool allocated;
	/*refcount: What is this for??*/
	//atomic_t refcount;
    	//long eph_count;
	//long eph_count_max;
};
/******************************************************************************/
/*					End KTB CLIENT related data structures*/
/******************************************************************************/

/******************************************************************************/
/*					      KTB POOL related data structures*/
/******************************************************************************/
struct tmem_pool {
	/****/

	struct tmem_client* associated_client;
	uint64_t uuid[2]; /* 0 for private, non-zero for shared */
	uint32_t pool_id;
	/* protected by pool_rwlock */
	struct rb_root obj_rb_root[OBJ_HASH_BUCKETS]; 
	
	/*pool synchronization*/
	rwlock_t pool_rwlock;
	//atomic_t refcount;
	
	/*pool acccounting*/
	long obj_count;  /* atomicity depends on pool_rwlock held for write */
	long obj_count_max;

	/*pool unused/unknown*/

	//struct list_head persistent_page_list;
	//unsigned long objnode_count, objnode_count_max;
	//bool shared;
	//bool persistent;
	//bool is_dying;
	//struct tmem_page_descriptor *cur_pgp;
    	//uint64_t sum_life_cycles;

	/****/
};

/******************************************************************************/
/*					  End KTB POOL related data structures*/
/******************************************************************************/

/******************************************************************************/
/*				       KTB pool OBJECT related data structures*/
/******************************************************************************/
struct tmem_oid;

struct tmem_object_root {
	struct tmem_oid oid;
	struct rb_node rb_tree_node; /* protected by pool->pool_rwlock */
	struct radix_tree_root tree_root; /* tree of pages within object */
	struct tmem_pool* pool;
	
	/*tmem_object_root synchronization*/
	spinlock_t obj_spinlock;

	/*tmem_object_root accounting*/
	unsigned long objnode_count; /* atomicity depends on obj_spinlock */
	long pgp_count; /* atomicity depends on obj_spinlock */
	//uint16_t last_client;
};

//seems like will have to do without it as of now
struct tmem_object_node {
	struct tmem_object_root *obj;
	struct radix_tree_node rtn;
};
/******************************************************************************/
/*		 		   End KTB pool OBJECT related data structures*/
/******************************************************************************/

/******************************************************************************/
/*				  KTB pool object PAGE related data structures*/
/******************************************************************************/
struct tmem_page_descriptor {
	/*
	 * can do away with certian unions and keep only what is neccessary for 
	 * now
	 */
	/*	
	union 
	{
		struct list_head global_eph_pages;
		struct list_head client_inv_pages;
	};
	*/
	/*
	union 
	{
		struct 
		{
	    		union
			{
				struct list_head client_eph_pages;
				struct list_head pool_pers_pages;
	    		};
	    		struct tmem_object_root *obj;
		} us;

		struct tmem_oid inv_oid;  // used for invalid list only
	};
	*/
	struct tmem_object_root *obj;
	/* this variable indicates whether this is pgp is holding a compressed 
	 * page or not
	 * I think I should do away with this
	 */
	uint32_t size; 
	/* 0 == PAGE_SIZE (pfp), -1 == data invalid,
		    		else compressed data (cdata) */
	uint32_t index;
	/* must hold pcd_tree_rwlocks[firstbyte] to use pcd pointer/siblings */
	
	uint16_t firstbyte; /* NON_SHAREABLE->pfp  otherwise->pcd */
	//bool eviction_attempted;  /* CHANGE TO lifetimes? (settable) */
	//struct list_head pcd_siblings;
	
	struct page* tmem_page;  // page frame pointer 
	struct tmem_page_content_descriptor *pcd; // page dedup 
	uint32_t pool_id;  // used for invalid list only

        //struct list_head client_rscl_pgps;
        //struct list_head client_lol_pgps; 
	/*
	union 
	{
		//struct page_info *pfp;  // page frame pointer  
		struct page* tmem_page;  // page frame pointer 
		char *cdata; // compressed data //
		struct tmem_page_content_descriptor *pcd; // page dedup 
	};

	union 
	{
		uint64_t timestamp;
		uint32_t pool_id;  // used for invalid list only
	};
	*/
};

/******************************************************************************/
/*		 	      End KTB pool object PAGE related data structures*/
/******************************************************************************/
struct tmem_system_view {
        struct rb_root pcd_tree_roots[256]; 
        struct radix_tree_root pcd_remote_tree_roots[256];
        //struct radix_tree_root pcd_remotified_tree_roots[256];
        rwlock_t pcd_tree_rwlocks[256]; 
        rwlock_t pcd_remote_tree_rwlocks[256];
        //rwlock_t pcd_remotified_tree_rwlocks[256];
        struct list_head remote_sharing_candidate_list;
        struct list_head local_only_list;
	struct list_head remote_shared_list;
        //struct list_head pcd_preorder_stack;
        rwlock_t system_list_rwlock;
        //spinlock_t system_list_lock;
};
/******************************************************************************/
/*				  KTB pool object PAGE related data structures*/
/******************************************************************************/
struct tmem_page_content_descriptor {
        /*status: 0 - local, 1 - being accessed by remote, 2 - put in remote*/
        int status;
	/*
	union 
	{
		char *cdata; // if compression_enabled
		char *tze; // if !compression_enabled,trailing zeroes eliminated
	};
	*/
        /*this pgp field is just for testing correctness*/
        struct tmem_page_descriptor *pgp;
	struct page *system_page;  //page frame pointer
	struct rb_node pcd_rb_tree_node;
  	//uint32_t index;
	uint32_t size; 
	uint32_t pgp_ref_count;
	/*pcd accounting*/
	
        struct list_head system_rscl_pcds;
        struct list_head system_lol_pcds;
	struct list_head system_rs_pcds;
        //struct list_head preorder_stack;
        char *remote_ip;
	/* 
	 * @remote_id can be the id of the remote page that you've remote
	 * deduplicated this pcd page with; which is unique in the radix 
	 * tree pcd_remote_tree_roots[firstbyte] at the remote machine.
	 * 		OR
	 * if this pcd page is being remote deduplicated by some remote machine
	 * then @remote_id is the unique id in the corresponding radix tree
	 * pcd_remote_tree_roots[firstbyte]. 
	 *
	 * hence it will never be both.
	 */
        unsigned long remote_id;
        uint8_t firstbyte;
        //uint64_t pagehash;
	//struct list_head pgp_list;
    	//bool eviction_attempted;  // CHANGE TO lifetimes? (settable)
	
	/* 
         * meaning of 'size'
	 * if compression_enabled -> 0<size<PAGE_SIZE (*cdata)
         * else if tze, 0<=size<PAGE_SIZE, rounded up to mult of 8
         * else PAGE_SIZE -> *pfp
         */
};
/******************************************************************************/
/*		 	     End KTB pool object PAGE  related data structures*/
/******************************************************************************/
//extern long long deduped_puts;
//extern struct rb_root pcd_tree_roots[256]; // choose based on first byte of page
//extern rwlock_t pcd_tree_rwlocks[256]; // poor man's concurrency for now
//extern spinlock_t client_list_lock;
extern struct tmem_system_view tmem_system;

extern struct kmem_cache* tmem_page_descriptors_cachep;
extern struct kmem_cache* tmem_page_content_desc_cachep;
extern struct kmem_cache* tmem_objects_cachep;
extern struct kmem_cache* tmem_object_nodes_cachep;

/*my bloom filter related*/
extern struct bloom_filter* tmem_system_bloom_filter;

/*tmem pool functions*/
extern void tmem_new_pool(struct tmem_pool* , uint32_t );
extern void tmem_flush_pool(struct tmem_pool*, int);

/*tmem pool object functions*/
extern unsigned tmem_oid_hash(struct tmem_oid*);
extern struct tmem_object_root* tmem_obj_alloc(struct tmem_pool*,\
		struct tmem_oid*);
extern struct tmem_object_root* tmem_obj_find(struct tmem_pool*,\
		struct tmem_oid*);
extern int tmem_obj_rb_insert(struct rb_root*, struct tmem_object_root*);
extern void tmem_obj_free(struct tmem_object_root*);
extern void tmem_obj_destroy(struct tmem_object_root*);

/*tmem object pgp functions*/
extern struct tmem_page_descriptor* tmem_pgp_alloc(struct tmem_object_root*);
extern int tmem_pgp_add_to_obj(struct tmem_object_root*, uint32_t,\
		struct tmem_page_descriptor*);
extern struct tmem_page_descriptor* tmem_pgp_lookup_in_obj(\
		struct tmem_object_root* , uint32_t);
extern void tmem_pgp_delist_free(struct tmem_page_descriptor*);
extern void tmem_pgp_free(struct tmem_page_descriptor*);
extern void tmem_pgp_free_data(struct tmem_page_descriptor *);    
extern struct tmem_page_descriptor* tmem_pgp_delete_from_obj(\
		struct tmem_object_root*, uint32_t );  

/*get client's page content functions*/
extern uint8_t tmem_get_first_byte(struct page*);
extern int tmem_pcd_copy_to_client(struct page* client_page,\
		struct tmem_page_descriptor *pgp);                                
/*copy from client*/
extern int tmem_copy_from_client(struct page*, struct page*);
/*copy to client*/
extern int tmem_copy_to_client(struct page* client_page, struct page* page);      

/*main dedup function*/
extern int pcd_associate(struct tmem_page_descriptor*, uint32_t);

/*main remote dedup function*/
extern int pcd_remote_associate(struct page*);
/*custom radix_tree_destroy function*/
//bool  __radix_tree_delete_node(struct radix_tree_root*,struct radix_tree_node*);
//void* indirect_to_ptr(void *);

/*list functions*/
extern void update_summary(struct tmem_page_descriptor*);

/*
//tcp server
extern int network_server_init(void);
extern void network_server_exit(void);

//tcp client
extern int tcp_client_init(void);
extern void tcp_client_exit(void);
extern int tcp_client_fwd_filter(struct bloom_filter *); 
*/
#endif /*_KTB_H_*/
