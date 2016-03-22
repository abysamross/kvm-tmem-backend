#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/cleancache.h>
#include <linux/tmem.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include "ktb.h"

#define mtp_debug 0 
#define mtp_debug_spl 0
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

//static struct tmem_client ktb_host;
static struct tmem_client ktb_all_clients[MAX_CLIENTS];

struct kmem_cache* tmem_page_descriptors_cachep;
struct kmem_cache* tmem_page_content_desc_cachep;
struct kmem_cache* tmem_objects_cachep;
struct kmem_cache* tmem_object_nodes_cachep;

struct rb_root pcd_tree_roots[256]; /* choose based on first byte of page */
rwlock_t pcd_tree_rwlocks[256]; /* poor man's concurrency for now */
long long deduped_puts;

void show_client_pool_info(struct tmem_client*, struct tmem_pool*);

int debug_ktb_new_pool = 0;
int debug_ktb_destroy_pool = 0;
int debug_ktb_put_page = 0;
int debug_ktb_dup_put_page = 0;
int debug_ktb_get_page = 0;
int debug_ktb_flush_page = 0;
int debug_ktb_flush_object = 0;
int debug_pcd_associate = 0;
int debug_pcd_disassociate = 0;
int debug_ktb_destroy_client = 0;
int debug_tmem_pool_destroy_objs = 0;
int debug_tmem_pgp_destroy = 0;
int debug_tmem_pgp_free = 0;
int debug_tmem_pgp_free_data = 0;
int debug_custom_radix_tree_destroy = 0;
int debug_custom_radix_tree_node_destroy = 0;

int show_msg_ktb_new_pool = 0;
int show_msg_ktb_destroy_pool = 0;
int show_msg_ktb_put_page = 0;
int show_msg_ktb_dup_put_page = 0;
int show_msg_ktb_get_page = 0;
int show_msg_ktb_flush_page = 0;
int show_msg_ktb_flush_object = 0;
int show_msg_pcd_associate = 0;
int show_msg_pcd_disassociate = 0;
int show_msg_ktb_destroy_client = 0;
int show_msg_tmem_pool_destroy_objs = 0;
int show_msg_tmem_pgp_destroy = 0;
int show_msg_tmem_pgp_free = 0;
int show_msg_tmem_pgp_free_data = 0;
int show_msg_custom_radix_tree_destroy = 0;
int show_msg_custom_radix_tree_node_destroy = 0;

/******************************************************************************/
/*							  ktb helper functions*/
/******************************************************************************/
//Get a client with client ID if one exists
static struct tmem_client* ktb_get_client_by_id(int client_id)
{
	//struct tmem_client* client = &ktb_host;
	struct tmem_client* client = NULL;
	
	//pr_info("***ktb_get_client_by_id***\n");
	//if (client_id != LOCAL_CLIENT) 
	//{
	
	//return NULL if Max number of clients exceeded
	if (client_id >= MAX_CLIENTS)
		goto out;
		
	//return an existing or allocated but unintialized/unused client address
	client = &ktb_all_clients[client_id];
	
	//}
	//else
	//client = &ktb_host;
out:
	return client;
}

//checks if the client ID belongs to an existing client
//or an invalid client (client ID i>= 16)
//else initializes a new client 
int ktb_new_client(int client_id)
{
	struct tmem_client *client;
	int ret = 0;

	//pr_info("***ktb_new_client***\n");
	client = ktb_get_client_by_id(client_id);
	
	//return 0 if Max number of clients exceeded
	if (client == NULL)
		goto out;

	//return -1 if a client with this client ID already exists
	if (client->allocated)
	{
		ret = -1;
		goto out;
	}

	//initialize a new client and return 1
	client->allocated = 1;
	client->client_id = client_id;
	ret = 1;

out:
	if(ret == 1)
		pr_info(" *** mtp | Initialized new client: %d | "
				"ktb_new_client *** \n", client_id);
	else if(ret == -1)
		pr_info(" *** mtp | Existing client: %d operation | "
				"ktb_new_client *** \n", client_id);
	else
		pr_info(" *** mtp | No such client possible: %d | "
				"ktb_new_client *** \n ", client_id);

	return ret;
}
/******************************************************************************/
/*						   End of ktb helper functions*/
/******************************************************************************/
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
/*                           					 KTB FUNCTIONS*/
/******************************************************************************/
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
			client->this_client_all_pools[poolid] = NULL;                                               
			tmem_flush_pool(pool, client_id);                                            
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

	//if(can_show(ktb_destroy_client))
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

	//pool = ktb_get_pool_by_id(client_id, pool_id);
	
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

	//if(can_show(ktb_flush_object))
	pr_info(" *** mtp | successfully deleted object: %llu %llu %llu rooted "
		"at rb_tree slot: %u of pool: %u of client: %u | "
		"ktb_flush_object*** \n", oidp->oid[2], oidp->oid[1], 
		oidp->oid[0], oidp_hash, pool->pool_id, 
		pool->associated_client->client_id);

	return 0;

out:                                                                             
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

	//pgp_delist_free(pgp);                                                        
	tmem_pgp_free(pgp);

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
	//if(can_show(ktb_flush_page))
	pr_info(" *** mtp | successfully deleted page with index: %u from "
		"object: %llu %llu %llu rooted at rb_tree slot: %u of pool: %u "
		"of client: %u | ktb_flush_page *** \n", 
		index, oidp->oid[2], oidp->oid[1], oidp->oid[0], 
		oidp_hash, pool->pool_id, client->client_id);

	return 0;

out:                                                                             
	return (unsigned long)ret;                                                                
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
			pr_info(" *** mtp: %s, %s, %d | object: %llu %llu %llu "
				"does not exist | ktb_get_page*** \n", 
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

	/*If page is locally deduplicated*/
	if(kvm_tmem_dedup_enabled && (pgp->firstbyte != NOT_SHAREABLE))
		rc = tmem_pcd_copy_to_client(client_page, pgp);                                      
	else                                                                         
       	rc = tmem_copy_to_client(client_page, pgp->tmem_page);                        
   
	if ( rc <= 0 )                                                               
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

	//pgp_delist_free(pgp);                                                
	tmem_pgp_free(pgp);
	
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

	//if(can_show(ktb_get_page))
		pr_info(" *** mtp | Successfully served page at index: %u, "
			"object: %llu %llu %llu rooted at rb_tree slot: %u of "
			"pool: %u of client: %u | ktb_get_page *** \n",
			index, oidp->oid[2], oidp->oid[1], oidp->oid[0], 
			oidp_hash, pool->pool_id, client->client_id);

	return 0;                                                                    
                                                                                 
bad_copy:                                                                        
	spin_unlock(&obj->obj_spinlock);                                             
out:
	return (unsigned long)rc;
}

static int ktb_dup_put_page(struct tmem_page_descriptor *pgp,\
		struct page* client_page)                                               
{                                                                                
	struct tmem_pool *pool;                                                      
	struct tmem_object_root *obj;                                                
	struct tmem_client *client;                                                       
	struct tmem_page_descriptor *pgpfound = NULL;                                
	unsigned long vaddr;
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

	vaddr = (get_zeroed_page(GFP_ATOMIC));
	pgp->tmem_page = virt_to_page(vaddr);

    	if (pgp->tmem_page == NULL)                          
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
		if(pcd_associate(pgp, 0) == -ENOMEM)
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
	//if(can_show(ktb_dup_put_page))
	pr_info(" *** mtp | successfully inserted page with index: %u, " 
		"of object: %llu %llu %llu in pool: %u of client: %u | "
		"ktb_dup_put_page *** \n",
		pgp->index, obj->oid.oid[2], obj->oid.oid[1], 
		obj->oid.oid[0], pool->pool_id, client->client_id); 
	
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
	unsigned long vaddr;
	unsigned int oidp_hash = tmem_oid_hash(oidp);
	//unsigned long paddr;

	client = ktb_get_client_by_id(client_id);
	if(unlikely(client == NULL))
	{
		if(can_debug(ktb_put_page))
			pr_info(" *** mtp: %s, %s, %d | No such client possible"
				" : %d | ktb_put_page *** \n ", 
				__FILE__, __func__, __LINE__, client->client_id);
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

			return -1;
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
				"of pool: %u of client: %u | ktb_put_page *** \n",
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
	
	vaddr = (get_zeroed_page(GFP_ATOMIC));
	pgp->tmem_page = virt_to_page(vaddr);
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
		if(pcd_associate(pgp, 0) == -ENOMEM)
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
	}

/*
	code to insert this object into various lists like the
	local_only_list, remote_sharing_candidate list,
	remote_shared list etc goes here
*/
	spin_unlock(&obj->obj_spinlock);
	//if(can_show(ktb_put_page))
	pr_info(" *** mtp | successfully inserted page with index: %u, " 
		"of object: %llu %llu %llu at rb_tree slot: %u of pool: %u "
		"of client: %u | ktb_put_page *** \n",
		index, oidp->oid[2], oidp->oid[1], oidp->oid[0],
		oidp_hash, pool->pool_id, client->client_id); 
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
	//if(can_show(ktb_destroy_pool))
	pr_info(" *** mtp | Successfully destroyed pool: %d of client: %d | "
		"ktb_destory_pool *** \n", pool_id, client_id); 
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

	if((unsigned int)client_id < MAX_CLIENTS)
	{
		//client = &ktb_all_clients[client_id];
		ktb_new_client(client_id)?\
			(client = &ktb_all_clients[client_id]):(client = NULL);
	}
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

	/* Implement this, this is being called from arch/x86/kvm/x86.c,
	 * via kvm_tmem_backend (kvm_tmem.c),
	 * when a VM is destroyed in kvm_arch_destroy_vm function
	 */

	.kvm_host_destroy_client = ktb_destroy_client,
	//.kvm_host_destroy_client = NULL,
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
	char *s = "kvm_tmem_bknd";

	pr_info(" *** mtp | INSERTED ********kvm_tmem_bknd******** INSERTED | "
		"ktb_main_init *** \n");
	//BUG_ON(sizeof(struct cleancache_filekey) != sizeof(struct tmem_oid));
	//pr_info(" *** MODULE | CURRENT ******** pid: %d, name: %s ******** "
	//	  " INSERTED | MODULE *** \n", current->pid, current->comm);
	
	pr_info(" *** mtp | kvm_tmem_bknd_enabled: %d, use_cleancache: %d | "
		"ktb_main_init *** \n", kvm_tmem_bknd_enabled, use_cleancache);

	if (kvm_tmem_bknd_enabled && use_cleancache) 
	{
		
		
		pr_info(" *** mtp | Boot Parameter Working | "
			"ktb_main_init *** \n");
		//BUG_ON(sizeof(struct cleancache_filekey) != 
		//sizeof(struct tmem_oid));
		

       		//ktb_radix_tree_init_maxindex();			
		kvm_host_tmem_register_ops(&ktb_ops);
		
		pr_info(" *** mtp | Cleancache enabled using: %s | "
				"ktb_main_init *** \n", s);
		
		tmem_objects_cachep = 
			kmem_cache_create("ktb_tmem_objects",\
				sizeof(struct tmem_object_root), 0, 0, NULL);
		
		tmem_page_descriptors_cachep = 
			kmem_cache_create("ktb_page_descriptors",\
				sizeof(struct tmem_page_descriptor), 0, 0, NULL);

		tmem_page_content_desc_cachep = 
			kmem_cache_create("ktb_page_content_descriptors",\
			sizeof(struct tmem_page_content_descriptor), 0, 0, NULL);

		//tmem_object_nodes_cachep =
		//kmem_cache_create("ktb_object_nodes",
		//sizeof(struct tmem_object_node), 0, 0, NULL);
		
		//ktb_new_client(TMEM_CLIENT);                                  
		/*	
		*/
		if(kvm_tmem_dedup_enabled)
		{
			for(i = 0; i < 256; i++)
			{
				pcd_tree_roots[i] = RB_ROOT;
				rwlock_init(&pcd_tree_rwlocks[i]);
			}
		}
	}

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
	*/
	debug(ktb_flush_page);
	debug(ktb_flush_object);
	debug(ktb_destroy_client);

	//end en/dis-able ktb_main.c debug

	//-------------------------
	// en/dis-able tmem.c debug
	//-------------------------
	/*
	debug(pcd_associate);
	debug(pcd_disassociate);
	debug(tmem_pgp_destroy);
	debug(tmem_pgp_free);
	debug(tmem_pgp_free_data);
	*/
	debug(tmem_pool_destroy_objs);
	debug(custom_radix_tree_destroy);
	debug(custom_radix_tree_node_destroy);
	// end en/dis-able tmem.c debug


	//------------------------------
	// en/dis-able ktb_main.c output 
	//------------------------------
	/*
	show_msg(ktb_new_pool);
	show_msg(ktb_put_page);
	show_msg(ktb_dup_put_page);
	show_msg(ktb_get_page);
	*/
	show_msg(ktb_flush_page);
	show_msg(ktb_flush_object);
	show_msg(ktb_destroy_client);
	
	//en/dis-able ktb_main.c output 

	//-------------------------
	//en/dis-able tmem.c output 
	//-------------------------
	/*
	show_msg(pcd_associate);
	show_msg(pcd_disassociate);
	show_msg(tmem_pgp_destroy);
	show_msg(tmem_pgp_free);
	show_msg(tmem_pgp_free_data);
	*/
	show_msg(tmem_pool_destroy_objs);
	show_msg(custom_radix_tree_destroy);
	show_msg(custom_radix_tree_node_destroy);
	// end en/dis-able tmem.c output 

	return 0;
}
/******************************************************************************/
/*						           END KTB MODULE INIT*/
/******************************************************************************/

/******************************************************************************/
/*							       KTB MODULE EXIT*/
/******************************************************************************/
static void __exit ktb_main_exit(void)
{
	ktb_ops.kvm_host_new_pool = NULL;
	ktb_ops.kvm_host_put_page = NULL;
	ktb_ops.kvm_host_get_page = NULL;
	ktb_ops.kvm_host_flush_page = NULL;
	ktb_ops.kvm_host_flush_object = NULL;
	ktb_ops.kvm_host_destroy_pool = NULL,
	ktb_ops.kvm_host_destroy_client = NULL,

	kvm_host_tmem_deregister_ops();

	pr_info(" *** mtp | REMOVED *******kvm_tmem_bknd******* REMOVED | "
		"ktb_main_exit *** \n");
}
/******************************************************************************/
/*							   END KTB MODULE EXIT*/
/******************************************************************************/

module_init(ktb_main_init)
module_exit(ktb_main_exit)
/******************************************************************************/
/*								END KTB MODULE*/
/******************************************************************************/
