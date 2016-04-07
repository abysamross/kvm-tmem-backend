#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/kvm_types.h>
#include <linux/slab.h>
#include <linux/tmem.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <asm/spinlock.h>
#include "ktb.h"

/******************************************************************************/
/*							   EXTERN DECLARATIONS*/
/******************************************************************************/
extern int debug_pcd_associate;
extern int debug_pcd_disassociate;
extern int debug_tmem_pool_destroy_objs;
extern int debug_tmem_pgp_destroy;
extern int debug_tmem_pgp_free;
extern int debug_tmem_pgp_free_data;
extern int debug_custom_radix_tree_destroy;
extern int debug_custom_radix_tree_node_destroy;

extern int show_msg_pcd_associate;
extern int show_msg_pcd_disassociate;
extern int show_msg_tmem_pool_destroy_objs;
extern int show_msg_tmem_pgp_destroy;
extern int show_msg_tmem_pgp_free;
extern int show_msg_tmem_pgp_free_data;
extern int show_msg_custom_radix_tree_destroy;
extern int show_msg_custom_radix_tree_node_destroy;
/******************************************************************************/
/*					 	       END EXTERN DECLARATIONS*/
/******************************************************************************/

/******************************************************************************/
/*					 	    STATIC FUNCTION PROTOTYPES*/
/******************************************************************************/
static int tmem_page_cmp(struct page *, struct page *);
static uint8_t tmem_get_first_byte(struct page* );
static void tmem_free_page(struct page* );
/******************************************************************************/
/*					 	END STATIC FUNCTION PROTOTYPES*/
/******************************************************************************/

/******************************************************************************/
/*						   CUSTOM RADIX TREE FUNCTIONS*/
/******************************************************************************/
static void custom_radix_tree_node_destroy(struct radix_tree_root *root,\
		struct radix_tree_node *node, void (*slot_free)(void *),\
		unsigned long level, unsigned long curr_slot)
{
	int i;
	for(i = 0; i < RADIX_TREE_MAP_SIZE; i++, curr_slot++)
	{
		struct radix_tree_node *slot = node->slots[i];
		BUG_ON(radix_tree_is_indirect_ptr(slot));

		if(can_debug(custom_radix_tree_node_destroy))
			pr_info(" *** mtp | parent level: %lu, parent node: %u "
				"level: %lu, node: %lu, slot: %d, "
				"index: %lu | "
				"custom_radix_tree_node_destroy *** \n",
				level?(level-1):1000, 
                                node->path >> RADIX_TREE_HEIGHT_SHIFT,
				level, curr_slot >> RADIX_TREE_MAP_SHIFT,
                                i, curr_slot);

		if(slot == NULL)
		{
			if(can_debug(custom_radix_tree_node_destroy))
				pr_info(" *** mtp | node->slot[%d] = NULL, "
					"continuing | "
					"custom_radix_tree_node_destroy *** \n",
					i);
			continue;
		}
		//if(node->height == 1)
                /*
		if(can_debug(custom_radix_tree_node_destroy))
			pr_info(" *** mtp | MAP_SHIFT: %d, "
				"MAP_SIZE: %lu, "
				"MAP_MASK: %lu, "
				"MAX_PATH: %lu, \n"
				"HEIGHT_SHIFT: %lu, "
				"HEIGHT_MASK: %lu, "
				"(node->path & RADIX_TREE_HEIGHT_MASK): %lu "
				"| custom_radix_tree_node_destroy \n",
				RADIX_TREE_MAP_SHIFT,
				RADIX_TREE_MAP_SIZE,
				RADIX_TREE_MAP_MASK,
				RADIX_TREE_MAX_PATH,
				RADIX_TREE_HEIGHT_SHIFT,
				RADIX_TREE_HEIGHT_MASK,
				(node->path & RADIX_TREE_HEIGHT_MASK));
                */
                if(can_debug(custom_radix_tree_node_destroy))
                        pr_info(" *** mtp | node->slot[%d] != NULL | "
                                "custom_radix_tree_node_destroy *** \n", i);

		if((node->path & RADIX_TREE_HEIGHT_MASK) == 1)
		{
		    if(slot_free)
		    {
			    if(can_debug(custom_radix_tree_node_destroy))
				pr_info(" *** mtp | "
                                        "(node->path & RADIX_TREE_HEIGHT_MASK) "
                                        "= %lu, calling tmem_pgp_destroy "
                                        "directly for index: %lu | "
					"custom_radix_tree_node_destroy *** \n",
				        node->path & RADIX_TREE_HEIGHT_MASK, 
                                        curr_slot);
			    slot_free(slot);
                            /* should i check for and clear all tags explicitly
                             * here?? Seems to work fine without that!
                             */
                            node->slots[i] = NULL;
                            node->count--;
		    }
		}
		else
		{
			if(can_debug(custom_radix_tree_node_destroy))
				pr_info(" *** mtp | "
                                        "(node->path & RADIX_TREE_HEIGHT_MASK) "
                                        "= %lu, calling custom_radix_tree_node_"
                                        "destroy recursively | "
					"custom_radix_tree_node_destroy *** \n",
				node->path & RADIX_TREE_HEIGHT_MASK);

		    	custom_radix_tree_node_destroy(root, slot, slot_free,\
					level+1, curr_slot << 6);
		}
	}
	//again discrepency with number of arguments
	//radix_tree_node_free(root, node);
	if(can_debug(custom_radix_tree_node_destroy))
                pr_info(" *** mtp | All children of node: %lu, at level: %lu "
			"have been deleted. node->count: %u, Freeing the node. | "
                        "custom_radix_tree_node_destroy *** \n",
			curr_slot >> RADIX_TREE_MAP_SHIFT, level, node->count);
        //radix_tree_node_free(node);
        //trying out a radix tree node delete call
        //seems to be not working !!
        if(__radix_tree_delete_node(root, node) == true)
        {
                if(can_debug(custom_radix_tree_node_destroy))
                        pr_info(" *** mtp | Node: %lu at level: %lu  deleted "
                                "successfully | custom_radix_tree_node_destroy "
                                "*** \n", curr_slot >> RADIX_TREE_MAP_SHIFT, 
                                level);
        }
        else
        {
                if(can_debug(custom_radix_tree_node_destroy))
                        pr_info(" *** mtp | Node: %lu at level: %lu  deletion "
                                "failed | custom_radix_tree_node_destroy "
                                "*** \n", curr_slot >> RADIX_TREE_MAP_SHIFT, 
                                level);
        }
}

void custom_radix_tree_destroy(struct radix_tree_root *root,\
		void (*slot_free)(void *))
{
	struct radix_tree_node *node = root->rnode;

    	if(node == NULL)
        	return;

    	if(!radix_tree_is_indirect_ptr(node))
	{
		//radix tree root rnode points directly to a data
		//item than another radix_tree_node.
        	if (slot_free)
		{
			if(can_debug(custom_radix_tree_destroy))
				pr_info(" *** mtp | calling tmem_pgp_destroy "
					"directly as radix_tree_root points "
					"directly to a data item | "
					"custom_radix_tree_destroy *** \n");

            		slot_free(node);
		}
    	}
	else
	{
		//radix tree root rnode points to another
		//radix_tree_node.
		if(can_debug(custom_radix_tree_destroy))
			pr_info(" *** mtp | calling custom_radix_tree_node "
				"destroy as radix_tree_root points to "
				"another radix_tree_node | "
				"custom_radix_tree_destroy *** \n");

        	node = indirect_to_ptr(node);
        	custom_radix_tree_node_destroy(root, node, slot_free, 0, 0);
	}
	//my radix_tree_init doesn't take any arguments
    	//radix_tree_init(root);
	INIT_RADIX_TREE(root, GFP_ATOMIC);
}

/******************************************************************************/
/*					       END CUSTOM RADIX TREE FUNCTIONS*/
/******************************************************************************/

/******************************************************************************/
/*						     MAIN PCD & DEDUP ROUTINES*/
/******************************************************************************/
int tmem_pcd_copy_to_client(struct page* client_page,\
		struct tmem_page_descriptor *pgp)
{
	uint8_t firstbyte = pgp->firstbyte;
	struct tmem_page_content_descriptor *pcd;
	int ret;

	ASSERT(kvm_tmem_dedup_enabled);
	read_lock(&pcd_tree_rwlocks[firstbyte]);
	pcd = pgp->pcd;

	//ret = tmem_copy_to_client(cmfn, pcd->pfp, tmem_cli_buf_null);
	ret = tmem_copy_to_client(client_page, pcd->system_page);
	read_unlock(&pcd_tree_rwlocks[firstbyte]);
	return ret;
}

int pcd_associate(struct tmem_page_descriptor* pgp, uint32_t csize)
{
	struct rb_node **new, *parent = NULL;
	struct rb_root *root;
	struct tmem_page_content_descriptor *pcd = NULL;
	int cmp;
	uint32_t tmem_page_size = 0;
	uint8_t firstbyte = 0;
	//tmem_get_first_byte(pgp->tmem_page);
	int ret = 0;

	if(!kvm_tmem_dedup_enabled)
		return 0;

	firstbyte = tmem_get_first_byte(pgp->tmem_page);

	ASSERT(firstbyte < 256);
	ASSERT(pgp->obj != NULL);
	ASSERT(pgp->obj->pool != NULL);

	ASSERT(pgp->tmem_page != NULL);
	tmem_page_size = PAGE_SIZE;
	//Not really sure whether the below assert is required or not
	ASSERT(!(tmem_page_size & (sizeof(uint64_t)-1)));

	//Accessing the pcd rb trees
	write_lock(&pcd_tree_rwlocks[firstbyte]);
	root = &pcd_tree_roots[firstbyte];
	new = &(root->rb_node);

	if(can_show(pcd_associate))
		pr_info(" *** mtp | Looking to de-duplicate page with index: "
			"%u of object: %llu %llu %llu rooted at rb_tree slot: "
			"%u of pool: %u of client: %u, having firstbyte: %u | "
			"pcd_associate *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], tmem_oid_hash(&(pgp->obj->oid)),
			pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id, firstbyte);

	while ( *new )
	{
		pcd = container_of(*new, struct tmem_page_content_descriptor,\
				pcd_rb_tree_node);
		parent = *new;

		//compare new entry and rb_tree entry, set cmp accordingly
		ASSERT(pgp->tmem_page != NULL);
		ASSERT(pcd->system_page != NULL);

		cmp = tmem_page_cmp(pgp->tmem_page, pcd->system_page);

		//walk tree or match depending on cmp
		if ( cmp < 0 )
		{
			new = &((*new)->rb_left);
		}
		else if ( cmp > 0 )
		{
			new = &((*new)->rb_right);
		}
		else
		{
			//if(can_show(pcd_associate))
				pr_info(" *** mtp | Got a match to de-duplicate"
					" page with index: %u of object: %llu "
					"%llu %llu rooted at rb_tree slot: %u "
					"of pool: %u of client: %u, having "
					"firstbyte: %u | pcd_associate *** \n",
					pgp->index, pgp->obj->oid.oid[2],
					pgp->obj->oid.oid[1],pgp->obj->oid.oid[0],
				       	tmem_oid_hash(&(pgp->obj->oid)),
					pgp->obj->pool->pool_id,
				pgp->obj->pool->associated_client->client_id,
					firstbyte);
		 	//match! free the no-longer-needed page
			//tmem_free_page(pgp->obj->pool, pgp->tmem_page);
			tmem_free_page(pgp->tmem_page);
		 	deduped_puts++;
			goto match;
		}
	}

	//if(can_show(pcd_associate))
		pr_info(" *** mtp | Found no match to de-duplicate page with "
			"index: %u of object: %llu %llu %llu rooted at rb_tree "
			"slot: %u of pool: %u of client: %u, having firstbyte: "
			"%u | pcd_associate *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], tmem_oid_hash(&(pgp->obj->oid)),
			pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id, firstbyte);
	//no match for an existing pcd, therefor allocate a new pcd and put it in
	//tree
	//pcd = kmem_cache_alloc(tmem_page_content_desc_cachep, KTB_GFP_MASK);
	pcd = kmem_cache_alloc(tmem_page_content_desc_cachep, GFP_ATOMIC);

	ASSERT(pcd);
	if(pcd == NULL)
	{
		if(can_debug(pcd_associate))
			pr_info(" *** mtp | Could not allocate a new page "
				"content descriptor for page with index: %u "
				"of object: %llu %llu %llu rooted at rb_tree "
				"slot: %u of pool: %u of client: %u, having "
				"firstbyte: %u | pcd_associate *** \n",
				pgp->index, pgp->obj->oid.oid[2],
				pgp->obj->oid.oid[1], pgp->obj->oid.oid[0],
				tmem_oid_hash(&(pgp->obj->oid)),
				pgp->obj->pool->pool_id,
				pgp->obj->pool->associated_client->client_id,
				firstbyte);

		ret = -ENOMEM;
		goto unlock;
	}

	RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);
	//INIT_LIST_HEAD(&pcd->pgp_list);
	//Point pcd->system_page to client page contents now available in
	//pgp->tmem_page
	pcd->system_page = pgp->tmem_page;
	pcd->size = PAGE_SIZE;
	pcd->pgp_ref_count = 0;

	rb_link_node(&pcd->pcd_rb_tree_node, parent, new);
	rb_insert_color(&pcd->pcd_rb_tree_node, root);

match:
	pcd->pgp_ref_count++;
	//list_add(&pgp->pcd_siblings,&pcd->pgp_list);
	pgp->firstbyte = firstbyte;
	//pgp->eviction_attempted = 0;
	pgp->pcd = pcd;
unlock:
	write_unlock(&pcd_tree_rwlocks[firstbyte]);
	return ret;
}

/* ensure pgp no longer points to pcd, nor vice-versa */
/* take pcd rwlock unless have_pcd_rwlock is set, always unlock when done */
//static void pcd_disassociate(struct tmem_page_descriptor *pgp,
//		struct tmem_pool *pool, int have_pcd_rwlock)
static void pcd_disassociate(struct tmem_page_descriptor *pgp,\
		int have_pcd_rwlock)
{

	struct tmem_page_content_descriptor *pcd = pgp->pcd;
	struct page* system_page = pgp->pcd->system_page;
	uint16_t firstbyte = pgp->firstbyte;
	//uint32_t pcd_size = pcd->size;
	//uint32_t pgp_size = pgp->size;
	ASSERT(kvm_tmem_dedup_enabled);
	ASSERT(firstbyte != NOT_SHAREABLE);
	ASSERT(firstbyte < 256);

	//if(have_pcd_rwlock)
	 //ASSERT_WRITELOCK(&pcd_tree_rwlocks[firstbyte]);
	//else
	 write_lock(&pcd_tree_rwlocks[firstbyte]);

	pgp->pcd = NULL;
	pgp->firstbyte = NOT_SHAREABLE;
	pgp->size = -1;

	 //If more pgps are referring this pcd then you return from here itself
	if (--pcd->pgp_ref_count)
	{
		//if(can_show(pcd_disassociate))
			pr_info(" *** mtp | Diassociating page with index: %u "
				"of object: %llu %llu %llu rooted at rb_tree "
				"slot: %u of pool: %u of client: %u, having "
				"firstbyte: %u from it's page content descriptor"
				" | pcd_disassociate *** \n",
				pgp->index, pgp->obj->oid.oid[2],
				pgp->obj->oid.oid[1], pgp->obj->oid.oid[0],
				tmem_oid_hash(&(pgp->obj->oid)),
				pgp->obj->pool->pool_id,
				pgp->obj->pool->associated_client->client_id,
				firstbyte);

		write_unlock(&pcd_tree_rwlocks[firstbyte]);
		return;
	}

	//if(can_show(pcd_disassociate))
	pr_info(" *** mtp | Diassociating page with index: %u of object: "
		"%llu %llu %llu rooted at rb_tree slot: %u of pool: %u "
		"of client: %u, having firstbyte: %u from it's page "
		"content descriptor (NO MORE REF TO THIS PAGE)| "
		"pcd_disassociate *** \n",
		pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
		pgp->obj->oid.oid[0], tmem_oid_hash(&(pgp->obj->oid)),
		pgp->obj->pool->pool_id,
		pgp->obj->pool->associated_client->client_id, firstbyte);

	//no more references to this pcd, recycle it and the physical page
	pcd->system_page = NULL;
	//remove pcd from rbtree
	rb_erase(&pcd->pcd_rb_tree_node, &pcd_tree_roots[firstbyte]);
	//reinit the struct for safety for now
	RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);
	//now free up the pcd memory
	kmem_cache_free(tmem_page_content_desc_cachep, pcd);
	//free up the system page that pcd held
	tmem_free_page(system_page);
	write_unlock(&pcd_tree_rwlocks[firstbyte]);
}
/******************************************************************************/
/*					         END MAIN PCD & DEDUP ROUTINES*/
/******************************************************************************/

/******************************************************************************/
/*							   STRUCT PAGE ROUTINE*/
/******************************************************************************/
//static void tmem_free_page(struct tmem_pool* pool, struct page* tmem_page)
static void tmem_free_page(struct page* page)
{
	ASSERT(page);
        if(page == NULL)
                BUG();
        else	
		__free_page(page);
}

static uint8_t tmem_get_first_byte(struct page* tmem_page)
{
	const uint8_t *p = page_address(tmem_page);
	uint8_t byte = p[0];
	return byte;
}

static int tmem_page_cmp(struct page *pgp_tmem_page, struct page *pcd_tmem_page)
{
	/*
	 * Not explicitly mapping as pgp_tmem_page is the new page that we
	 * obtained using virt_to_page recently and pcd_tmem_page is pointing
	 * to another already existing pgp->tmem_page
	 */

	//const uint64_t *p1 = __map_domain_page(pfp1);
	const uint64_t *p1 = page_address(pgp_tmem_page);
	const uint64_t *p2 = page_address(pcd_tmem_page);
	int rc = memcmp(p1, p2, PAGE_SIZE);

	return rc;
}

int tmem_copy_to_client(struct page* client_page, struct page* page)
{
	//map tmem_page and cli_page to va-s and do memcpy
	unsigned long *tmem_va, *client_va;
	int ret = 1;

	//check if tmem_page is already mapped !!
	//if it is already mapped then we need only map client_page
	//I seriously think this is not needed as the struct page tmem_page was
	//obtained by calling virt_to_page

	//tmem_va = kmap(tmem_page);
	//added later
	tmem_va = page_address(page);

	ASSERT(tmem_va);
	if(tmem_va == NULL)
		return -1;

	//client_va = page_address(client_page);
	client_va = kmap_atomic(client_page);

	ASSERT(client_va);
	if(client_va == NULL)
		return -1;

	if(!memcpy(client_va, tmem_va, PAGE_SIZE))
		ret = -1;

	kunmap_atomic(client_va);
        smp_mb();
	return ret;
}

int tmem_copy_from_client(struct page* tmem_page, struct page* client_page)
{
	//map tmem_page and cli_page to va-s and do memcpy
	unsigned long *tmem_va, *client_va;
	int ret = 1;

	//check if tmem_page is already mapped !!
	//if it is already mapped then we need only map client_page
	//I seriously think this is not needed as the struct page tmem_page was
	//obtained by calling virt_to_page

	//tmem_va = kmap(tmem_page);
	//added later
	tmem_va = page_address(tmem_page);

	ASSERT(tmem_va);
	if(tmem_va == NULL)
		return -1;

	client_va = kmap_atomic(client_page);
	//client_va = page_address(client_page);

	ASSERT(client_va);
	if(client_va == NULL)
		return -1;

        smp_mb();
	if(!memcpy(tmem_va, client_va, PAGE_SIZE))
		ret = -1;

	kunmap_atomic(client_va);

	return ret;
}
/******************************************************************************/
/*						END STRUCT PAGE ROUTINES      */
/******************************************************************************/

/******************************************************************************/
/*					PAGE DESCRIPTOR MANIPULATION ROUTINES */
/******************************************************************************/
//void tmem_pgp_free_data(struct tmem_page_descriptor *pgp,
//		struct tmem_pool *pool)
void tmem_pgp_free_data(struct tmem_page_descriptor *pgp)
{
	//uint32_t pgp_size = pgp->size;
	if(pgp->tmem_page == NULL)
		return;

	if(can_show(tmem_pgp_free_data))
		pr_info(" *** mtp | freeing data of pgp of page with index: %u, "
			"of object: %llu %llu %llu in pool: %d, of client: %d "
			"| tmem_pgp_free_data *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id);

	if(kvm_tmem_dedup_enabled && pgp->firstbyte != NOT_SHAREABLE)
		pcd_disassociate(pgp,0);
	//pcd_disassociate(pgp,pool,0);
	else
		tmem_free_page(pgp->tmem_page);
	//tmem_free_page(pgp->obj->pool, pgp->tmem_page);

	pgp->tmem_page = NULL;
	pgp->size = -1;
}

void tmem_pgp_free(struct tmem_page_descriptor *pgp)
{
	struct tmem_pool *pool = NULL;

	ASSERT(pgp->obj != NULL);
	//ASSERT(pgp->obj->pool != NULL);
	ASSERT(pgp->obj->pool->associated_client != NULL);

	pool = pgp->obj->pool;

	if(can_show(tmem_pgp_free))
		pr_info(" *** mtp | freeing pgp of page with index: %u, "
			"of object: %llu %llu %llu in pool: %d, of client: %d "
			"| tmem_pgp_free *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id);

	tmem_pgp_free_data(pgp);

	//pgp->size = -1;
	pgp->obj = NULL;
	pgp->index = -1;
	kmem_cache_free(tmem_page_descriptors_cachep, pgp);
}

static void tmem_pgp_destroy(void *v)
{
	struct tmem_page_descriptor *pgp = (struct tmem_page_descriptor *)v;

	ASSERT(pgp);
	pgp->obj->pgp_count--;
	//pgp_delist_free(pgp);
	if(can_show(tmem_pgp_destroy))
		pr_info(" *** mtp | destroying pgp of page with index: %u, "
			"of object: %llu %llu %llu in pool: %d, of client: %d "
			"| tmem_pgp_destroy *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id);

   	tmem_pgp_free(pgp);
}

struct tmem_page_descriptor *tmem_pgp_delete_from_obj\
			    (struct tmem_object_root *obj, uint32_t index)
{
	struct tmem_page_descriptor *pgp;

	ASSERT(obj != NULL);
	ASSERT_SPINLOCK(&obj->obj_spinlock);
	ASSERT(obj->pool != NULL);

    	pgp = radix_tree_delete(&obj->tree_root, index);

    	if ( pgp != NULL )
        	obj->pgp_count--;

    	ASSERT(obj->pgp_count >= 0);

    	return pgp;
}


struct tmem_page_descriptor *tmem_pgp_lookup_in_obj(\
		struct tmem_object_root *obj, uint32_t index)
{
	ASSERT(obj != NULL);
	ASSERT_SPINLOCK(&obj->obj_spinlock);
	ASSERT(obj->pool != NULL);
	return radix_tree_lookup(&obj->tree_root, index);
}

int tmem_pgp_add_to_obj (struct tmem_object_root *obj, uint32_t index,\
		struct tmem_page_descriptor *pgp)
{
	int ret;

	ASSERT_SPINLOCK(&obj->obj_spinlock);
	ret = radix_tree_insert(&obj->tree_root, index, pgp);

	if ( !ret )
	{
		obj->pgp_count++;
	}

	return ret;
}

struct tmem_page_descriptor *tmem_pgp_alloc(struct tmem_object_root *obj)
{
	struct tmem_page_descriptor *pgp;
	struct tmem_pool *pool;

	ASSERT(obj != NULL);
	ASSERT(obj->pool != NULL);
	pool = obj->pool;

	//pgp = kmem_cache_alloc(tmem_page_descriptors_cachep, KTB_GFP_MASK);
	pgp = kmem_cache_alloc(tmem_page_descriptors_cachep, GFP_ATOMIC);

	ASSERT(pgp);
	if (pgp == NULL)
	{
		return NULL;
	}

	//pgp->us.obj = obj;
	//INIT_LIST_HEAD(&pgp->global_eph_pages);
	//INIT_LIST_HEAD(&pgp->us.client_eph_pages);
	pgp->tmem_page = NULL;

	if(kvm_tmem_dedup_enabled)
	{
		pgp->firstbyte = NOT_SHAREABLE;
		//pgp->eviction_attempted = 0;
		//INIT_LIST_HEAD(&pgp->pcd_siblings);
	}
	pgp->size = -1;
	pgp->index = -1;
	pgp->obj = obj;
	//pgp->timestamp = get_cycles();
	//atomic_inc_and_max(global_pgp_count);
	//atomic_inc_and_max(pool->pgp_count);
	return pgp;
}
/******************************************************************************/
/*				     END PAGE DESCRIPTOR MANIPULATION ROUTINES*/
/******************************************************************************/

/******************************************************************************/
/*				  POOL OBJECT COLLECTION MANIPULATION ROUTINES*/
/******************************************************************************/
static void oid_set_invalid(struct tmem_oid *oidp)
{
	oidp->oid[0] = oidp->oid[1] = oidp->oid[2] = -1UL;
}

unsigned tmem_oid_hash(struct tmem_oid *oidp)
{
	return (hash_long(oidp->oid[0] ^ oidp->oid[1] ^ oidp->oid[2],
        	BITS_PER_LONG) & OBJ_HASH_BUCKETS_MASK);
}

static int tmem_oid_compare(struct tmem_oid *left, struct tmem_oid *right)
{
	if ( left->oid[2] == right->oid[2] )
	{
		if ( left->oid[1] == right->oid[1] )
		{
	    		if ( left->oid[0] == right->oid[0] )
				return 0;
	    		else if ( left->oid[0] < right->oid[0] )
				return -1;
	    		else
				return 1;
		}
		else if ( left->oid[1] < right->oid[1] )
	    		return -1;
		else
	    		return 1;
	}
	else if ( left->oid[2] < right->oid[2] )
		return -1;
	else
		return 1;
}

/* Returns a locked object if one is found*/
struct tmem_object_root * tmem_obj_find(struct tmem_pool *pool,\
		struct tmem_oid *oidp)
{
	struct rb_node *node;
	struct tmem_object_root *obj;

	restart_find:
	read_lock(&pool->pool_rwlock);
	//pr_info("*** hash(oidp): %u\n ***", tmem_oid_hash(oidp));
	node = pool->obj_rb_root[tmem_oid_hash(oidp)].rb_node;

	while ( node )
	{
		obj = container_of(node, struct tmem_object_root, rb_tree_node);
		switch ( tmem_oid_compare(&obj->oid, oidp) )
		{
		    case 0: /* equal */

			if(!spin_trylock(&obj->obj_spinlock))
			{
			    read_unlock(&pool->pool_rwlock);
			    goto restart_find;
			}
			read_unlock(&pool->pool_rwlock);
			return obj;

		    case -1:
			node = node->rb_left;
			break;

		    case 1:
			node = node->rb_right;
		}
	}
	read_unlock(&pool->pool_rwlock);
	return NULL;
}
/* free an object that has no more pgps in it */
void tmem_obj_free(struct tmem_object_root *obj)
{
	struct tmem_pool *pool;
	struct tmem_oid old_oid;
	ASSERT_SPINLOCK(&obj->obj_spinlock);
	ASSERT(obj != NULL);
	ASSERT(obj->pgp_count == 0);
	pool = obj->pool;

	ASSERT(pool != NULL);
	ASSERT(pool->associated_client != NULL);
	//ASSERT_WRITELOCK(&pool->pool_rwlock);

	//may be a "stump" with no leaves
	if ( obj->tree_root.rnode != NULL )
		custom_radix_tree_destroy(&obj->tree_root, tmem_pgp_destroy);

	ASSERT((long)obj->objnode_count == 0);
	ASSERT(obj->tree_root.rnode == NULL);
	pool->obj_count--;
	ASSERT(pool->obj_count >= 0);

	obj->pool = NULL;
	old_oid = obj->oid;

	oid_set_invalid(&obj->oid);

	rb_erase(&obj->rb_tree_node, &pool->obj_rb_root[tmem_oid_hash(&old_oid)]);
	spin_unlock(&obj->obj_spinlock);

	kmem_cache_free(tmem_objects_cachep, obj);
}

void tmem_obj_destroy(struct tmem_object_root *obj)
{
	//ASSERT_WRITELOCK(&obj->pool->pool_rwlock);
	custom_radix_tree_destroy(&obj->tree_root, tmem_pgp_destroy);
	tmem_obj_free(obj);
}

/* destroys all objs in a pool, or only if obj->last_client matches cli_id */
static void tmem_pool_destroy_objs(struct tmem_pool *pool)
{
	struct rb_node *node;
	struct tmem_object_root *obj;
	int i;

	write_lock(&pool->pool_rwlock);
	//pool->is_dying = 1;
	for (i = 0; i < OBJ_HASH_BUCKETS; i++)
	{
		node = rb_first(&pool->obj_rb_root[i]);
		while ( node != NULL )
		{
		    obj = container_of(node, struct tmem_object_root,\
				    rb_tree_node);
		    spin_lock(&obj->obj_spinlock);
		    node = rb_next(node);
		    //if ( obj->last_client == cli_id )
		    if(can_show(tmem_pool_destroy_objs))
			    pr_info(" *** mtp | destroying obj: %llu %llu %llu,"
				    " at slot: %d, of pool: %d, belonging to "
				    "client: %d | tmem_pool_destroy_objs *** \n",
				    obj->oid.oid[2], obj->oid.oid[1],
				    obj->oid.oid[0], i, pool->pool_id,
				    pool->associated_client->client_id);

		    tmem_obj_destroy(obj);
		    //else
			//spin_unlock(&obj->obj_spinlock);
		}
	}
	write_unlock(&pool->pool_rwlock);
}

struct tmem_object_root* tmem_obj_alloc (struct tmem_pool* pool,\
		struct tmem_oid *oidp)
{
	struct tmem_object_root *obj;

	//ASSERT(pool != NULL);
	//if ( (obj = kmalloc(sizeof(struct tmem_object_root), GFP_ATOMIC))
	//== NULL)
	//obj = kmem_cache_alloc(tmem_objects_cachep, KTB_GFP_MASK);
	obj = kmem_cache_alloc(tmem_objects_cachep, GFP_ATOMIC);

	if(obj == NULL)
		return NULL;

	//shouldn't I lock pool before I increment??
	pool->obj_count++;

	//obj_count_max is initialised to 0 during definition
	if (pool->obj_count > pool->obj_count_max)
		pool->obj_count_max = pool->obj_count;

	//atomic_inc_and_max(global_obj_count);
	//radix_tree_init(&obj->tree_root);
	INIT_RADIX_TREE(&obj->tree_root, GFP_ATOMIC);
	//radix_tree_set_alloc_callbacks(&obj->tree_root, rtn_alloc,
	//rtn_free, obj);
	spin_lock_init(&obj->obj_spinlock);
	obj->pool = pool;
	obj->oid = *oidp;
	obj->objnode_count = 0;
	obj->pgp_count = 0;
	//obj->last_client = pool->associated_client->client_id;
	return obj;
}

int tmem_obj_rb_insert(struct rb_root *root, struct tmem_object_root *obj)
{
	struct rb_node **new, *parent = NULL;
	struct tmem_object_root *this;

	new = &(root->rb_node);

	while ( *new )
	{
		this = container_of(*new, struct tmem_object_root, rb_tree_node);
		parent = *new;
		switch (tmem_oid_compare(&this->oid, &obj->oid))
		{
			case 0:
				return 0;
			case -1:
				new = &((*new)->rb_left);
				break;
			case 1:
				new = &((*new)->rb_right);
				break;
		}
	}

	rb_link_node(&obj->rb_tree_node, parent, new);
	rb_insert_color(&obj->rb_tree_node, root);
	return 1;
}
/******************************************************************************/
/* 			      END POOL OBJECT COLLECTION MANIPULATION ROUTINES*/
/******************************************************************************/

/******************************************************************************/
/*						    POOL MANIPULATION ROUTINES*/
/******************************************************************************/
void tmem_flush_pool(struct tmem_pool *pool, int client_id)
{
	ASSERT(pool != NULL);
	pr_info(" *** mtp | Destroying ephemeral tmem pool: %d, of client: %d | "
		"tmem_flush_pool ***\n", pool->pool_id, client_id);

	tmem_pool_destroy_objs(pool);
	//pool->client->pools[pool->pool_id] = NULL;
	kfree(pool);
}

void tmem_new_pool(struct tmem_pool *pool, uint32_t flags)
{
	//int persistent = flags & TMEM_POOL_PERSIST;
	//int shared = flags & TMEM_POOL_SHARED;
	int i;

	for (i = 0; i < OBJ_HASH_BUCKETS; i++)
		pool->obj_rb_root[i] = RB_ROOT;

	//INIT_LIST_HEAD(&pool->persistent_page_list);
	rwlock_init(&pool->pool_rwlock);
}
/******************************************************************************/
/*						END POOL MANIPULATION ROUTINES*/
/******************************************************************************/
