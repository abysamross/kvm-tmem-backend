#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/kvm_types.h>
#include <linux/slab.h>
#include <linux/tmem.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <asm/spinlock.h>
#include "ktb.h"
#include "network_tcp.h"

/******************************************************************************/
/*							   EXTERN DECLARATIONS*/
/******************************************************************************/

extern u64 test_remotified_get;
extern u64 test_remotified_get_succ;
extern u64 test_remotified_get_fail;

extern int debug_pcd_remote_associate;
extern int debug_pcd_associate;
extern int debug_pcd_disassociate;
extern int debug_tmem_pool_destroy_objs;
extern int debug_tmem_pgp_destroy;
extern int debug_tmem_pgp_free;
extern int debug_tmem_pgp_free_data;
extern int debug_custom_radix_tree_destroy;
extern int debug_custom_radix_tree_node_destroy;
extern int debug_pcd_add_to_remote_tree;
extern int debug_tmem_pcd_status_update;
extern int debug_tmem_remotified_copy_to_client;

extern int show_msg_pcd_associate;
extern int show_msg_pcd_disassociate;
extern int show_msg_tmem_pool_destroy_objs;
extern int show_msg_tmem_pgp_destroy;
extern int show_msg_tmem_pgp_free;
extern int show_msg_tmem_pgp_free_data;
extern int show_msg_custom_radix_tree_destroy;
extern int show_msg_custom_radix_tree_node_destroy;
extern int show_msg_pcd_remote_associate;
extern int show_msg_pcd_add_to_remote_tree;
extern int show_msg_tmem_pcd_status_update;
extern int show_msg_tmem_remotified_copy_to_client;

extern u64 tmem_dedups;
extern u64 succ_tmem_dedups;
extern u64 failed_tmem_dedups;

extern u64 succ_tmem_remotify_puts;
extern u64 failed_tmem_remotify_puts;

extern u64 tmem_remotified_gets;
extern u64 succ_tmem_remotified_gets;
extern u64 failed_tmem_remotified_gets;

extern u64 tmem_remote_dedups;
extern u64 succ_tmem_remote_dedups;
extern u64 failed_tmem_remote_dedups;
/******************************************************************************/
/*					 	       END EXTERN DECLARATIONS*/
/******************************************************************************/

/******************************************************************************/
/*					 	    STATIC FUNCTION PROTOTYPES*/
/******************************************************************************/
static int tmem_page_cmp(struct page *, struct page *);
//static uint8_t tmem_get_first_byte(struct page* );
static void tmem_free_page(struct page* );
/******************************************************************************/
/*					 	END STATIC FUNCTION PROTOTYPES*/
/******************************************************************************/

/******************************************************************************/
/*						   CUSTOM RADIX TREE FUNCTIONS*/
/******************************************************************************/
/*
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
 */
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
/*
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
                            // should i check for and clear all tags explicitly
                            // here?? Seems to work fine without that!
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
*/
void custom_radix_tree_destroy(struct radix_tree_root *root,\
		void (*slot_free)(void *))
{
        struct radix_tree_iter iter;
        void **slot;

        radix_tree_for_each_slot(slot, root, &iter, 0)
        {
                //struct tmem_page_descriptor *pgp = 
                //        (struct tmem_page_descriptor *)*slot;
                struct tmem_page_descriptor *pgp = 
                        radix_tree_deref_slot(slot);
                //pr_info(" *** mtp | index being deleted: %u | "
                //        "custom_radix_tree_destroy *** \n",
                //         pgp->index);

                if(radix_tree_delete(root, pgp->index) == NULL)
                {
                       if(can_show(custom_radix_tree_destroy)) 
                                pr_info(" *** mtp | item at index not present: "
                                        "%u | custom_radix_tree_destroy *** \n",
                                        pgp->index);
                } 
                else
                {
                       if(can_show(custom_radix_tree_destroy)) 
                                pr_info(" *** mtp | success, item at index "
                                        "present: %u | "
                                        "custom_radix_tree_destroy *** \n",
                                        pgp->index);
                        slot_free(pgp);
                }

        }
}
/******************************************************************************/
/*					       END CUSTOM RADIX TREE FUNCTIONS*/
/******************************************************************************/

/******************************************************************************/
/*					   MAIN PCD, REMOTIFY & DEDUP ROUTINES*/
/******************************************************************************/
void tmem_pcd_status_update(struct tmem_page_content_descriptor *pcd,
                            struct tmem_page_content_descriptor **xnexpcd,
			    uint8_t firstbyte, uint64_t remote_id,
			    char *rs_ip, int remote_match, bool *res)
{
	char *ip = NULL;
        struct tmem_page_content_descriptor *nexpcd = *xnexpcd;
	ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
	strcpy(ip, rs_ip);

	write_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));

        if(can_debug(tmem_pcd_status_update))
                pr_info("@@@@ pcd_tree_roots[%u] LOCKED @@@@\n", firstbyte);

	write_lock(&(tmem_system.system_list_rwlock));

        if(can_debug(tmem_pcd_status_update))
                pr_info("@@@@ system_list_lock LOCKED @@@@\n");
        /* it's a grave sin to get a pcd not belonging to the rscl here!! */
        BUG_ON(list_empty(&pcd->system_rscl_pcds));
	BUG_ON(pcd->system_page == NULL);
	/* 
	 * just ensuring that this is not an aleady remotified pcd.
	 * this should never happen.
	 */
	BUG_ON(pcd->remote_ip != NULL);
	BUG_ON(pcd->status == 2);
        BUG_ON(*res == true);

        if(can_debug(tmem_pcd_status_update))
                pr_info("@@@@@@ currently: %d, status: %d, firstbyte: %u,"
                        " remote_id: %llu, remote_ip: %s, remote_match:"
                        " %d, res: %s @@@@@@\n",
                        pcd->currently, pcd->status, firstbyte,
                        remote_id, rs_ip, remote_match,
                        (*res==true)?"true":"false");
        /*
         * hack_safe_nexpcd:0 to ensure that nexpcd points to a
         * valid pcd. how will it point to invalid pcd?  bcoz I
         * am unlocking my list after getting a ref to pcd and
         * in between there can be many pcd_disassociate()s This
         * will update the nexpcd to point to the latest valid
         * next pcd in list
         */
        /* safely reset the nexpcd pointer*/
        if(can_debug(tmem_pcd_status_update))
        {
                pr_info("@@@@ updating nexpcd @@@@ \n");
                /*
                if(nexpcd != NULL)
                {
                pr_info("old nexpcd address: %lx\n", (unsigned long)nexpcd);

                pr_info("@@@@ nexpcd->firstbyte: %u, nexpcd->status: %d,"
                        " nexpcd->currently: %d, nextpcd->remote_ip: %s,"
                        " nexpcd->remote_id: %llu, nexpcd->system_page: %s"
                        " @@@@\n", nexpcd->firstbyte, nexpcd->status,
                        nexpcd->currently, nexpcd->remote_ip, nexpcd->remote_id, 
                        (nexpcd->system_page==NULL)?"NULL":"NOT NULL"); 
                }
                */
        }

        smp_mb();
        list_safe_reset_next(pcd, (*xnexpcd), system_rscl_pcds);

        if(can_debug(tmem_pcd_status_update))
        {
                if(can_debug(tmem_pcd_status_update))
                {
                        pr_info("@@@@ after updating nexpcd @@@@ \n");

                pr_info("new nexpcd address: %lx\n", (unsigned long)nexpcd);
                pr_info("list head address: %lx\n",
                (unsigned long)(&(tmem_system.remote_sharing_candidate_list)));

                if(&nexpcd->system_rscl_pcds !=
                &(tmem_system.remote_sharing_candidate_list))
                {
                pr_info("@@@@ nexpcd->firstbyte: %u, nexpcd->status: %d,"
                        " nexpcd->currently: %d, nextpcd->remote_ip: %s,"
                        " nexpcd->remote_id: %llu, nexpcd->system_page: %s"
                        " @@@@\n", nexpcd->firstbyte, nexpcd->status,
                        nexpcd->currently, nexpcd->remote_ip, nexpcd->remote_id, 
                        (nexpcd->system_page==NULL)?"NULL":"NOT NULL"); 

                if(nexpcd->pgp != NULL)
                {

		pr_info(" *** mtp | pcd pgp page with index: "
			"%u of object: %llu %llu %llu rooted at rb_tree slot: "
			"%u of pool: %u of client: %u, having firstbyte: %u | "
			"tmem_pcd_status_update *** \n",
			nexpcd->pgp->index, nexpcd->pgp->obj->oid.oid[2], 
                        nexpcd->pgp->obj->oid.oid[1],
			nexpcd->pgp->obj->oid.oid[0], 
                        tmem_oid_hash(&(nexpcd->pgp->obj->oid)),
			nexpcd->pgp->obj->pool->pool_id,
			nexpcd->pgp->obj->pool->associated_client->client_id,
                        firstbyte);
                }
                }
                }
        }
        /* now you may remove him from rscl */
        /* 
         * In case there was a race/concurrent access at ktb_remotify_puts()
         * and pcd_remote_associate/pcd_associate I let the pcd remain in the
         * remote_sharing_candidate_list itself.  For a page that was
         * remote|local_associated in pcd[_remotei]_associate() while being
         * tried to remotify in ktb_remotify_puts() I will just put it in it's
         * rightful place in local_only_list.
                if(pcd->status == 1)
         */
        if(pcd->currently == ASSOCIATING)
        {
                /* 
                 * if I ever get a pcd with currently == ASSOCIATING 
                 * in here that would be only because it was remote| local
                 * associated, with a remote pcd, at the same time while it was
                 * being explored for remotification in ktb_remotify_puts() and
                 * if that is the case this pcd is certain to be in
                 * remote_sharing_candidate list itself i.e in here I shouldn't
                 * get a remote associated pcd that is already in
                 * local_only_list
                 */
                //failed_tmem_remotify_puts++;

                //if(!list_empty(&pcd->system_rscl_pcds))
                //{
                if(can_debug(tmem_pcd_status_update))
                        pr_info("@@@@ removing from rscl @@@@\n");
                list_del_init(&pcd->system_rscl_pcds); 

                if(can_debug(tmem_pcd_status_update))
                        pr_info("@@@@ moving to lol @@@@\n");

                list_add_tail(&pcd->system_lol_pcds,\
                              &(tmem_system.local_only_list));
                //}

                pcd->currently = NORMAL;
                goto getout;
        }

        /* 
         * remove the pcd from the pcd_tree_roots only if a match was found at
         * a remote server
         */
        if(
                (remote_match == 1) 
                        ||
                ((remote_match == 0) && pcd->currently == DISASSOCIATING)
        )
        {
                if(can_debug(tmem_pcd_status_update))
                        pr_info("@@@@ removing from rscl @@@@\n");
                list_del_init(&pcd->system_rscl_pcds); 

                if(can_debug(tmem_pcd_status_update))
                        pr_info("@@@@ removing from pcd_tree_roots @@@@\n");

	        /* delete this pcd from the rbtree pcd_tree_roots[firstbyte] */
                rb_erase(&pcd->pcd_rb_tree_node,\
                         &(tmem_system.pcd_tree_roots[firstbyte]));
                /* reinit the struct for safety for now */
                RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);
                /* 
                 * free the pcd->system_page. it is not required as either it is
                 * marked for disassociation or it was successfully remotified.
                 */
                __free_page(pcd->system_page);
                pcd->system_page = NULL;

                /* decrement the count of unique pages */
                system_unique_pages--;
        }

        if(pcd->currently == DISASSOCIATING)
        {
                /*
                 * this pcd was choosen to be disassociated when it was explored
                 * for remotification. it should be deleted now.
                 */
                //failed_tmem_remotify_puts++;

                if(pcd->status == 1)
                {
                        if(can_debug(tmem_pcd_status_update))
                                pr_info(" @@@@ removing from pcd_remote_tree_"
                                        "roots @@@@\n");
                        write_lock(
                        &(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));

                        if(can_debug(tmem_pcd_status_update))
                        {
                                pr_info("pcd_remote_tree_rwlocks[%u] LOCKED"
                                        " tmem_pcd_status_update\n", firstbyte);
                                pr_info(" *** mtp | disassociating a remote"
                                        " page | tmem_pcd_status_update ***\n");
                        }

                        pcd = 
                        radix_tree_delete(
                        &(tmem_system.pcd_remote_tree_roots[firstbyte])
                        ,pcd->remote_id);

                        write_unlock(
                        &(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));

                        if(can_debug(tmem_pcd_status_update))
                                pr_info("pcd_remote_tree_rwlocks[%u] UNLOCKED"
                                        " tmem_pcd_status_update\n", firstbyte);
                }
                //now free up the pcd memory
                kmem_cache_free(tmem_page_content_desc_cachep, pcd);
                pcd = NULL;
                goto getout;
        }

        pcd->currently = NORMAL;

        if(remote_match == 0)
                goto getout;

	pcd->status = 2;
	pcd->remote_ip = ip;
	pcd->remote_id = remote_id;
	/* 
	 * add this to the remote shared list;
	 * from now this page is available only in system_rs_pcds list
	 */
	//if(!list_empty(&pcd->system_rscl_pcds))
	//{
                /*
                 * hack_safe_nexpcd:1
                 * to ensure that nexpcd points to a valid pcd.
                 * how will it point to invalid pcd?
                 * bcoz I am unlocking my list after getting a ref to pcd and in
                 * between there can be many pcd_disassociate()s
                 * This will update the nexpcd to point to the latest valid next
                 * pcd in list
                 */

        if(can_debug(tmem_pcd_status_update))
                pr_info("@@@@ moving to rs @@@@\n");

        list_add_tail(&pcd->system_rs_pcds,\
                      &(tmem_system.remote_shared_list));
	//}

        if(can_debug(tmem_pcd_status_update))
        {
                if(pcd->system_page != NULL)
                        pr_info(" OMG: pcd->system_page != NULL even after"
                                "__free_page \n");
        }
	*res = true;

        //if(can_debug(tmem_pcd_status_update))
        /*
                pr_info(" exp1 | successfully remotified page with index: "
                        "%u of object: %llu %llu %llu rooted at rb_tree slot: "
                        "%u of pool: %u of client: %u, having firstbyte: %u | "
                        " *** \n",
                        pcd->pgp->index, pcd->pgp->obj->oid.oid[2],
                        pcd->pgp->obj->oid.oid[1],
                        pcd->pgp->obj->oid.oid[0],
                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                        pcd->pgp->obj->pool->pool_id,
                        pcd->pgp->obj->pool->associated_client->client_id,
                        firstbyte);
        */
        /*
         * hack_safe_nexpcd:2
         * to ensure that nexpcd points to a valid pcd I need to leave it locked
         *
	write_unlock(&(tmem_system.system_list_rwlock));
         */
getout:

        if(can_debug(tmem_pcd_status_update))
        pr_info("@@@@@@ firstbyte: %u, remote_id: %llu, remote_ip: %s,"
                " remote_match: %d, res: %s @@@@@@\n",
                firstbyte, remote_id, rs_ip, remote_match,
                (*res==true)?"true":"false");

	write_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
        if(can_debug(tmem_pcd_status_update))
                pr_info("@@@@ pcd_tree_roots[%u] UNLOCKED @@@@\n", firstbyte);
}

int tmem_remotified_copy_to_client(struct page *client_page,\
			           struct tmem_page_content_descriptor *pcd)
{
	uint8_t firstbyte;
        int ret = -1;
	uint64_t remote_id;
        void *vaddr;
	char *remote_ip;
        struct page *page = NULL;

        page = alloc_page(GFP_ATOMIC);

        if((pcd->pgp->obj->oid.oid[2] == 0) && 
           (pcd->pgp->obj->oid.oid[1] == 0) &&
           (pcd->pgp->obj->oid.oid[0] == 272842))
        {
                test_remotified_get++;
                if(can_debug(tmem_remotified_copy_to_client))
                pr_info(" exp2A | getting"
                        " remotified page with"
                        " index: %u of object:"
                        " %llu %llu %llu rooted at"
                        " rb_tree slot: %u of"
                        " pool: %u of client:"
                        " %u, having firstbyte:"
                        " %u | tmem_remotified_copy_to_client *** \n",
                        pcd->pgp->index,
                        pcd->pgp->obj->oid.oid[2],
                        pcd->pgp->obj->oid.oid[1],
                        pcd->pgp->obj->oid.oid[0],
                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                        pcd->pgp->obj->pool->pool_id,
                       pcd->pgp->obj->pool->associated_client->client_id,
                        pcd->firstbyte); 
        }

        if(page == NULL)
        {
                failed_tmem_remotified_gets++;

                if((pcd->pgp->obj->oid.oid[2] == 0) && 
                   (pcd->pgp->obj->oid.oid[1] == 0) &&
                   (pcd->pgp->obj->oid.oid[0] == 272842))
                {
                        test_remotified_get_fail++;
                        if(can_debug(tmem_remotified_copy_to_client))
                        pr_info(" exp2C | failed to"
                                " get remotified page with"
                                " index: %u of object:"
                                " %llu %llu %llu rooted at"
                                " rb_tree slot: %u of"
                                " pool: %u of client:"
                                " %u, having firstbyte:"
                                " %u | tmem_remotified_copy_to_client *** \n",
                                pcd->pgp->index,
                                pcd->pgp->obj->oid.oid[2],
                                pcd->pgp->obj->oid.oid[1],
                                pcd->pgp->obj->oid.oid[0],
                                tmem_oid_hash(&(pcd->pgp->obj->oid)),
                                pcd->pgp->obj->pool->pool_id,
                               pcd->pgp->obj->pool->associated_client->client_id,
                                pcd->firstbyte); 
                }
                goto exit_remote;
        }

        vaddr = page_address(page);
        memset(vaddr, 0, PAGE_SIZE);


	read_lock(&(tmem_system.system_list_rwlock));
	remote_id = pcd->remote_id;	
	remote_ip = pcd->remote_ip;	
	firstbyte = pcd->firstbyte;
	read_unlock(&(tmem_system.system_list_rwlock));

        if(can_debug(tmem_remotified_copy_to_client))
        pr_info(" *** mtp | getting remotified page with firstbyte: %u, ip: %s,"
                " id: %llu | tmem_remotified_copy_to_client *** \n",
                firstbyte, remote_ip, remote_id);
        ret = 
	ktb_remotified_get_page(page, remote_ip, firstbyte, remote_id); 

        if(ret < 0)
                goto free_exit_remote;

        if(can_debug(tmem_remotified_copy_to_client))
        pr_info(" *** mtp | got remotified page: %u, ip: %s, id: %llu |"
                " tmem_remotified_copy_to_client *** \n",
                firstbyte, remote_ip, remote_id);


	ret = tmem_copy_to_client(client_page, page);

free_exit_remote: 

        if(ret == 0)
        {
                succ_tmem_remotified_gets++;
                if((pcd->pgp->obj->oid.oid[2] == 0) && 
                   (pcd->pgp->obj->oid.oid[1] == 0) &&
                   (pcd->pgp->obj->oid.oid[0] == 272842))
                {
                        test_remotified_get_succ++;
                        if(can_debug(tmem_remotified_copy_to_client))
                pr_info(" exp2B | successfully"
                        " got remotified page with"
                        " index: %u of object:"
                        " %llu %llu %llu rooted at"
                        " rb_tree slot: %u of"
                        " pool: %u of client:"
                        " %u, having firstbyte:"
                        " %u | tmem_remotified_copy_to_client *** \n",
                        pcd->pgp->index,
                        pcd->pgp->obj->oid.oid[2],
                        pcd->pgp->obj->oid.oid[1],
                        pcd->pgp->obj->oid.oid[0],
                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                        pcd->pgp->obj->pool->pool_id,
                        pcd->pgp->obj->pool->associated_client->client_id,
                        firstbyte); 
                }
        }
        else
        {
                failed_tmem_remotified_gets++;

                if((pcd->pgp->obj->oid.oid[2] == 0) && 
                   (pcd->pgp->obj->oid.oid[1] == 0) &&
                   (pcd->pgp->obj->oid.oid[0] == 272842))
                {
                        test_remotified_get_fail++;
                if(can_debug(tmem_remotified_copy_to_client))
                pr_info(" exp2C | failed to"
                        " get remotified page with"
                        " index: %u of object:"
                        " %llu %llu %llu rooted at"
                        " rb_tree slot: %u of"
                        " pool: %u of client:"
                        " %u, having firstbyte:"
                        " %u | tmem_remotified_copy_to_client *** \n",
                        pcd->pgp->index,
                        pcd->pgp->obj->oid.oid[2],
                        pcd->pgp->obj->oid.oid[1],
                        pcd->pgp->obj->oid.oid[0],
                        tmem_oid_hash(&(pcd->pgp->obj->oid)),
                        pcd->pgp->obj->pool->pool_id,
                        pcd->pgp->obj->pool->associated_client->client_id,
                        firstbyte); 
                }
        }

        __free_page(page);

exit_remote:
        return ret;
}

int tmem_pcd_copy_to_client(struct page *client_page,\
                            struct tmem_page_descriptor *pgp)
{
	uint8_t firstbyte = pgp->firstbyte;
	int ret = 0;
	struct tmem_page_content_descriptor *pcd;

	ASSERT(kvm_tmem_dedup_enabled);

	read_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	pcd = pgp->pcd;
	/*
	   ret = tmem_copy_to_client(cmfn, pcd->pfp, tmem_cli_buf_null);
	   if(pcd->system_page != NULL && pcd->remote_ip == NULL)
	*/
	if(pcd->status == 0 || pcd->status == 1)
	{
		ret = tmem_copy_to_client(client_page, pcd->system_page);
		read_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	}
	//else if(pcd->system_page == NULL && pcd->remote_ip != NULL)
	else if(pcd->status == 2)
	{
                tmem_remotified_gets++;
		read_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
                if(can_debug(tmem_remotified_copy_to_client))
                pr_info(" *** mtp |issuing remotified copy to client for page"
                        " with firstbyte: %u | tmem_pcd_copy_to_client *** \n",
                        firstbyte);

		ret = tmem_remotified_copy_to_client(client_page, pcd);

                if(can_debug(tmem_remotified_copy_to_client))
                pr_info(" *** mtp |remotified copy to client for page"
                        " with firstbyte: %u returned| tmem_pcd_copy_to_client *** \n",
                        firstbyte);
	}

	return ret;
}

int pcd_add_to_remote_tree(uint8_t firstbyte, uint64_t id,\
                           struct tmem_page_content_descriptor *pcd)
{
	int ret = -1;
	//unsigned long index = (unsigned long)id;
	struct radix_tree_root *tree_root;

        if(can_debug(pcd_add_to_remote_tree))
        {
                pr_info("firstbyte: %u, lock: %d, add: %llx \n", firstbyte,
                (tmem_system.pcd_remote_tree_rwlocks[firstbyte]).raw_lock.cnts.counter,
                (unsigned long long)(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte])));
                pr_info("tree root: %llx \n", 
                 (unsigned long long)(&(tmem_system.pcd_remote_tree_roots[firstbyte])));
                pr_info("ret: %d \n", ret);
        }

	write_lock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));

        if(can_debug(pcd_add_to_remote_tree))
                pr_info("after write_lock firstbyte: %u, lock: %d, add: %llx \n",
                        firstbyte,
                (tmem_system.pcd_remote_tree_rwlocks[firstbyte]).raw_lock.cnts.counter,
                (unsigned long long)(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte])));

	tree_root = &(tmem_system.pcd_remote_tree_roots[firstbyte]);

        if(can_debug(pcd_add_to_remote_tree))
                pr_info("after getting tree root: %llx \n", 
                        (unsigned long long)tree_root);

	ret = radix_tree_insert(tree_root, id, pcd);

        if(can_debug(pcd_add_to_remote_tree))
                pr_info("after inserting into radix_tree: %d \n", ret);

	write_unlock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));

        if(can_debug(pcd_add_to_remote_tree))
                pr_info("after write_unlock firstbyte: %u, lock: %d, add: %llx \n", 
                        firstbyte,
                        (tmem_system.pcd_remote_tree_rwlocks[firstbyte]).raw_lock.cnts.counter,
                        (unsigned long long)(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte])));

	return ret;
}

int pcd_remote_associate(struct page *remote_page, uint64_t *id)
{
	uint8_t firstbyte;
	int ret = 0;
	int cmp;
	uint32_t tmem_page_size = 0;
	struct rb_node **new, *parent = NULL;
	struct rb_root *root;
	struct tmem_page_content_descriptor *pcd = NULL;
	//uint64_t pghash;
	if(!kvm_tmem_dedup_enabled)
		return 0;
	firstbyte = tmem_get_first_byte(remote_page);
	//pghash = tmem_page_hash(pgp->tmem_page);
	ASSERT(firstbyte < 256);
	tmem_page_size = PAGE_SIZE;
	//Not really sure whether the below assert is required or not
	ASSERT(!(tmem_page_size & (sizeof(uint64_t)-1)));
        /*
         * Even though there can be a race/concurrent access of pcds by
         * pcd_remote_associate() and ktb_remotify_puts() i.e while
         * ktb_remotify_puts() aquires the list lock tries to remotify pcd, but
         * while doing the network operation unlocks the list and in this gap
         * pcd_associate() aquires the list lock and moves it to
         * local_only_list.  This is not a problem as the
         * tmem_remotified_pcd_status_update() and pcd_remote_associate() are
         * protected by the pcd_tree_rwlocks[firstbyte] lock only one,
         * ktb_remotify_puts() or pcd_remote_associate(), will take effect on
         * the pcd. Remember: tmem_remotified_pcd_status_update() is invoked
         * from within ktb_remotify_puts() on finding a match at a remote server
         * to take the pcd off pcd_remote_tree_roots[firstbyte]; out of
         * remote_sharing_candidate_list and to put it in remote_shared_list.
         * But
         * its an altogether different story if pcd_remote_associate() moves the
         * pcd to lol, the pcd_disassociate() deletes many pcds including nexpcd
         * thus screwing up my nexpcd pointer taken in ktb_remotify_puts().
         * This is prevented by not moving a pcd to lol list while
         * pcd->currently == REMOTIFYING and updating it to REMOTEASSOC.  And in
         * tmem_remotified_pcd_status_update() if you find the pcd is currently
         * REMOTEASSOC then, under the list lock, update nexpcd first and move
         * it lol and prevent the remotification from happening
         */
        //Accessing the pcd rb trees
	write_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	root = &(tmem_system.pcd_tree_roots[firstbyte]);
	new = &(root->rb_node);

	tmem_remote_dedups++;
	/*
	   if(can_show(pcd_associate))
	   pr_info(" *** mtp | Looking to de-duplicate page with index: "
	   "%u of object: %llu %llu %llu rooted at rb_tree slot: "
	   "%u of pool: %u of client: %u, having firstbyte: %u | "
	   "pcd_associate *** \n",
	   pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
	   pgp->obj->oid.oid[0], tmem_oid_hash(&(pgp->obj->oid)),
	   pgp->obj->pool->pool_id,
	   pgp->obj->pool->associated_client->client_id, firstbyte);
	*/
	if(can_show(pcd_remote_associate))
		pr_info(" *** mtp | Looking to de-duplicate remote page having"
			" firstbyte: %u | pcd_remote_associate *** \n",
			firstbyte);
	while(*new)
	{
		pcd = container_of(*new, struct tmem_page_content_descriptor,\
				   pcd_rb_tree_node);
		parent = *new;
		//compare new entry and rb_tree entry, set cmp accordingly
		ASSERT(remote_page != NULL);
		ASSERT(pcd->system_page != NULL);
		BUG_ON(remote_page == NULL);
		BUG_ON(pcd->system_page == NULL);

		cmp = tmem_page_cmp(remote_page, pcd->system_page);
		//walk tree or match depending on cmp
		if ( cmp < 0 )
		{
			new = &((*new)->rb_left);
		}
		else if ( cmp > 0 )
		{
			new = &((*new)->rb_right);
		}
		/*
		if(pghash < pcd->pagehash)
		{
		new = &((*new)->rb_left);
		}
		else if(pghash > pcd->pagehash)
		{
		new = &((*new)->rb_right);
		}
		*/
		else
		{
                        if(pcd->currently == DISASSOCIATING)
                        {
	                        if(can_show(pcd_remote_associate))
                                {
                                pr_info("matched pcd is DISASSOCIATING "
                                        "pcd_remote_associate\n");
                                pr_info(" pcd->currently: %d, pcd->status: %d,"
                                        " pcd->firstbyte: %u"
                                        "pcd_remote_associate ***\n", 
                                        pcd->currently, pcd->status,
                                        pcd->firstbyte);
                                }

                                goto remoteassocfail; 
                        }

			BUG_ON(pcd->status == 2);
			BUG_ON(pcd->remote_ip != NULL);
			/*
			   if(pcd->system_page == NULL && pcd->remote_ip != NULL)
			   {
			   new = &((*new)->rb_left);
			   continue;
			   }
			   BUG_ON(pcd->system_page == NULL);
			   cmp = tmem_page_cmp(pgp->tmem_page, pcd->system_page);
			   if(cmp != 0)
			   {
			   new = &((*new)->rb_left);
			   continue;
			   }
			*/
			/*
			   if(can_show(pcd_remote_associate))
			   pr_info(" *** mtp | Got a match to de-duplicate"
			   " remote page having firstbyte: %u |"
			   " pcd_remote_associate *** \n",
			   firstbyte);
			   */
			if(can_show(pcd_remote_associate))
				pr_info(" *** mtp | Got a match to de-duplicate"
					" remote page. Local page index: %u"
					" of object: %llu %llu %llu rooted at"
					" rb_tree slot: %u of pool: %u of"
					" client: %u, having firstbyte: %u, "
                                        " pgp_firstbyte: %u, pcd_firstbyte: %u |"
					" pcd_remote_associate *** \n",
					pcd->pgp->index,
					pcd->pgp->obj->oid.oid[2],
					pcd->pgp->obj->oid.oid[1],
					pcd->pgp->obj->oid.oid[0],
					tmem_oid_hash(&(pcd->pgp->obj->oid)),
					pcd->pgp->obj->pool->pool_id,
				pcd->pgp->obj->pool->associated_client->client_id,
				firstbyte, pcd->pgp->firstbyte, pcd->firstbyte);
			/* 
			 * this pcd is alreay associated to a remote page.
			 */
			if(pcd->status == 1)
			{
				*id = pcd->remote_id;
	                        succ_tmem_remote_dedups++;
				goto getout;
			}
			//write_lock(&id_rwlock);
			/* else, give new remote id */
			pcd->remote_id = tmem_system.remote_tree_ids[firstbyte];
			*id = pcd->remote_id;
			//write_unlock(&id_rwlock);
			/* 
			 * change status to remote pcd, i.e. being accessed by
			 * remote machine
			 */
			pcd->status = 1;
			ret = 
			pcd_add_to_remote_tree(pcd->firstbyte, pcd->remote_id,\
					       pcd);
			if(ret != 0)
			{
				ret = -1;
			        pcd->status = 0;
				pcd->remote_id = 0;
				*id = 0;
				goto remoteassocfail;
			}
			else
			{
				/* 
				 * increment and keep ready remote_id of
				 * this tree for next remote association. 
				 */
				++tmem_system.remote_tree_ids[firstbyte];
				//goto match;
                                /* 
                                 * If the matched pcd is a unique pcd then move
                                 * it to lol list.  lol list. Hence even a
                                 * remote association will result in a pcd being
                                 * put to local_only_list because you don't want
                                 * this pcd to remotified anymore...obviously as
                                 * you are already allowing a remote machine to
                                 * share it. You wouldn't want to upset that guy
                                 * would you? 
                                 */
                                write_lock(&(tmem_system.system_list_rwlock));

                                /*
                                if(pcd->currently == ASSOCIATING) || 
                                (pcd->currently == REMOTIFYING)
                                */
                                if(pcd->currently == NORMAL)
                                {
                                        if(!list_empty(&pcd->system_rscl_pcds))
                                        {
                                                list_del_init(
                                                &pcd->system_rscl_pcds);
                                                list_add_tail(
                                                &pcd->system_lol_pcds,\
                                                &(tmem_system.local_only_list));
                                        }
                                }
                                else
                                {
	                                if(can_show(pcd_remote_associate))
                                        {
                                        pr_info(" *** mtp | making"
                                                " pcd->currently ="
                                                " ASSOCIATING|"
                                                " pcd_remote_associate ***\n");
                                        pr_info(" pcd->currently: %d,"
                                                " pcd->status: %d,"
                                                " pcd->firstbyte: %u"
                                                "pcd_remote_associate ***\n", 
                                                pcd->currently, pcd->status,
                                                pcd->firstbyte);
                                        }
                                        pcd->currently = ASSOCIATING;
                                }

                                write_unlock(&(tmem_system.system_list_rwlock));
	                        succ_tmem_remote_dedups++;
                                goto getout;
                        }
			/* 
			 * NOTE: we are not incrementing the pcd->refcount for a
			 * remote association, because we do not want a remote
			 * association to prevent this pcd from being destroyed
			 * locally.
			 */
		}
	}

remoteassocfail:

	ret = -1;
	//tmem_free_page();
	//__free_page(remote_page);
	//failed_tmem_dedups++;
	failed_tmem_remote_dedups++;

	if(can_show(pcd_remote_associate))
		pr_info(" *** mtp | Found no match to de-duplicate remote "
			"page having firstbyte: %u | pcd_remote_associate "
			"*** \n", firstbyte);

        //goto getout;
	/*
	pcd->pgp_ref_count++;
	//list_add(&pgp->pcd_siblings,&pcd->pgp_list);
	pgp->firstbyte = firstbyte;
	//pgp->eviction_attempted = 0;
	pgp->pcd = pcd;
	*/
//match:

	//succ_tmem_dedups++;
getout:
	write_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	//__free_page(remote_page);
	return ret;
}

int pcd_associate(struct tmem_page_descriptor* pgp, uint32_t csize)
{
	uint8_t firstbyte;
	int cmp;
	uint32_t tmem_page_size = 0;
	struct rb_node **new, *parent = NULL;
	struct rb_root *root;
	struct tmem_page_content_descriptor *pcd = NULL;
	//uint64_t pghash = 0;
	//tmem_get_first_byte(pgp->tmem_page);
	int ret = 0;

	if(!kvm_tmem_dedup_enabled)
		return 0;

	firstbyte = tmem_get_first_byte(pgp->tmem_page);
        //pghash = tmem_page_hash(pgp->tmem_page);

	ASSERT(firstbyte < 256);
	ASSERT(pgp->obj != NULL);
	ASSERT(pgp->obj->pool != NULL);

	ASSERT(pgp->tmem_page != NULL);
	tmem_page_size = PAGE_SIZE;
	//Not really sure whether the below assert is required or not
	ASSERT(!(tmem_page_size & (sizeof(uint64_t)-1)));

        /*
         * Even though there can be a race/concurrent access of pcds by
         * pcd_associate() and ktb_remotify_puts() i.e while ktb_remotify_puts()
         * aquires the list lock tries to remotify pcd, but while doing the
         * network operation unlocks the list and in this gap pcd_associate()
         * aquires the list lock and moves it to local_only_list.  This is not a
         * problem as the tmem_remotified_pcd_status_update() and
         * pcd_associate() are protected by the pcd_tree_rwlocks[firstbyte] lock
         * only one, ktb_remotify_puts() or pcd_associate(), will take effect on
         * the pcd. Remember: tmem_remotified_pcd_status_update() is invoked
         * from within ktb_remotify_puts() on finding a match at a remote server
         * to take the pcd off pcd_remote_tree_roots[firstbyte]; out of
         * remote_sharing_candidate_list and to put it in remote_shared_list 
         *
         * But its an altogether different story if pcd_associate() moves the
         * pcd to lol, the pcd_disassociate() deletes many pcds including nexpcd
         * thus screwing up my nexpcd pointer taken in ktb_remotify_puts().
         * This is prevented by not moving a pcd to lol list while
         * pcd->currently == REMOTIFYING and updating it to LOCALASSOC. 
         * And in tmem_remotified_pcd_status_update() if you find the pcd is
         * currently LOCALASSOC then, under the list lock, update nexpcd first
         * and move it lol and prevent the remotification from happening
         */
	//Accessing the pcd rb trees
	write_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	root = &(tmem_system.pcd_tree_roots[firstbyte]);
	new = &(root->rb_node);

	tmem_dedups++;

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
		/*
		if(pghash < pcd->pagehash)
		{
			new = &((*new)->rb_left);
		}
		else if(pghash > pcd->pagehash)
		{
			new = &((*new)->rb_right);
		}
		*/
		else
		{
                        if(pcd->currently == DISASSOCIATING)
                        {
	                        if(can_debug(pcd_associate))
                                {
                                pr_info("matched pcd is DISASSOCIATING "
                                        "pcd_associate\n");
                                pr_info(" pcd->currently: %d, pcd->status: %d,"
                                        " pcd->firstbyte: %u"
                                        "pcd_associate ***\n", pcd->currently,
                                        pcd->status, pcd->firstbyte);
                                }

                                goto assocfailed;
                        }

                        BUG_ON(pcd->status == 2);

                        /*if the page has been been moved to a remote machine*/
                        /*
                        if(pcd->system_page == NULL && pcd->remote_ip != NULL)
                        {
			        new = &((*new)->rb_left);
                                continue;
                        }

                        BUG_ON(pcd->system_page == NULL);

		        cmp = tmem_page_cmp(pgp->tmem_page, pcd->system_page);

                        if(cmp != 0)
                        {
			        new = &((*new)->rb_left);
                                continue;
                        }
                        */


			//match! free the no-longer-needed page
			//tmem_free_page(pgp->obj->pool, pgp->tmem_page);
			//deduped_puts++;

			/* 
			 * If the matched pcd is from rscl then move it to lol.
			 * I don't have a reference to a pgp here. This means 
			 * that I have to do remote dedup also based on pcds. 
			 * i.e. the summaries should hold pcds.
			 */
                        /*
                         * NOTE: this can already be also in local_only_list
                         * as it could have been subjected to a remote_associate
                         */
                        //spin_lock(&(tmem_system.system_list_lock));
                        write_lock(&(tmem_system.system_list_rwlock));
                        /*
                        if(pcd->currently == ASSOCIATING) || 
                        (pcd->currently == REMOTIFYING)
                        */
                        if(pcd->currently == NORMAL)
                        {
                                if(!list_empty(&pcd->system_rscl_pcds))
                                {
                                        list_del_init(&pcd->system_rscl_pcds); 
                                        list_add_tail(&pcd->system_lol_pcds,\
                                        &(tmem_system.local_only_list));
                                }
                        } 
                        else
                        {
	                        if(can_debug(pcd_associate))
                                {
                                pr_info(" *** mtp | making pcd->currently ="
                                        " ASSOCIATING| pcd_associate ***\n");

                                pr_info(" pcd->currently: %d, pcd->status: %d,"
                                        " pcd->firstbyte: %u"
                                        "pcd_associate ***\n", pcd->currently,
                                        pcd->status, pcd->firstbyte);
                                }

                                pcd->currently = ASSOCIATING;
                        }

                        write_unlock(&(tmem_system.system_list_rwlock));
                        //spin_unlock(&(tmem_system.system_list_lock));
			if(can_show(pcd_associate))
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
			succ_tmem_dedups++;

                        tmem_free_page(pgp->tmem_page);
			goto match;
		}
	}

assocfailed:

	ret = 1;
	failed_tmem_dedups++;

	if(can_show(pcd_associate))
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
	INIT_LIST_HEAD(&pcd->system_rscl_pcds);
	INIT_LIST_HEAD(&pcd->system_lol_pcds);
	INIT_LIST_HEAD(&pcd->system_rs_pcds);
	//Point pcd->system_page to client page contents now available in
	//pgp->tmem_page
	pcd->status = 0;
        pcd->currently = NORMAL;
	/*line below is a just for testing correctness*/
	pcd->pgp = pgp;
	pcd->system_page = pgp->tmem_page;
	pcd->size = PAGE_SIZE;
	pcd->pgp_ref_count = 0;
	pcd->remote_ip = NULL;
	pcd->remote_id = 0;
	pcd->firstbyte = firstbyte;
	//pcd->pagehash = pghash;

	rb_link_node(&pcd->pcd_rb_tree_node, parent, new);
	rb_insert_color(&pcd->pcd_rb_tree_node, root);
	/*
         * increment unique pages count and insert this newly created pcd"
         * into list of unique pcds, ones that are potential candidates for"
         * remote sharing.
	 */
        system_unique_pages++;

	write_lock(&(tmem_system.system_list_rwlock));

	list_add_tail(&(pcd->system_rscl_pcds),\
	&(tmem_system.remote_sharing_candidate_list));

	write_unlock(&(tmem_system.system_list_rwlock));

	update_bflt(pcd);
match:
	pcd->pgp_ref_count++;
	//list_add(&pgp->pcd_siblings,&pcd->pgp_list);
	pgp->firstbyte = firstbyte;
	//pgp->eviction_attempted = 0;
	pgp->pcd = pcd;
unlock:
	write_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
	return ret;
}

/* ensure pgp no longer points to pcd, nor vice-versa */
/* take pcd rwlock unless have_pcd_rwlock is set, always unlock when done */
//static void pcd_disassociate(struct tmem_page_descriptor *pgp,
//struct tmem_pool *pool, int have_pcd_rwlock)
static void pcd_disassociate(struct tmem_page_descriptor *pgp,\
		             int have_pcd_rwlock)
{

	struct tmem_page_content_descriptor *pcd = pgp->pcd;
	struct page* system_page = NULL;
	char *ip = NULL; 
	uint16_t firstbyte = pgp->firstbyte;
	//uint32_t pcd_size = pcd->size;
	//uint32_t pgp_size = pgp->size;
	ASSERT(kvm_tmem_dedup_enabled);
	ASSERT(firstbyte != NOT_SHAREABLE);
	ASSERT(firstbyte < 256);

	if(pgp->pcd->system_page != NULL)
		system_page = pgp->pcd->system_page;
	/* if it is a remotified pcd */
	if(pgp->pcd->remote_ip != NULL)
		ip = pgp->pcd->remote_ip;
	//if(have_pcd_rwlock)
	//ASSERT_WRITELOCK(&pcd_tree_rwlocks[firstbyte]);
	//else
	write_lock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));

        if(can_debug(pcd_disassociate))
                pr_info("pcd_tree_rwlocks[%u] LOCKED pcd_disassociate\n",
                        firstbyte);

	pgp->pcd = NULL;
	pgp->firstbyte = NOT_SHAREABLE;
	pgp->size = -1;
	/*
	   If more pgps are referring this pcd then you return from here itself
	   Also then this pcd is certainly in local_only_list and you shouldn't
	   remove it from this list.
	   */
	if (--pcd->pgp_ref_count)
	{
		if(can_show(pcd_disassociate))
			pr_info(" *** mtp | Diassociating page with index: %u "
				"of object: %llu %llu %llu rooted at rb_tree "
				"slot: %u of pool: %u of client: %u, having "
				"firstbyte: %u from it's page content descripto"
				"r | pcd_disassociate *** \n",
				pgp->index, pgp->obj->oid.oid[2],
				pgp->obj->oid.oid[1], pgp->obj->oid.oid[0],
				tmem_oid_hash(&(pgp->obj->oid)),
				pgp->obj->pool->pool_id,
				pgp->obj->pool->associated_client->client_id,
				firstbyte);
		/*
		 * TODO: What if pgp_ref_count becomes 1 and this pcd does not 
		 * belong to pcd_remote_tree_roots? Shouldn't it be moved back 
		 * to rscl list so that you can explore remote sharing op?
		 * if I let it remain in rscl list then I am forgoing an
		 * opportunity to remotify it.
		 */
		write_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
                if(can_debug(pcd_disassociate))
                        pr_info("pcd_tree_rwlocks[%u] UNLOCKED"
                                " pcd_disassociate\n",
                                firstbyte);
		return;
	}

	write_lock(&(tmem_system.system_list_rwlock));

        if(can_debug(pcd_disassociate))
                pr_info("system_list_lock LOCKED pcd_disassociate\n");

	if(can_show(pcd_disassociate))
		pr_info(" *** mtp | Diassociating page with index: %u of object"
			": %llu %llu %llu rooted at rb_tree slot: %u of pool:"
                        " %u of client: %u, having firstbyte: %u from it's page"
			" content descriptor (NO MORE REF TO THIS PAGE),"
                        " firstbyte: %u status: %d, remoteip: %s, remoteid:"
                        " %llu, currently: %d | pcd_disassociate *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], tmem_oid_hash(&(pgp->obj->oid)),
			pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id, firstbyte,
			pcd->firstbyte, pcd->status, 
                        (pcd->remote_ip==NULL)?"NULL":pcd->remote_ip,
                        pcd->remote_id,
                        pcd->currently);
	/*
	 * no more references to this pcd, recycle it and the physical page.
	 * also this pcd can be either in remote_sharing_candidate_list or
	 * local_only_list
	 */

        /*
         * a bad bad hack which will let the pcd remain in the backend without
         * anyone actually accessing it. And causing a pcd in the remote server
         * to be moved to remote_tree without this guy actually acessing it
         * remotely.
         * NOTE: this will eventually be deleted by tmem_pcd_status_update()
         */
        if(pcd->currently != NORMAL)
        {
                if(can_debug(pcd_disassociate))
                {
                        pr_info(" *** mtp | making pcd->currently ="
                                " DISASSOCIATING| pcd_disassociate ***\n");
                        pr_info(" pcd->currently: %d, pcd->status: %d,"
                                " pcd->firstbyte: %u"
                                "pcd_disassociate ***\n", pcd->currently,
                                pcd->status, pcd->firstbyte);
                }
                pcd->currently = DISASSOCIATING;
                goto disassofail;
        }
        /*
        else
                pcd->currently = DISASSOCIATING;
         */

	if(!list_empty(&pcd->system_rscl_pcds))
		list_del_init(&pcd->system_rscl_pcds);
                //list_replace
	else if(!list_empty(&pcd->system_lol_pcds))
		list_del_init(&pcd->system_lol_pcds);
	else if(!list_empty(&pcd->system_rs_pcds))
		list_del_init(&pcd->system_rs_pcds);
	//write_unlock(&(tmem_system.system_list_rwlock));
	/*
	 * if this pcd is being accessed by some remote machine
	 */
	pcd->pgp = NULL;

	if(pcd->status == 2)
        {
                if(can_debug(pcd_disassociate))
                        pr_info(" *** mtp | disassociating a remotified page |"
                                " pcd_disassociate ***\n");
		goto skiprbfree;
        }
        else if(pcd->status == 1)
	{
		write_lock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));

                if(can_debug(pcd_disassociate))
                {
                        pr_info("pcd_remote_tree_rwlocks[%u] LOCKED"
                                " pcd_disassociate\n", firstbyte);
                        pr_info(" *** mtp | disassociating a remote page |"
                                " pcd_disassociate ***\n");
                }

		pcd = 
		radix_tree_delete(&(tmem_system.pcd_remote_tree_roots[firstbyte])
				  ,pcd->remote_id);

		write_unlock(&(tmem_system.pcd_remote_tree_rwlocks[firstbyte]));
                if(can_debug(pcd_disassociate))
                        pr_info("pcd_remote_tree_rwlocks[%u] UNLOCKED"
                                " pcd_disassociate\n", firstbyte);
	}

	pcd->system_page = NULL;
	//remove pcd from rbtree
	rb_erase(&pcd->pcd_rb_tree_node,\
		 &(tmem_system.pcd_tree_roots[firstbyte]));
	//reinit the struct for safety for now
	RB_CLEAR_NODE(&pcd->pcd_rb_tree_node);
        //decrement system unique pages count
        system_unique_pages--;
skiprbfree:
	//now free up the pcd memory
	kmem_cache_free(tmem_page_content_desc_cachep, pcd);
	//free up the system page that pcd held
	if(system_page != NULL)
		tmem_free_page(system_page);

	if(ip != NULL)
		kfree(ip);
	/* 
	 * moving this list unlock here ensures that check_remote_sharing_op()
	 * won't get into trouble by having a race condition with
	 * ktb_destroy_client() (which will eventually call pcd_disassociate)
	 * while accessing the pcds in the system_rscl_pcds list.
	 */
disassofail:

	write_unlock(&(tmem_system.system_list_rwlock));
        if(can_debug(pcd_disassociate))
                pr_info("system_list_lock UNLOCKED pcd_disassociate\n");

	write_unlock(&(tmem_system.pcd_tree_rwlocks[firstbyte]));
        if(can_debug(pcd_disassociate))
                pr_info("pcd_tree_rwlocks[%u] UNLOCKED pcd_disassociate\n",
                        firstbyte);
}
/******************************************************************************/
/*					         END MAIN PCD & DEDUP ROUTINES*/
/******************************************************************************/

/******************************************************************************/
/*							   STRUCT PAGE ROUTINE*/
/******************************************************************************/
//static void tmem_free_page(struct tmem_pool* pool, struct page* tmem_page)
uint64_t tmem_page_hash(struct page *tmem_page)
{
	const uint64_t *p = page_address(tmem_page);
	//uint8_t byte = p[0];
        
        /* I could just do a simple XOR instead of all this*/
	return (hash_long(p[0] ^ p[1] ^ p[2] ^ p[3],
        	BITS_PER_LONG) & PAGE_HASH_MASK);
}

static void tmem_free_page(struct page* page)
{
	ASSERT(page);
        if(page == NULL)
                BUG();
        else	
		__free_page(page);
}

uint8_t tmem_get_first_byte(struct page* tmem_page)
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
	int ret = 0;

	//check if tmem_page is already mapped !!
	//if it is already mapped then we need only map client_page
	//I seriously think this is not needed as the struct page tmem_page was
	//obtained by calling virt_to_page

	//tmem_va = kmap(tmem_page);
	//added later
	tmem_va = page_address(page);

	ASSERT(tmem_va);
	if(tmem_va == NULL)
	{
		ret = -1;
		goto bad_copy;
	}

	//client_va = page_address(client_page);
	client_va = kmap_atomic(client_page);

	ASSERT(client_va);
	if(client_va == NULL)
	{
		ret = -1;
		goto bad_copy;
	}

	if(!memcpy(client_va, tmem_va, PAGE_SIZE))
		ret = -1;


	kunmap_atomic(client_va);
        smp_mb();

bad_copy:
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
		pr_info(" *** mtp | freeing data of pgp of page with index: %u,"
			" of object: %llu %llu %llu in pool: %d, of client: %d,"
			" having firstbyte: %u, status: %d, pcd->firstbyte: %u|"
                        " tmem_pgp_free_data *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id,
			pgp->firstbyte, pgp->pcd->status, pgp->pcd->firstbyte);

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

        /*
	if(can_show(tmem_pgp_free))
		pr_info(" *** mtp | freeing pgp of page with index: %u, "
			"of object: %llu %llu %llu in pool: %d, of client: %d "
			"| tmem_pgp_free *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id);
        */
	tmem_pgp_free_data(pgp);

	//pgp->size = -1;
	pgp->obj = NULL;
	pgp->index = -1;
	kmem_cache_free(tmem_page_descriptors_cachep, pgp);
        if(can_show(tmem_pgp_free))
                pr_info(" *** mtp | kmem_cache_free done | *** \n");
}

void tmem_pgp_delist_free(struct tmem_page_descriptor *pgp)
{
        /*
       spin_lock(&client_list_lock); 

       if(!list_empty(&pgp->client_rscl_pgps))
               list_del_init(&pgp->client_rscl_pgps);
       else if(!list_empty(&pgp->client_lol_pgps))
               list_del_init(&pgp->client_lol_pgps);
       
       spin_unlock(&client_list_lock); 
       */
       tmem_pgp_free(pgp);
}

static void tmem_pgp_destroy(void *v)
{
	struct tmem_page_descriptor *pgp = (struct tmem_page_descriptor *)v;

	ASSERT(pgp);
	pgp->obj->pgp_count--;
	if(can_show(tmem_pgp_destroy))
		pr_info(" *** mtp | destroying pgp of page with index: %u, "
			"of object: %llu %llu %llu in pool: %d, of client: %d "
			"| tmem_pgp_destroy *** \n",
			pgp->index, pgp->obj->oid.oid[2], pgp->obj->oid.oid[1],
			pgp->obj->oid.oid[0], pgp->obj->pool->pool_id,
			pgp->obj->pool->associated_client->client_id);

	tmem_pgp_delist_free(pgp);
        //tmem_pgp_free(pgp);
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
	//INIT_LIST_HEAD(&pgp->client_rscl_pgps);
	//INIT_LIST_HEAD(&pgp->client_lol_pgps);
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
