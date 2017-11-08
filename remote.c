/*
make_summary(); || update_bflt(); || send_summary();
lookup_remote_summary_dir(); || bloom_filters || update_remote_summary_dir();
remote_tmem_lookup() //should be in tmem.c ideally
*/
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/list.h>
#include <linux/tmem.h>
#include "ktb.h" 
#include "bloom_filter.h"

extern int debug_update_bflt;
extern int show_msg_update_bflt;

void update_bflt(struct tmem_page_content_descriptor* pcd)
{
        struct tmem_page_content_descriptor *tmp_pcd;
        uint8_t byte;
        bool bloom_res;
        unsigned long int count1 = 0;
        unsigned long int count2 = 0;

        //pr_info(" *** mtp | Inside update_bflt | *** \n");

        if(can_show(update_bflt))
        {
                //spin_lock(&(tmem_system.system_list_lock));
                read_lock(&(tmem_system.system_list_rwlock));

                if(!list_empty(&(tmem_system.remote_sharing_candidate_list)))
                {
                        list_for_each_entry(tmp_pcd,\
                        &(tmem_system.remote_sharing_candidate_list),\
                        system_rscl_pcds)
                        {
                                if(can_debug(update_bflt))
                                        pr_info(" *** mtp | In rscl object: "
                                                "%llu %llu %llu, index: %u | "
                                                "update_bflt *** \n", 
                                                tmp_pcd->pgp->obj->oid.oid[2],
                                                tmp_pcd->pgp->obj->oid.oid[1],
                                                tmp_pcd->pgp->obj->oid.oid[0], 
                                                tmp_pcd->pgp->index);
                                count1++;
                        }
                        pr_info(" *** mtp | rscl pcds: %lu | update_bflt "
                                "***\n", count1);
                }
                pr_info("__________________________________________________\n");
                if(!list_empty(&(tmem_system.local_only_list)))
                {
                        list_for_each_entry(tmp_pcd,\
			&(tmem_system.local_only_list),\
			system_lol_pcds)
                        {
                                if(can_debug(update_bflt))
                                        pr_info(" *** mtp | In lol object: "
                                                "%llu %llu %llu, index: %u | "
                                                "update_bflt *** \n", 
                                                tmp_pcd->pgp->obj->oid.oid[2],
                                                tmp_pcd->pgp->obj->oid.oid[1],
                                                tmp_pcd->pgp->obj->oid.oid[0], 
                                                tmp_pcd->pgp->index);
                                count2++;
                        }
                        pr_info(" *** mtp | lol pcds: %lu | update_bflt "
                                "***\n", count2);
                }
                pr_info("__________________________________________________\n");

                read_unlock(&(tmem_system.system_list_rwlock));
                //spin_unlock(&(tmem_system.system_list_lock));
        }

        //pcd = pgp->pcd;

        if(can_show(update_bflt))
                pr_info(" *** mtp | rscl object: "
                        "%llu %llu %llu, index: %u | "
                        "update_bflt *** \n", 
                        pcd->pgp->obj->oid.oid[2],
                        pcd->pgp->obj->oid.oid[1],
                        pcd->pgp->obj->oid.oid[0], 
                        pcd->pgp->index);
        
        /* 
         * now the bloom filter should be under lock, as I don't want the network
         * server trying to transfer it while I am accessing it.
         * The bloom filter implementation already has a mutex that locks it
         * while accessing it for add and other operations.
         */
        if(tmem_system_bloom_filter == NULL)
                return;

        byte = tmem_get_first_byte(pcd->system_page);

        if(bloom_filter_add(tmem_system_bloom_filter, &byte, 1))
                pr_info(" *** mtp | adding rscl object to bloom filter failed "
                        "| update_bflt *** \n");
        
        if(bloom_filter_check(tmem_system_bloom_filter, &byte, 1, &bloom_res))
                pr_info(" *** mtp | checking for rscl object in bloom filter "
                        " failed | update_bflt *** \n"); 

        if(bloom_res == false)
        { 
                if(can_show(update_bflt))
                        pr_info(" *** mtp | the rscl object was not set in"
                                " bloom filter | update_bflt *** \n");
        }

        if(can_show(update_bflt))
                pr_info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
        return; 
}
