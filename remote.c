/*
make_summary(); || update_summary(); || send_summary();
lookup_remote_summary_dir(); || bloom_filters || update_remote_summary_dir();
remote_tmem_lookup() //should be in tmem.c ideally
*/
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/list.h>
#include <linux/tmem.h>
#include "ktb.h" 

extern struct tmem_client *ktb_get_client_by_id(int);

extern int debug_make_summary;
extern int show_msg_make_summary;

void make_summary(int client_id)
{
        struct tmem_client *client = NULL;
        struct tmem_page_descriptor *pgp;

        client = ktb_get_client_by_id(client_id);

        if(client == NULL)
                goto out;

        pr_info(" *** mtp | Inside make_summary | *** \n");

        spin_lock(&client_list_lock);

        if(!list_empty(&client->remote_sharing_candidate_list))
        {
                list_for_each_entry(pgp, &client->remote_sharing_candidate_list,\
                                client_rscl_pgps)
                {
                        if(can_show(make_summary))
                                pr_info(" *** mtp | In rscl object: "
                                        "%llu %llu %llu, index: %u | "
                                        "make_summary *** \n", 
                                        pgp->obj->oid.oid[2],
                                        pgp->obj->oid.oid[1],
                                        pgp->obj->oid.oid[0], 
                                        pgp->index);
                }
        }

        pr_info("__________________________________________________________\n");

        if(!list_empty(&client->local_only_list))
        {
                list_for_each_entry(pgp, &client->local_only_list,\
                                client_lol_pgps)
                {
                        if(can_show(make_summary))
                                pr_info(" *** mtp | In lol object: "
                                        "%llu %llu %llu, index: %u | "
                                        "make_summary *** \n", 
                                        pgp->obj->oid.oid[2],
                                        pgp->obj->oid.oid[1],
                                        pgp->obj->oid.oid[0], 
                                        pgp->index);
                }
        }

        spin_unlock(&client_list_lock);
out:
        pr_info("__________________________________________________________\n");
}
