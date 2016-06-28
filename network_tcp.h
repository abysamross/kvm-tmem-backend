#ifndef _LTCP_H_
#define _LTCP_H_

/*
struct bloom_filter {
	struct kref		kref;
	struct mutex		lock;
	struct list_head	alg_list;
	unsigned int		bitmap_size;
	unsigned long		bitmap[0];
};
*/

struct remote_server
{
        struct socket *lcc_socket;
        /*
         * lcc_socket; the socket using which leader
         * client communicates with remote server.
         */
        //int rs_id;
        char *rs_ip;
        int rs_port;
        //struct sockaddr_in *rs_addr;
        //unsigned long rs_bitmap[0];
        //unsigned long *rs_bitmap;
        int rs_bmap_size;
        struct list_head rs_list;
        struct bloom_filter *rs_bflt;
};

extern int timed_fwd_filter(void *);
extern struct task_struct *fwd_bflt_thread;
extern struct list_head rs_head;
extern rwlock_t rs_rwspinlock;
extern struct socket *cli_conn_socket;
extern void check_remote_sharing_op(void);
extern int network_server_init(void);
extern void network_server_exit(void);
extern int tcp_client_fwd_filter(struct bloom_filter *);
extern int tcp_client_init(void);
extern void tcp_client_exit(void);
extern int tcp_client_connect_rs(struct remote_server *);
extern int tcp_client_snd_page(struct remote_server *, struct page *);
/*
extern int tcp_client_passon(char *);
extern struct bloom_filter *bflt;
extern int bit_size;
*/
#endif
