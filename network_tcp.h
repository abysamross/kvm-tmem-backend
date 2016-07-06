#ifndef _LTCP_H_
#define _LTCP_H_

#define MAX_CONNS 16
/*
struct bloom_filter {
	struct kref		kref;
	struct mutex		lock;
	struct list_head	alg_list;
	unsigned int		bitmap_size;
	unsigned long		bitmap[0];
};
*/
#define debug(f) (debug_##f = 1)
#define can_debug(f) (debug_##f == 1)
#define show_msg(f) (show_msg_##f = 1)
#define can_show(f) (show_msg_##f == 1)

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

struct tcp_conn_handler_data
{
        struct sockaddr_in *address;
        struct socket *accept_socket;
        int thread_id;
        char *ip;
        int port;
        char *in_buf;
};

struct tcp_conn_handler
{
        struct tcp_conn_handler_data *data[MAX_CONNS];
        struct task_struct *thread[MAX_CONNS];
        int tcp_conn_handler_stopped[MAX_CONNS]; 
};

struct tcp_server_service
{
      int running;  
      struct socket *listen_socket;
      struct task_struct *thread;
      struct task_struct *accept_thread;
};

extern struct tcp_server_service *tcp_server;
extern struct tcp_conn_handler *tcp_conn_handler;
extern int tcp_acceptor_stopped;
extern int tcp_acceptor_started;
extern int tcp_listener_stopped;
extern int  tcp_listener_started;
extern int timed_fwd_filter_stopped;

extern int timed_fwd_filter(void *);
extern struct mutex timed_ff_mutex;
extern struct task_struct *fwd_bflt_thread;
extern struct list_head rs_head;
//extern rwlock_t rs_rwspinlock;
extern struct rw_semaphore rs_rwmutex;
extern struct socket *cli_conn_socket;
extern int  check_remote_sharing_op(void);
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
