#include <linux/kernel.h>
/*
#include <linux/module.h>
#include <linux/init.h>
*/
#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/unistd.h>
#include <linux/wait.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

#include "bloom_filter.h"
#include "network_tcp.h"

/*
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");
*/

#define DEFAULT_PORT 2325
#define MODULE_NAME "tmem_tcp_server"

//DEFINE_RWLOCK(rs_rwspinlock);
DEFINE_MUTEX(timed_ff_mutex);
DECLARE_RWSEM(rs_rwmutex);
LIST_HEAD(rs_head);

int debug_tcp_server_send = 0;
int debug_tcp_server_receive = 0;
int debug_compare_page = 0;
int debug_rcv_and_cmp_page = 0;
int debug_register_rs = 0;
int debug_deregister_rs = 0;
int debug_look_up_rs = 0;
int debug_drop_connection = 0;
int debug_create_and_register_rs = 0;
int debug_receive_bflt = 0;
int debug_connection_handler = 0;
int debug_tcp_server_accept = 0;
int debug_tcp_server_listen = 0;
int debug_tcp_server_start = 0;
int debug_get_remote_page = 0;
/*
int debug_tcp_client_send = 0;
int debug_tcp_client_receive = 0;
int debug_tcp_client_snd_page = 0;
int debug_tcp_client_fwd_filter = 0;
int debug_tcp_client_connect_rs = 0;
int debug_tcp_client_connect = 0;
*/
int show_msg_tcp_server_send = 0;
int show_msg_tcp_server_receive = 0;
int show_msg_compare_page = 0;
int show_msg_rcv_and_cmp_page = 0;
int show_msg_register_rs = 0;
int show_msg_deregister_rs = 0;
int show_msg_look_up_rs = 0;
int show_msg_drop_connection = 0;
int show_msg_create_and_register_rs = 0;
int show_msg_receive_bflt = 0;
int show_msg_connection_handler = 0;
int show_msg_tcp_server_accept = 0;
int show_msg_tcp_server_listen = 0;
int show_msg_tcp_server_start = 0;
int show_msg_get_remote_page = 0;
/*
int show_msg_tcp_client_send = 0;
int show_msg_tcp_client_receive = 0;
int show_msg_tcp_client_snd_page = 0;
int show_msg_tcp_client_fwd_filter = 0;
int show_msg_tcp_client_connect_rs = 0;
int show_msg_tcp_client_connect = 0;
*/
//int bit_size = 268435456;
//int delay = 120;
int tcp_listener_stopped = 0;
int tcp_listener_started = 0;
int tcp_acceptor_stopped = 0;
int tcp_acceptor_started = 0;
int timed_fwd_filter_stopped = 0;

/*
extern void *test_page_vaddr;
extern struct page *test_page;
extern int tmem_remote_dedups;
extern int succ_tmem_remote_dedups;
extern int failed_tmem_remote_dedups;
*/
extern int pcd_remote_associate(struct page *, uint64_t *);
extern int ktb_remote_get(struct page *, uint8_t, uint64_t);
extern int ktb_remotify_puts(void);
//struct task_struct *fwd_bflt_thread = NULL;
/*
struct bloom_filter *bflt = NULL;
struct socket *client_conn_socket = NULL;
DEFINE_SPINLOCK(tcp_server_lock);
*/

/*
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
*/
struct tcp_conn_handler *tcp_conn_handler;

struct tcp_server_service *tcp_server;

char *inet_ntoa(struct in_addr *in)
{
        char *str_ip = NULL;
        u_int32_t int_ip = 0;
        
        str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

        if(!str_ip)
                return NULL;
        else
                memset(str_ip, 0, 16);

        int_ip = in->s_addr;

        sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
                (int_ip >> 16) & 0xFF, (int_ip >> 24) & 0xFF);
        
        return str_ip;
}

int tcp_server_send(struct socket *sock, const char *buf, const size_t length,\
                    unsigned long flags)
{
        struct msghdr msg;
        struct kvec vec;
        int len, written = 0, left =length;
        mm_segment_t oldmm;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = flags;
        msg.msg_flags   = 0;

        oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
        vec.iov_len = left;
        vec.iov_base = (char *)buf + written;

        len = kernel_sendmsg(sock, &msg, &vec, left, left);
        
        if((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT)&&(len == -EAGAIN)))
                goto repeat_send;

        if(len > 0)
        {
                written += len;
                left -= len;
                if(left)
                        goto repeat_send;
        }
        
        set_fs(oldmm);
        return written?written:len;
}

//int tcp_server_receive(struct socket *sock, int id,struct sockaddr_in *address,
//                unsigned char *buf,int size, unsigned long flags)
int tcp_server_receive(struct socket *sock, void *rcv_buf, int size,\
                       unsigned long flags, int huge)
{
        int len = 0, totread = 0, left = size, count = size;
        struct msghdr msg;
        struct kvec vec;
        char *buf = NULL;
        
        if(sock==NULL)
                return -1;

        buf = (char *)rcv_buf;

        msg.msg_name = 0;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = flags;

read_again:

        vec.iov_len = left;
        vec.iov_base = (char *)(buf + totread);
        /*
        if(!skb_queue_empty(&sock->sk->sk_receive_queue))
                pr_info("recv queue empty ? %s \n",
                        skb_queue_empty(&sock->sk->sk_receive_queue)?"yes":"no");
        */
        len = kernel_recvmsg(sock, &msg, &vec, size, size, flags);

        if(len == -EAGAIN || len == -ERESTARTSYS)
	{
		if(can_debug(tcp_server_receive))
                        pr_info(" *** mtp | error while reading: %d | "
                                "tcp_server_receive *** \n", len);
                goto read_again;
	}
        
        if(huge)
        {
                /* 
                 * you should timeout somehow if you cannot get the entire bloom
                 * filter rather than simply looping around.
                 */
                /*
                 * count and comparison of buf with "FAIL"|"ADIOS" are ugly ways
                 * of ensuring that a huge receive, a blft(32MB) or page(4KB),
                 * doesn't loop forever.
                 * comparison with "FAIL" is to safeguard against the other end
                 * not being able to send entire size.
                 * comparison with "ADIOS" is to safeguard against the other end
                 * quitting in between; this most probably won't happen as the
                 * other end will take care not to quit until and unless it
                 * tries to send the size bytes.
                 * count is to safeguard against an ungraceful exit of the other
                 * end.
                 */
                if(count < 0)
                        goto recv_out;

                count--;

                if(len > 0)
                {
                        //pr_info("len: %d\n", len);
                        if((len == 4) && (memcmp(buf+totread, "FAIL", 4) == 0))
                                goto recv_out;
                        totread += len;
                        //pr_info("total read: %d\n", totread);
                        left -= len;
                        //pr_info("left: %d\n", left);
                        if(left)
                                goto read_again;
                }
        }
        //len = msg.msg_iter.kvec->iov_len;
recv_out:

        if(can_show(tcp_server_receive))
        {
                pr_info(" *** mtp | return from receive after reading total: "
                        "%d bytes, last read: %d bytes | tcp_server_receive \n", 
                        totread, len);
        }

        return totread?totread:len;
}

/*
int dummy_compare_page(struct page *new_page, void *new_page_vaddr)
{
        void *vaddr;
        int ret1 = 0;
        int ret2 = 0;

        vaddr = page_address(new_page);
        
        ret1 = memcmp(vaddr, test_page_vaddr, PAGE_SIZE);

        if(can_show(compare_page))
                pr_info(" *** mtp | page test 1 result: %d | "
                        "compare_page ***\n", ret1);

        ret2 = memcmp(new_page_vaddr, test_page_vaddr, PAGE_SIZE);

        if(can_show(compare_page))
                pr_info(" *** mtp | page test 2 result: %d | "
                        "compare_page ***\n", ret2);


        if(can_show(compare_page))
        {
                if((ret1 == 0) && (ret2 == 0))
                {
                        pr_info(" *** mtp | page tests passed | "
                                "compare_page ***\n");
                        return 0;
                }
        }
}
*/

void get_remote_page(struct tcp_conn_handler_data *conn)
{
	uint8_t firstbyte;
        int ret = 0, len = 49, i = 0;
        //char in_msg[len+1];
        char out_msg[len+1];
        //void *vaddr;
        //void *new_page_vaddr;
	char *tmp;
        //struct socket *conn_socket; 
        struct page *new_page = NULL;
	uint64_t id;

        new_page = alloc_page(GFP_ATOMIC);
	/*
        new_page_vaddr = page_address(new_page);
        memset(new_page_vaddr, 0, PAGE_SIZE);
	*/
        if(new_page == NULL)
	{
		memset(out_msg, 0, len+1);                                        
		strcat(out_msg, "FAIL");
		ret = -1;
                goto rget_fail;
	}

	for(i = 0; i < 4; i++)
	{
		tmp = strsep(&(conn->in_buf), ":");
		if(i == 2)
			kstrtou8(tmp, 10, &firstbyte);
		/*
		if(i == 3)
			kstrtou64(tmp, 10, &cd);
		*/
	}

	kstrtou64(tmp, 10, &id);

        if(can_show(get_remote_page))
		pr_info(" *** mtp | client looking for RGET:PAGE"
			" with firstbyte: %u, id: %llu | get_remote_page"
			" ***\n", firstbyte, id);                           

	/* look up pcd_remote_tree_roots[firstbyte] */
	ret = ktb_remote_get(new_page, firstbyte, id);

        if(can_show(get_remote_page))
		pr_info(" *** mtp | client sending response for RGET:PAGE"
			" with firstbyte: %u, id: %llu | get_remote_page"
			" ***\n", firstbyte, id);                           

	if(ret < 0)
	{
		memset(out_msg, 0, len+1);                                        
		strcat(out_msg, "FAIL");

		if(can_show(get_remote_page))
			pr_info(" *** mtp | RGET:PAGE with firstbyte: %u,"
				" id: %llu PAGE NOT FOUND | get_remote_page ***\n",
				firstbyte, id);                           

		goto rget_fail_re;
	}
	else if(ret == 0)
	{
		ret = 
		kernel_sendpage(conn->accept_socket, new_page, 0,\
				PAGE_SIZE, MSG_DONTWAIT);
	}

        if(ret != PAGE_SIZE)
        {
		msleep(5000);
		memset(out_msg, 0, len+1);        
		strcat(out_msg, "FAIL");
		goto rget_fail;
	}
	else if(ret == PAGE_SIZE)
	{
		if(can_show(get_remote_page))
			pr_info(" *** mtp | RGET:PAGE with firstbyte: %u,"
				" id: %llu SUCCEEDED | get_remote_page ***\n",
				firstbyte, id);                           
	}

	return;

rget_fail:

	if(can_show(get_remote_page))
		pr_info(" *** mtp | RGET:PAGE with firstbyte: %u,"
			" id: %llu FAILED | get_remote_page ***\n",
			firstbyte, id);                           
rget_fail_re:

	ret = 
	tcp_server_send(conn->accept_socket, out_msg, strlen(out_msg), MSG_DONTWAIT);

	return;
}

int compare_page(struct page *new_page, uint64_t *id)
{
        if(pcd_remote_associate(new_page, id) < 0)
        {
                if(can_show(compare_page))
                        pr_info(" *** mtp | page test FAILED |"
                                " compare_page ***\n");
                return -1;
        }
        else
        {
                if(can_show(compare_page))
                        pr_info(" *** mtp | page test SUCCEEDED."
				" ID = %llu | compare_page ***\n",
				*id);
                return 0;
        }

}

int rcv_and_cmp_page(struct tcp_conn_handler_data *conn, uint64_t *id)
{
	int ret, len = 49;
	//int i;
	char out_buf[len+1];
	//char *ip, *tmp;
	void *new_page_vaddr;
	struct page *new_page = NULL;

	new_page = alloc_page(GFP_ATOMIC);

	if(new_page == NULL)
		goto recv_page_fail;

	new_page_vaddr = page_address(new_page);
	memset(new_page_vaddr, 0, PAGE_SIZE);

	/* 
	 * the lines above can be replaced by the following single line 
	 * new_page_vaddr = get_zeroed_page(GFP_ATOMIC);
	 */

	/*
	   ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

	   for(i = 0; i < 3; i++)
	   tmp = strsep(&(conn->in_buf), ":");

	   strcpy(ip, tmp);
	*/

	/*
	   tmp = strsep(&(conn->in_buf), ":");
	   kstrtoint(tmp, 10, &port);

	   tmp = strsep(&(conn->in_buf), ":");
	   kstrtoint(tmp, 10, &bmap_byte_size);

	   bitmap = vmalloc(bmap_byte_size);
	   memset(bitmap, 0, bmap_byte_size);
	*/

	memset(out_buf, 0, len+1);
	strcat(out_buf, "SEND:PAGE");

	if(can_debug(rcv_and_cmp_page))
		pr_info(" *** mtp | server[%d] sending response: %s for page"
			" of rs: %s | rcv_and_cmp_page ***\n",
			conn->thread_id, out_buf, conn->ip);

	ret =
	tcp_server_send(conn->accept_socket,(void *)out_buf,strlen(out_buf),\
			MSG_DONTWAIT);
	/* 
	 * chose not to have a wait queue here, as page receive is a huge
	 * receive and tcp_server_receive won't return until it gets/issues 4096
	 * kernel_recvmsg calls or it receives an explicit FAIL.
	 */
	ret = 
	tcp_server_receive(conn->accept_socket, new_page_vaddr, PAGE_SIZE,\
			   MSG_DONTWAIT, 1);

	if(can_debug(rcv_and_cmp_page))
		pr_info(" *** mtp | server[%d] received page (size: %d) of"
			" rs: [%s] | rcv_and_cmp_page ***\n",
			conn->thread_id, ret, conn->ip);

	if(ret != PAGE_SIZE)
		goto recv_page_fail;

	//if(compare_page(new_page, new_page_vaddr) < 0)
	if(compare_page(new_page, id) < 0)
		goto recv_page_fail;

	return 0;

recv_page_fail:

	return -1;
}
//struct remote_server *register_rs(struct socket *socket, char* pkt,
//                int id, struct sockaddr_in *address)
struct remote_server *register_rs(struct socket *socket, char* ip, int port)
{
        struct remote_server *rs = NULL;
        
        rs = kmalloc(sizeof(struct remote_server), GFP_KERNEL);

        if(!rs)
                return NULL;
        memset(rs, 0, sizeof(struct remote_server));
        rs->lcc_socket = socket; 
        rs->rs_ip = ip;
        rs->rs_port = port;
        //rs->rs_bitmap = NULL;
        rs->rs_bmap_size = 0;
        rs->rs_bflt = NULL;
        
        if(can_show(register_rs))
                pr_info(" *** mtp | registered remote server with ip: %s:%d | "
                        "register_rs ***\n", rs->rs_ip, rs->rs_port);

        down_write(&rs_rwmutex);
        //write_lock(&rs_rwspinlock);
        list_add_tail(&(rs->rs_list), &(rs_head));
        //write_unlock(&rs_rwspinlock);
        up_write(&rs_rwmutex);

        return rs;
}

/*
int unused_old_update_bflt(struct remote_server *rs)
{
        struct remote_server *rs_tmp;

        down_read(&rs_rwmutex);
        if(!(list_empty(&rs_head)))
        {
                list_for_each_entry(rs_tmp, &(rs_head), rs_list)
                {
                        up_read(&rs_rwmutex);
                        pr_info("remote server info:\nip-> %s | port-> %d\n", 
                                rs_tmp->rs_ip, rs_tmp->rs_port);
        
                        if(strcmp(rs_tmp->rs_ip, rs->rs_ip) == 0)
                        {
                                //rs_tmp->rs_bitmap = bmap;
                        }
                        //kfree(ip);
                }
        }
        else
        {
              up_read(&rs_rwmutex);
              return -1;
              
        }

        return 0;
}
*/

/*
 * NOTE:
 * deregister_rs and snd_page are not called in response to a message from a
 * remote server.
 */
void deregister_rs(void)
{
        struct remote_server *rs = NULL;
        struct list_head *pos = NULL;
        struct list_head *pos_next = NULL;

        down_write(&rs_rwmutex);
        //write_lock(&rs_rwspinlock);
        if(!(list_empty(&rs_head)))
        {
                //list_for_each_entry(rs_tmp, &(rs_head), rs_list)
                list_for_each_safe(pos, pos_next, &(rs_head))
                {
                        rs = list_entry(pos, struct remote_server, rs_list);

                        if(can_debug(deregister_rs))
                                pr_info(" *** mtp | found remote server "
                                        "info:\n | ip-> %s | port-> %d "
                                        "| deregister_rs ***\n", 
                                        rs->rs_ip, rs->rs_port);

                        list_del_init(&(rs->rs_list));
                        sock_release(rs->lcc_socket);
                        if(rs->rs_ip != NULL)
                                kfree(rs->rs_ip);
                        if(rs->rs_bflt)
                                vfree(rs->rs_bflt);
                        kfree(rs);
                }
        }
        //write_unlock(&rs_rwspinlock);
        up_write(&rs_rwmutex);

}

struct remote_server* look_up_rs(char *ip, int port)
{
        struct remote_server *rs_tmp;

        down_read(&rs_rwmutex);
        //read_lock(&rs_rwspinlock);
        if(!(list_empty(&rs_head)))
        {
                list_for_each_entry(rs_tmp, &(rs_head), rs_list)
                {
                        //up_read(&rs_rwmutex);
                        //read_unlock(&rs_rwspinlock);
                        if(strcmp(rs_tmp->rs_ip, ip) == 0)
                        {
                                if(can_debug(look_up_rs))
                                        pr_info(" *** mtp | found remote server"
                                                " info:\n | ip-> %s | port-> %d"
                                                " | look_up_rs ***\n", 
                                                rs_tmp->rs_ip, rs_tmp->rs_port);

                                up_read(&rs_rwmutex);
                                return rs_tmp;
                        }
                        //read_lock(&rs_rwspinlock);
                        //down_read(&rs_rwmutex);
                }
        }
        //else
        //read_unlock(&rs_rwspinlock);
        up_read(&rs_rwmutex);

        return NULL;
}

void drop_connection(struct tcp_conn_handler_data *conn)
{
      struct remote_server *rs;
      char *ip, *tmp;
      int port;
      int i = 0;

      ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
      for(i = 0; i < 2; i++)
              tmp = strsep(&(conn->in_buf), ":");
      strcpy(ip, tmp);

      tmp = strsep(&(conn->in_buf), ":");
      kstrtoint(tmp, 10, &port);

      rs = look_up_rs(ip, port);

      down_write(&rs_rwmutex);
      if(rs != NULL)
      {
              //write_lock(&rs_rwspinlock);
              list_del_init(&(rs->rs_list));
              //write_unlock(&rs_rwspinlock);
              //up_write(&rs_rwmutex);
              sock_release(rs->lcc_socket);
              if(rs->rs_ip != NULL)
                      kfree(rs->rs_ip);
              //vfree(rs->rs_bitmap);
              if(rs->rs_bflt != NULL)
                      vfree(rs->rs_bflt);
              kfree(rs);
      }
      up_write(&rs_rwmutex);
      kfree(ip);
}

struct remote_server *create_and_register_rs(char *ip, int port)
{
        int err;
        struct remote_server *rs;
        struct socket *rs_socket;

        err =  sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &rs_socket);

        if(err < 0 || rs_socket == NULL)
        {
                if(can_debug(create_and_register_rs))
                        pr_info("*** mtp | error: %d creating "
                                "remote server connection socket for rs: %s |"
                                "create_and_register_rs ***\n", err, ip);
                goto fail;
        }

        rs = register_rs(rs_socket, ip, port);

        if(rs == NULL)
        {
                if(can_debug(create_and_register_rs))
                        pr_info(" *** mtp | error: registering rs: %s with"
                                " this server | create_and_register_rs ****\n",
                                ip);

                goto fail;
        }

        err = tcp_client_connect_rs(rs);

        if(err < 0)
        {
                if(can_debug(create_and_register_rs))
                        pr_info(" *** mtp | error: %d connecting"
                                " this server to rs:%s |"
                                " create_and_register_rs ***\n", err, ip);

              down_write(&rs_rwmutex);
              //write_lock(&rs_rwspinlock);
              list_del_init(&(rs->rs_list));
              //write_unlock(&rs_rwspinlock);
              kfree(rs->rs_ip);
              kfree(rs);
              up_write(&rs_rwmutex);
              goto fail;
        }

        return rs;
fail:
        return NULL;
}


//int receive_bflt(struct socket *accept_socket, char *in_buf, int bmap_size)
int receive_bflt(struct tcp_conn_handler_data *conn)
{
      struct remote_server *rs;
      struct bloom_filter *bflt;
      char *ip, *tmp;
      int port, len = 49;
      char out_buf[len+1];
      //unsigned long *bitmap = NULL;
      int bmap_byte_size;
      int bmap_bits_size;
      int i;
      int ret;
      //int bmap_bytes_size = 0;

      ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

      for(i = 0; i < 3; i++)
              tmp = strsep(&(conn->in_buf), ":");

      strcpy(ip, tmp);

      tmp = strsep(&(conn->in_buf), ":");
      kstrtoint(tmp, 10, &port);

      tmp = strsep(&(conn->in_buf), ":");
      kstrtoint(tmp, 10, &bmap_bits_size);

      bmap_byte_size = BITS_TO_LONGS(bmap_bits_size)*sizeof(unsigned long);

      /*
      bitmap = vmalloc(bmap_byte_size);
      memset(bitmap, 0, bmap_byte_size);
      */

      bflt = bloom_filter_new(bmap_bits_size);

      /*
      if(!bitmap)
      {
              pr_info("server[%d] failed to allocate memory for bflt of "
                      "rs: %s | receive_bflt ***\n", conn->thread_id, ip);
              kfree(ip);
              goto rcvfail; 
      }
      */

      if(IS_ERR(bflt))
      {
              if(can_debug(receive_bflt))
                      pr_info("server[%d] failed to allocate memory for bflt "
                              "of rs: %s | receive_bflt ***\n", 
                              conn->thread_id, ip);
              goto bflt_alloc_fail; 
      }

      if(bloom_filter_add_hash_alg(bflt,"crc32c"))
      {
              pr_info(" *** mtp | Adding crc32c algo to bloom filter"
                      "failed | ktb_main_init *** \n");
              goto bflt_alg_fail;
      }

      if(bloom_filter_add_hash_alg(bflt,"sha1"))
      {
              pr_info(" *** mtp | Adding sha1 algo to bloom filter"
                      " failed | ktb_main_init *** \n");
              goto bflt_alg_fail;
      }
      
      memset(out_buf, 0, len+1);
      strcat(out_buf, "SEND:BFLT");
       
      if(can_show(receive_bflt))
              pr_info(" *** mtp | server[%d] sending response: %s for bflt of "
                      "rs: %s | receive_bflt ***\n", 
                      conn->thread_id, out_buf, ip);
        
      ret =
      tcp_server_send(conn->accept_socket,(void *)out_buf,strlen(out_buf),\
                      MSG_DONTWAIT);

      //receive actual bflt bitmap
      ret = 
      tcp_server_receive(conn->accept_socket, (void *)bflt->bitmap,\
                         bmap_byte_size, MSG_DONTWAIT, 1);

      if(can_show(receive_bflt))
              pr_info(" *** mtp | server[%d] received bitmap (size: %d) of "
                      "rs: [%s] | receive_bflt ***\n",
                      conn->thread_id, ret, ip);

      if(ret != bmap_byte_size)
              goto bflt_rcv_fail;

      rs = look_up_rs(ip, port);
              
      if(rs == NULL)
      {
              rs = create_and_register_rs(ip, port);

              if(rs == NULL)
              {
                      if(can_debug(receive_bflt))
                              pr_info(" *** mtp | server[%d]"
                                      " create_and_register_rs for"
                                      " rs: %s failed | receive_bflt ***\n",
                                      conn->thread_id, ip);

                      goto bflt_rcv_fail;
              }
      }
      else
              kfree(ip);

      /*free the bitmap for an existing server*/
      down_write(&rs_rwmutex);
      if(rs->rs_bflt != NULL)
              vfree(rs->rs_bflt);

      rs->rs_bflt = bflt;
      up_write(&rs_rwmutex);

      /*
      if(can_show(receive_bflt))
              pr_info(" *** mtp | server[%d] testing received bitmap of"
                      " rs: [%s]\n bitmap[0]: %d, bitmap[10]: %d |\n"
                      " receive_bflt ***\n", conn->thread_id, ip, 
                      test_bit(0, rs->rs_bflt->bitmap), 
                      test_bit(0, rs->rs_bflt->bitmap));

      //bmap_bits_size = bmap_byte_size << 3;
      for(i = 0; i < bmap_bits_size; i++)
              if(test_bit(i, rs->rs_bflt->bitmap))
                      pr_info("%d bit is set\n", i);
       */

      return 0;

bflt_rcv_fail:
bflt_alg_fail:

      vfree(bflt);

bflt_alloc_fail:

      kfree(ip);

      return -1;
}

int connection_handler(void *data)
{
	int ret;
	int len = 49;
	char in_buf[len+1];
	char out_buf[len+1];

	struct tcp_conn_handler_data *conn_data = 
	(struct tcp_conn_handler_data *)data;

	//struct sockaddr_in *address = conn_data->address;
	struct socket *accept_socket = conn_data->accept_socket;
	char *ip = conn_data->ip;
	int port = conn_data->port;
	int id = conn_data->thread_id;
	DECLARE_WAITQUEUE(recv_wait, current);

	conn_data->in_buf = in_buf;
	allow_signal(SIGKILL|SIGSTOP);

	while(1)
	{
		add_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);  

		while(skb_queue_empty(&accept_socket->sk->sk_receive_queue))
		{
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);

			if(kthread_should_stop())
			{
				if(can_show(connection_handler))
					pr_info(" *** mtp | tcp server handle"
						" connection thread stopping"
						" | connection_handler *** \n");

				//tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;

				__set_current_state(TASK_RUNNING);
				remove_wait_queue(&accept_socket->sk->sk_wq->wait,\
						&recv_wait);
				tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;
				kfree(tcp_conn_handler->data[id]->address);
				kfree(tcp_conn_handler->data[id]->ip);
				kfree(tcp_conn_handler->data[id]);
				//kfree(tmp);
				sock_release(tcp_conn_handler->data[id]->\
					     accept_socket);
				return 0;
			}

			if(signal_pending(current))
			{
				__set_current_state(TASK_RUNNING);
				remove_wait_queue(&accept_socket->sk->sk_wq->wait,\
						  &recv_wait);
				goto out;
			}
		}
		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);

		if(can_show(connection_handler))
			pr_info(" *** mtp | server[%d] receiving message | "
				"connection_handler ***\n", id);

		memset(in_buf, 0, len+1);
		//ret = tcp_server_receive(accept_socket, id, address, in_buf, len,
		//                         MSG_DONTWAIT);
		ret = tcp_server_receive(accept_socket, (void *)in_buf, len,\
					 MSG_DONTWAIT, 0);

		if(can_show(connection_handler))
			pr_info(" *** mtp | server[%d] received: %d bytes from"
				" %s:%d, says: %s | connection_handler ***\n",
				id, ret, ip, port, in_buf);

		if(ret > 0)
		{
			if(memcmp(in_buf, "RECV", 4) == 0)
			{
				if(memcmp(in_buf+5, "BFLT", 4) == 0)
				{

					conn_data->in_buf = in_buf;
					if(receive_bflt(conn_data) < 0)
						goto bfltfail;

					//unused_old_update_bflt(rs);

					memset(out_buf, 0, len+1);
					strcat(out_buf, "DONE:BFLT");
					goto bfltresp;
bfltfail:
					memset(out_buf, 0, len+1);
					strcat(out_buf, "FAIL:BFLT");
bfltresp:
					if(can_show(connection_handler))
						pr_info(" *** mtp | sending"
							" response: %s |"
							" connection_handler"
							" ***\n",
							out_buf);

					tcp_server_send(accept_socket, out_buf,\
							strlen(out_buf),\
							MSG_DONTWAIT);

					if(can_show(connection_handler))
						pr_info(" *** mtp | sending test"
							" page | "
							"connection_handler *** \n");

					if(memcmp(out_buf, "DONE:BFLT", 9) == 0)
					{
						if(ktb_remotify_puts() < 0)
							break;
					}
					/*
					   if(test_page != NULL)
					   snd_page(test_page);
					   */
				}
				else if(memcmp(in_buf+5, "PAGE", 4) == 0)
				{
					/* 
					 * do comparison of this page in 
					 * the tmem bknd. Give response.
					 */
					uint64_t id;
					conn_data->in_buf = in_buf;
					if(rcv_and_cmp_page(conn_data,&id)<0)
						goto pagefail;

					memset(out_buf, 0, len+1);
					//strcat(out_buf, "FNDS:PAGE");
					snprintf(out_buf, sizeof(out_buf),\
						 "FNDS:PAGE:%llu", id);
					goto pageresp;
pagefail:
					memset(out_buf, 0, len+1);
					strcat(out_buf, "FAIL:PAGE");
pageresp: 
					tcp_server_send(accept_socket, out_buf,\
							strlen(out_buf),\
							MSG_DONTWAIT);
				}
			}
			else if(memcmp(in_buf, "RGET", 4) == 0)
			{
				conn_data->in_buf = in_buf;
				get_remote_page(conn_data);
			}
			else if(memcmp(in_buf, "QUIT", 4) == 0)
			{
				conn_data->in_buf = in_buf;
				drop_connection(conn_data);

			}
			/* this is aplicable only to the thread handling connection
			 * to the leader */
			else if(memcmp(in_buf, "ADIOS", 5) == 0)
			{
				int r = 1;

				memset(out_buf, 0, len+1);
				strcat(out_buf, "ADIOSAMIGO");

				if(can_show(connection_handler))
					pr_info(" *** mtp | sending response: %s"
						" | connection_handler ***\n",
						out_buf);

				tcp_server_send(accept_socket, out_buf,\
						strlen(out_buf), MSG_DONTWAIT);
				/* here also the local client connection 
				 * with the leader server should be severed.
				 * Not only that, the entire local server 
				 * module should be brought down as there is
				 * no longer a leader server */
				mutex_lock(&timed_ff_mutex);
				if(fwd_bflt_thread != NULL)
				{
					if(!timed_fwd_filter_stopped)
					{
						r = kthread_stop(fwd_bflt_thread);

						if(!r)
						{
							if(fwd_bflt_thread != NULL)
								put_task_struct(\
								fwd_bflt_thread);

							timed_fwd_filter_stopped=1;

							if(can_show(\
							   connection_handler))
							{
								pr_info(" *** mtp"
									" | timed"
									" forward"
									" filter"
									" thread"
									" stopped |"
									"connection_"
									" handler"
									" *** \n");
							}
						}
					}
				}
				mutex_unlock(&timed_ff_mutex);

				if(cli_conn_socket)
				{
					if(can_show(connection_handler))
						pr_info(" *** mtp | 1. Closing"
							" client connection |"
							" connection_handler"
							" *** \n");
					tcp_client_exit();
				}

				break;
			}
		}
	}
out:
	tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;
	kfree(tcp_conn_handler->data[id]->address);
	kfree(tcp_conn_handler->data[id]->ip);
	kfree(tcp_conn_handler->data[id]);
	//kfree(tmp);
	sock_release(tcp_conn_handler->data[id]->accept_socket);
	//tcp_conn_handler->thread[id] = NULL;
	do_exit(0);
}

int tcp_server_accept(void)
{
        int accept_err = 0;
        struct socket *socket;
        struct socket *accept_socket = NULL;
        struct inet_connection_sock *isock; 
        int id = 0;
        DECLARE_WAITQUEUE(accept_wait, current);

        allow_signal(SIGKILL|SIGSTOP);

        tcp_acceptor_started = 1;
        socket = tcp_server->listen_socket;

        if(can_show(tcp_server_accept))
                pr_info(" *** mtp | creating the accept socket |"
                        " tcp_server_accept *** \n");

        while(1)
        {
                struct tcp_conn_handler_data *data = NULL;
                struct sockaddr_in *client = NULL;
                char *sip;
                int sport;
                int addr_len;

                accept_err =  
                sock_create(socket->sk->sk_family, socket->type,\
                            socket->sk->sk_protocol, &accept_socket);

                if(accept_err < 0 || !accept_socket)
                {
                        if(can_show(tcp_server_accept))
                                pr_info(" *** mtp | accept_error: %d while"
                                        " creating tcp server accept socket | "
                                        " tcp_server_accept *** \n",
                                        accept_err);
                        goto err;
                }

                accept_socket->type = socket->type;
                accept_socket->ops  = socket->ops;

                isock = inet_csk(socket->sk);
                
               add_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
               while(reqsk_queue_empty(&isock->icsk_accept_queue))
               {
                       __set_current_state(TASK_INTERRUPTIBLE);
                       //set_current_state(TASK_INTERRUPTIBLE);

                       //change this HZ to about 5 mins in jiffies
                       schedule_timeout(HZ);


                       if(kthread_should_stop())
                       {
                               if(can_show(tcp_server_accept))
                                       pr_info(" *** mtp | 1.tcp server"
                                               " acceptor thread stopped |"
                                               " tcp_server_accept *** \n");

                               tcp_acceptor_stopped = 1;
                               __set_current_state(TASK_RUNNING);
                               remove_wait_queue(&socket->sk->sk_wq->wait,\
                                                 &accept_wait);
                               sock_release(accept_socket);
                               return 0;
                       }

                       if(signal_pending(current))
                       {
                               __set_current_state(TASK_RUNNING);
                               remove_wait_queue(&socket->sk->sk_wq->wait,\
                                                 &accept_wait);
                               goto release;
                       }

               } 
               __set_current_state(TASK_RUNNING);
               remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);


               if(can_show(tcp_server_accept))
                       pr_info(" *** mtp | accept connection |"
                               " tcp_server_accept ***\n");

               accept_err = 
               socket->ops->accept(socket, accept_socket, O_NONBLOCK);

               if(accept_err < 0)
               {
                       if(can_show(tcp_server_accept))
                               pr_info(" *** mtp | accept_error: %d while"
                                       " accepting tcp server |"
                                       " tcp_server_accept *** \n", accept_err);
                       goto release;
               }

               client = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);   
               memset(client, 0, sizeof(struct sockaddr_in));

               addr_len = sizeof(struct sockaddr_in);

               accept_err = 
               accept_socket->ops->getname(accept_socket,
                                           (struct sockaddr *)client,\
                                           &addr_len, 2);

               if(accept_err < 0)
               {
                       if(can_debug(tcp_server_accept))
                               pr_info(" *** mtp | accept_error: %d in getname"
                                       " tcp server | tcp_server_accept *** \n",
                                       accept_err);
                       goto release;
               }

               sip = inet_ntoa(&(client->sin_addr));
               sport = ntohs(client->sin_port);

               if(can_show(tcp_server_accept))
                       pr_info("connection from: %s %d \n", sip, sport);

               //kfree(tmp);
  
               if(can_show(tcp_server_accept))
                       pr_info("handle connection\n");

               /*should I protect this against concurrent access?*/
               for(id = 0; id < MAX_CONNS; id++)
               {
                        if(tcp_conn_handler->thread[id] == NULL)
                                break;
               }

               if(can_show(tcp_server_accept))
                       pr_info("gave free id: %d\n", id);

               if(id == MAX_CONNS)
                       goto release;

               data = kmalloc(sizeof(struct tcp_conn_handler_data), GFP_KERNEL);
               memset(data, 0, sizeof(struct tcp_conn_handler_data));

               data->address = client;
               data->accept_socket = accept_socket;
               data->thread_id = id;
               data->ip = sip;
               data->port = sport;
               data->in_buf = NULL;

               tcp_conn_handler->tcp_conn_handler_stopped[id] = 0;
               tcp_conn_handler->data[id] = data;
               tcp_conn_handler->thread[id] = 
               kthread_run((void *)connection_handler, (void *)data,MODULE_NAME);
               if(tcp_conn_handler->thread[id])
                       get_task_struct(tcp_conn_handler->thread[id]);

               if(kthread_should_stop())
               {
                       if(can_show(tcp_server_accept))
                               pr_info(" *** mtp | 2. tcp server acceptor"
                                       " thread stopped | tcp_server_accept"
                                       " *** \n");
                       tcp_acceptor_stopped = 1;
                       //sock_release(accept_socket);
                       return 0;
               }
                        
               if(signal_pending(current))
               {
                       break;
               }
        }

        tcp_acceptor_stopped = 1;
        do_exit(0);
release: 
       sock_release(accept_socket);
err:
       tcp_acceptor_stopped = 1;
       do_exit(0);
}

int tcp_server_listen(void)
{
        int server_err;
        struct socket *conn_socket;
        struct sockaddr_in server;

        DECLARE_WAIT_QUEUE_HEAD(wq);

        allow_signal(SIGKILL|SIGTERM);         

        tcp_listener_started = 1;
        server_err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP,\
                                 &tcp_server->listen_socket);
        if(server_err < 0)
        {
                if(can_debug(tcp_server_listen))
                        pr_info(" *** mtp | Error: %d while creating tcp"
                                " server listen socket | tcp_server_listen"
                                " *** \n", server_err);
                goto err;
        }

        conn_socket = tcp_server->listen_socket;
        tcp_server->listen_socket->sk->sk_reuse = 1;

        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_family = AF_INET;
        server.sin_port = htons(DEFAULT_PORT);

        server_err = 
        conn_socket->ops->bind(conn_socket, (struct sockaddr*)&server,\
                               sizeof(server));

        if(server_err < 0) {
                if(can_debug(tcp_server_listen))
                        pr_info(" *** mtp | Error: %d while binding tcp server"
                                " listen socket | tcp_server_listen *** \n",
                                server_err);
                goto release;
        }

        server_err = conn_socket->ops->listen(conn_socket, 16);

        if(server_err < 0)
        {
                if(can_debug(tcp_server_listen))
                        pr_info(" *** mtp | Error: %d while listening in tcp "
                                "server listen socket | tcp_server_listen "
                                "*** \n", server_err);
                goto release;
        }

        tcp_server->accept_thread = 
        kthread_run((void*)tcp_server_accept, NULL, MODULE_NAME);

        while(1)
        {
                wait_event_timeout(wq, 0, 3*HZ);

                if(kthread_should_stop())
                {
                        if(can_show(tcp_server_listen))
                                pr_info(" *** mtp | tcp server listening thread"
                                        " stopped | tcp_server_listen *** \n");
                        tcp_listener_stopped = 1;
                        return 0;
                }

                if(signal_pending(current))
                        goto release;
        }

        sock_release(conn_socket);
        tcp_listener_stopped = 1;
        do_exit(0);
release:
        sock_release(conn_socket);
err:
        tcp_listener_stopped = 1;
        do_exit(0);
}


/*
int start_fwd_filter(struct bloom_filter *bflt)
{
        fwd_bflt_thread = 
        kthread_run((void *)timed_fwd_filter, (void *)bflt, "fwd_bflt");

        if(fwd_bflt_thread == NULL)
                return -1;

        get_task_struct(fwd_bflt_thread);

        return 0;
}
*/

int tcp_server_start(void)
{
        tcp_server->running = 1;
        tcp_server->thread = 
        kthread_run((void *)tcp_server_listen, NULL, MODULE_NAME);

        if(tcp_server->thread == NULL)
                return -1;
        
        if(tcp_listener_stopped)
                return -1;

        return 0;
}

//static int __init network_server_init(void)
int network_server_init(void)
{
        /*
        struct bloom_filter *bflt = NULL;
        unsigned long bitmap_bytes_size; 
        */

        pr_info(" *** mtp | initiating network_server | "
                "network_server_init ***\n");

        /*
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
        */

        tcp_server = kmalloc(sizeof(struct tcp_server_service), GFP_KERNEL);
        memset(tcp_server, 0, sizeof(struct tcp_server_service));

        tcp_conn_handler = kmalloc(sizeof(struct tcp_conn_handler), GFP_KERNEL);
        memset(tcp_conn_handler, 0, sizeof(struct tcp_conn_handler));

        /*
        bitmap_bytes_size = 
        BITS_TO_LONGS(bit_size)*sizeof(unsigned long);
        
        bflt = vmalloc(sizeof(*bflt)+bitmap_bytes_size);
        memset(bflt, 0, sizeof(*bflt)+bitmap_bytes_size);

        if(!bflt)
        {
                pr_info(" *** mtp | failed to allocate memory for bflt | "
                        "network_server_init *** \n");
        }
        else
        {
                bflt->bitmap_size = bit_size;

                // randomly set two bits in the bitmap 
                set_bit(0, bflt->bitmap);
                set_bit(10, bflt->bitmap);
                //set_bit(1024, bflt->bitmap);
                //set_bit(4095, bflt->bitmap);
                //set_bit(1024, bflt->bitmap);
                //set_bit(20160, bflt->bitmap);
        }
        */

        if(tcp_server_start() != 0)
        {
                pr_info(" *** mtp | could not start network server "
                        "network_server_init *** \n");
                return -1;
        }

        if(tcp_listener_stopped)
        {
                pr_info(" *** mtp | could not start network server "
                        "network_server_init *** \n");
                return -1;
        }

        /*
        if(tcp_client_init() != 0) 
        {
                int ret;
                
                if(tcp_acceptor_started && !tcp_acceptor_stopped)
                {
                        ret = kthread_stop(tcp_server->accept_thread);
                        if(!ret)
                                pr_info(" *** mtp | stopping tcp server accept "
                                        "thread as local client could not setup "
                                        "a connection with leader server | "
                                        "network_server_init *** \n");
                }

                if(tcp_listener_started && !tcp_listener_stopped)
                {
                        ret = kthread_stop(tcp_server->thread);
                        if(!ret)
                                pr_info("*** mtp | stopping tcp server listening"
                                        " thread as local client could not setup"
                                        " a connection with leader server |"
                                        " network_server_init *** \n");

                        if(tcp_server->listen_socket != NULL)
                        {
                                sock_release(tcp_server->listen_socket);
                                tcp_server->listen_socket = NULL;
                        }
                }
                

                kfree(tcp_conn_handler);
                kfree(tcp_server);
                //vfree(bflt);
                tcp_server = NULL;
                return -1;
        }
        */

        /*
        if(bflt)
        {
                if(tcp_client_fwd_filter(bflt) < 0)
                {
                        pr_info(" *** mtp | tcp_client_fwd_filter 2 attmepts "
                                "failed | network_server_init ***\n");
                }
        }
        else
                pr_info(" *** mtp | network server unable to call "
                        "tcp_client_fwd_filter (bflt) as bflt not created | "
                        "network_server_init ***\n");
        */

        /*
        show_msg(tcp_server_send);
        show_msg(tcp_server_receive);
        show_msg(register_rs);
        show_msg(deregister_rs); 
        show_msg(look_up_rs); 
        show_msg(drop_connection); 
        show_msg(create_and_register_rs); 
        show_msg(connection_handler); 
        show_msg(tcp_server_accept); 
        show_msg(tcp_server_listen); 
        show_msg(tcp_server_start); 
        show_msg(receive_bflt); 
        */
        show_msg(compare_page);
        /*
        show_msg(rcv_and_cmp_page);
	*/

        debug(compare_page);
	/*
        debug(tcp_server_send);
        debug(tcp_server_receive);
        debug(rcv_and_cmp_page);
        debug(register_rs);
        debug(deregister_rs); 
        debug(look_up_rs); 
        debug(drop_connection); 
        debug(create_and_register_rs); 
        debug(receive_bflt); 
        debug(connection_handler); 
        debug(tcp_server_accept); 
        debug(tcp_server_listen); 
        debug(tcp_server_start); 
        */
        return 0;
}

//static void __exit network_server_exit(void)
void network_server_exit(void)
{
        int ret;
        int id;

        if(tcp_server == NULL)
        {
                pr_info(" *** mtp | No network server running |"
                        " network_server_exit *** \n");

                goto exit_net_server;
        }

        if(tcp_server->thread == NULL)
        {
                pr_info(" *** mtp | No kernel thread to kill | "
                        "network_server_exit *** \n");

                goto exit_net_server;
        }

        for(id = 0; id < MAX_CONNS; id++)
        {
                if(tcp_conn_handler->thread[id] != NULL)
                {
                        if(pid_alive(tcp_conn_handler->thread[id]))
                                pr_info(" *** mtp | connection handler "
                                        "thread id: %d is not stale and "
                                        "safe to kill | "
                                        "network_server_exit *** \n", id);
                        else
                                continue;

                        if(!tcp_conn_handler->tcp_conn_handler_stopped[id])
                        {
                                pr_info(" *** mtp | calling kthread_stop "
                                        "on connection hanlder thread: %d"
                                        " | network_server_exit *** \n", id);
                              ret = 
                              kthread_stop(tcp_conn_handler->thread[id]);

                                if(!ret)
                                        pr_info(" *** mtp | tcp server "
                                                "connection handler "
                                                "thread: %d stopped | "
                                                "network_server_exit "
                                                "*** \n", id);
                                
                                if(tcp_conn_handler->thread[id] != NULL)
                                        put_task_struct(\
                                        tcp_conn_handler->thread[id]);
                        }
               }
        }

        if(tcp_acceptor_started && !tcp_acceptor_stopped)
        {
                ret = kthread_stop(tcp_server->accept_thread);
                if(!ret)
                        pr_info(" *** mtp | tcp server acceptor thread"
                                " stopped | network_server_exit *** \n");
        }

        if(tcp_listener_started && !tcp_listener_stopped)
        {
                ret = kthread_stop(tcp_server->thread);
                if(!ret)
                        pr_info(" *** mtp | tcp server listening thread"
                                " stopped | network_server_exit *** \n");

                if(tcp_server->listen_socket != NULL)
                {
                        sock_release(tcp_server->listen_socket);
                        tcp_server->listen_socket = NULL;
                }

        }

        kfree(tcp_conn_handler);
        kfree(tcp_server);
        tcp_server = NULL;

        if(cli_conn_socket)
        {
                pr_info(" *** mtp | 2. Closing client connection | "
                        "network_server_exit ***\n");
                tcp_client_exit();
        }

exit_net_server:
        deregister_rs();
        pr_info(" *** mtp | network server module unloaded | "
                "network_server_exit *** \n");
}
/*
module_init(network_server_init)
module_exit(network_server_exit)
*/
