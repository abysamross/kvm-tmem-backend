#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>

#include "bloom_filter.h"
#include "network_tcp.h"

#define PORT 2325

struct socket *cli_conn_socket = NULL;

u32 create_address(u8 *ip)
{
        u32 addr = 0;
        int i;

        for(i=0; i<4; i++)
        {
                addr += ip[i];
                if(i==3)
                        break;
                addr <<= 8;
        }
        return addr;
}

u32 create_addr_from_str(char *str)
{
        u32 addr = 0;
        int i;
        u32 j;

        for(i = 0; i < 4; i++)
        {
                j = 0;
                kstrtouint(strsep(&str,"."), 10, &j);
                //pr_info("%d octet: %u\n", i, j);
                addr += j;

                if(i == 3)
                        break;

                addr <<= 8;
        }

        return addr;
}

int tcp_client_send(struct socket *sock, void *snd_buf, const size_t length,\
                    unsigned long flags, int huge)
{
        struct msghdr msg;
        //struct iovec iov;
        struct kvec vec;
        int len, written = 0, left = length;
        char *buf;
        mm_segment_t oldmm;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        /*
        msg.msg_iov     = &iov;
        msg.msg_iovlen  = 1;
        */
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags   = flags;

        buf = (char *)snd_buf;

        oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
        /*
        msg.msg_iov->iov_len  = left;
        msg.msg_iov->iov_base = (char *)buf + written; 
        */
        vec.iov_len = left;
        vec.iov_base = (char *)(buf + written);

        //len = kernel_sendmsg(sock, &msg, &vec, 1???, left);????
        len = kernel_sendmsg(sock, &msg, &vec, left, left);

        if((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT)&&(len == -EAGAIN)))
                goto repeat_send;

        //pr_info("written: %d\n", len);

        if(huge)
        {
                if(len > 0)
                {
                        //pr_info("written: %d\n", len);
                        written += len;
                        //pr_info("total written: %d\n", written);
                        left -= len;
                        //pr_info("left: %d\n", left);
                        if(left)
                                goto repeat_send;
                }
        }
        set_fs(oldmm);
        pr_info(" *** mtp | return from send after writing total: %d bytes, "
                "last write: %d bytes | tcp_client_send \n", written, len);
        return written ? written:len;
}

int tcp_client_receive(struct socket *sock, char *str, unsigned long flags)
{
        //mm_segment_t oldmm;
        struct msghdr msg;
        //struct iovec iov;
        struct kvec vec;
        int len;
        int max_size = 50;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        /*
        msg.msg_iov     = &iov;
        msg.msg_iovlen  = 1;
        */
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags   = flags;
        /*
        msg.msg_iov->iov_base   = str;
        msg.msg_ioc->iov_len    = max_size; 
        */
        vec.iov_len = max_size;
        vec.iov_base = str;

        //oldmm = get_fs(); set_fs(KERNEL_DS);
read_again:
        //len = sock_recvmsg(sock, &msg, max_size, 0); 
        len = kernel_recvmsg(sock, &msg, &vec, max_size, max_size, flags);

        if(len == -EAGAIN || len == -ERESTARTSYS)
        {
                pr_info(" *** mtp | error while reading: %d | "
                        "tcp_client_receive *** \n", len);

                goto read_again;
        }


        pr_info(" *** mtp | the server says: %s | tcp_client_receive *** \n",str);
        //set_fs(oldmm);
        return len;
}

int tcp_client_snd_page(struct remote_server *rs, struct page *page)
{
        int ret = 0, len = 49;
        char in_msg[len+1];
        char out_msg[len+1];
        void *vaddr;
        struct socket *conn_socket; 

        DECLARE_WAIT_QUEUE_HEAD(page_wait);                               

        conn_socket = rs->lcc_socket;

        pr_info(" *** mtp | client sending RECV:PAGE to: %s | "
                "tcp_client_snd_page ***\n", rs->rs_ip);                           

        memset(out_msg, 0, len+1);                                        

        snprintf(out_msg, sizeof(out_msg), "RECV:PAGE");

        tcp_client_send(conn_socket, out_msg, strlen(out_msg), MSG_DONTWAIT, 0);
        
snd_page_wait:

        wait_event_timeout(page_wait,\
                           !skb_queue_empty(&conn_socket->sk->sk_receive_queue),\
                           10*HZ);   

        if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))              
        {
                pr_info(" *** mtp | client receiving message | "
                        "tcp_client_snd_page ***\n");                           
                memset(in_msg, 0, len+1);                                 

                ret = tcp_client_receive(conn_socket, in_msg, MSG_DONTWAIT); 

                pr_info(" *** mtp | client received: %d bytes | "
                        "tcp_client_snd_page ***\n", ret);
        
                if(ret > 0)                                              
                {
                        if(memcmp(in_msg, "SEND", 4) == 0)
                        {
                                if(memcmp(in_msg+5, "PAGE", 4) == 0)
                                {
                                        vaddr = page_address(page);

                                        /*
                                        ret = 
                                        tcp_client_send(conn_socket, vaddr,\
                                                        PAGE_SIZE,MSG_DONTWAIT,1);
                                        */
                                        ret = 
                                        kernel_sendpage(conn_socket, page, 0,\
                                                        PAGE_SIZE, MSG_DONTWAIT);

                                        if(ret != PAGE_SIZE)
                                        {
                                                msleep(5000);
                                                memset(out_msg, 0, len+1);        
                                                strcat(out_msg, "FAIL");
                                                ret = 
                                                tcp_client_send(conn_socket,\
                                                                out_msg,\
                                                                strlen(out_msg),\
                                                                MSG_DONTWAIT, 0);
                                                goto page_fail;
                                        }

                                        pr_info(" *** mtp | page "
                                                "send to: %s | "
                                                "tcp_client_snd_page *** \n",
                                                rs->rs_ip);

                                        goto snd_page_wait;
                                }
                        }
                        else if(memcmp(in_msg, "FNDS", 4) == 0)
                        {
                                if(memcmp(in_msg+5, "PAGE", 4) == 0)
                                {
                                        pr_info(" *** mtp | SUCCESS: page "
                                                "found at: %s | "
                                                "tcp_client_snd_page *** \n",
                                                rs->rs_ip);
                                }
                        }
                        else if(memcmp(in_msg, "FAIL", 4) == 0)
                        {
                                if(memcmp(in_msg+5, "PAGE", 4) == 0)
                                {
                                        pr_info(" *** mtp | FAIL: page "
                                                "not found at: %s | "
                                                "tcp_client_snd_page *** \n",
                                                rs->rs_ip);
                                }
                        }
                        else
                                goto page_fail;
                }
        }
        else                                                              
        {                                                                  
                pr_info(" *** mtp | client RECV:PAGE:%s failed | "
                        "tcp_client_snd_page ***\n", rs->rs_ip);

                goto page_fail;                                                  
        }

        return 0;

page_fail:

         return -1;
}

int tcp_client_fwd_filter(struct bloom_filter *bflt)
{                                                     
        int len = 49;                                              
        char in_msg[len+1];                                              
        char out_msg[len+1];                                            
        int ret;
        int attempts = 0;
        void *vaddr;
        //unsigned long off;
        int size;
        int i;
        //struct page *pg;
        //int pc = 0;

        DECLARE_WAIT_QUEUE_HEAD(bflt_wait);                               

bflt_resend:                                                                  

        pr_info(" *** mtp | client sending FRWD:BFLT | "
                "tcp_client_fwd_filter ***\n");                           

        mutex_lock(&bflt->lock);

        for(i = 0; i < bflt->bitmap_size; i++)
                if(test_bit(i, bflt->bitmap))
                        pr_info("bit: %d of bflt is set\n", i);

        mutex_unlock(&bflt->lock);

        size = BITS_TO_LONGS(bflt->bitmap_size)*sizeof(unsigned long);

        pr_info(" *** mtp | bmap bits size: %d, bmap bytes size: %d | "
                "tcp_client_fwd_filter\n", bflt->bitmap_size, size);

        memset(out_msg, 0, len+1);                                        

        snprintf(out_msg, sizeof(out_msg), "FRWD:BFLT:%d",\
                 bflt->bitmap_size);

        tcp_client_send(cli_conn_socket, out_msg, strlen(out_msg),\
                        MSG_DONTWAIT, 0);
fwd_bflt_wait:
        /* this waiting thing can be made a parametrized funtion, the
         * argument to which specifies the wait time*/
        wait_event_timeout(bflt_wait,\
                           !skb_queue_empty(&cli_conn_socket->sk->\
                           sk_receive_queue), 10*HZ);   

        if(!skb_queue_empty(&cli_conn_socket->sk->sk_receive_queue))              
        {                                                                        
                pr_info(" *** mtp | client receiving message | "
                        "tcp_client_fwd_filter ***\n");                           
                memset(in_msg, 0, len+1);                                 

                ret = tcp_client_receive(cli_conn_socket, in_msg, MSG_DONTWAIT); 

                pr_info(" *** mtp | client received: %d bytes | "
                        "tcp_client_fwd_filter ***\n", ret);

                if(ret > 0)                                              
                {
                        if(memcmp(in_msg, "SEND", 4) == 0)
                        {
                                if(memcmp(in_msg+5, "BFLT", 4) == 0)
                                {
                                        //int tot_ret = 0;
                                        //int n_pages = 
                                        //(size + PAGE_SIZE - 1)/PAGE_SIZE;
                                        //int n_pages = CEILING(size, PAGE_SIZE);
                                        //int j=0;
                                        vaddr = 
                                        (void*)((unsigned long)bflt->bitmap);

                                        if(((unsigned long)bflt & (PAGE_SIZE-1))
                                           != 0)
                                                pr_info(" *** mtp | bflt does "
                                                        "not start from a page "
                                                        "boundary | "
                                                        "tcp_client_fwd_filter"
                                                        " ***\n");
                                        /* 
                                         * should I lock the bloom filter before
                                         * sending it??
                                         */

                                        //mutex_lock(&bflt->lock);

                                        ret = 
                                        tcp_client_send(cli_conn_socket, vaddr,\
                                                        size, MSG_DONTWAIT, 1);

                                        //mutex_unlock(&bflt->lock);

                                        /*
                                        for(j = 0; j < n_pages; j++)
                                        {
                                                ret = 
                                                tcp_client_send(cli_conn_socket,\
                                                                vaddr,PAGE_SIZE,\
                                                                MSG_DONTWAIT, 1);
                                                vaddr += PAGE_SIZE;
                                                tot_ret += ret;
                                        }
                                        */

                                        /* 
                                         * Can I assume that memory allocated
                                         * by vmalloc starts from a page
                                         * boundary? Else, I will have to send
                                         * the offset within the page also, at
                                         * least for first page.
                                         */

                                        /* 
                                         * if you failed to send the entire bloom
                                         * filter you should inform this to
                                         * leader server, who is wating for the
                                         * entire size of bloom filter
                                         */
                                        pr_info(" *** mtp | client send: %d "
                                                "bytes as bflt | "
                                                "tcp_client_fwd_filter ***\n", 
                                                ret);                           

                                        /* 
                                         * this resending can also be taken out
                                         * from here and done from the place
                                         * where frwd_filter was originally
                                         * called
                                         */
                                        
                                        if( ret != size)
                                        {
                                                msleep(5000);
                                                memset(out_msg, 0, len+1);        
                                                strcat(out_msg, "FAIL");
                                                ret = 
                                                tcp_client_send(cli_conn_socket,\
                                                                out_msg,\
                                                                strlen(out_msg),\
                                                                MSG_DONTWAIT, 0);
                                        }
                                        goto fwd_bflt_wait;
                                        /*
                                        if(ret != size)
                                                goto bflt_fail;

                                        goto fwd_bflt_wait;
                                        */
                                        /*
                                        for(;vaddr <= (void *)(bflt + size);
                                                        vaddr += PAGE_SIZE)
                                        {
                                                pg = vmalloc_to_page(vaddr);
                                                kernel_sendpage(cli_conn_socket,\
                                                               pg, 0, PAGE_SIZE,\
                                                               MSG_DONTWAIT);
                                                pr_info("page: %d sent\n", pc);
                                                pc++;
                                        }
                                        */
                                }
                                /*
                                else if(memcmp(in_msg+4, "PAGE", 4) == 0)
                                {
                                      //obtain ip or unique id from in_msg
                                      //do comparison of this page in the tmem
                                      //bknd.
                                      //Give response.
                                }
                                */
                        }
                        else if(memcmp(in_msg, "FAIL", 4) == 0)
                        {
                                if(memcmp(in_msg+5, "BFLT", 4) == 0)
                                {
                                        if(attempts == 1)
                                                goto bflt_fail;

                                        /*
                                         * this retry can be moved to place of
                                         * invocation of
                                         * leader_client_fwd_filter function,
                                         * rather than handling it here, as it
                                         * was done in normal remote server client
                                         */
                                        attempts++;
                                        pr_info(" *** mtp | client re-sending "
                                                "FWD:BFLT | " 
                                                "leader_client_fwd_filter***\n");

                                        goto bflt_resend;
                                }
                        
                        }
                        else if(memcmp(in_msg, "DONE", 4) == 0)            
                        {                                                   
                                if(memcmp(in_msg+5, "BFLT", 4) == 0)
                                {
                                        pr_info(" *** mtp | client FWD:BFLT "
                                                "success | "
                                                "tcp_client_fwd_filter ***\n");   
                                }
                        }                                                
                        else                                              
                        {                                                 
                                /*
                                if(attempts == 1)
                                        goto bflt_fail;

                                pr_info(" *** mtp | client re-sending "
                                        "FRWD:BFLT |tcp_client_fwd_filter***\n"); 
                                attempts++;
                                bflt_resend;
                                */
                                goto bflt_fail;                                
                        }                                                     
                }                                                             
        }                                                                    
        else                                                              
        {                                                                  
                pr_info(" *** mtp | client FWD:BFLT failed | "
                        "tcp_client_fwd_filter ***\n");                       
                goto bflt_fail;                                                  
        }                                 

        return 0;

bflt_fail:
        pr_info(" *** mtp | client FWD:BFLT failed | "
                "tcp_client_fwd_filter ***\n");                       
        return -1;
}

int tcp_client_connect_rs(struct remote_server *rs)
{
        struct socket *conn_socket;
        struct sockaddr_in saddr;
        int port;
        char *ip; 
        int ret = -1;
        //int id;

        conn_socket = rs->lcc_socket;
        ip = kmalloc(16*(sizeof(char)),GFP_KERNEL);
        strcpy(ip, rs->rs_ip);
        port = rs->rs_port; 
        //id = rs->rs_id;

        pr_info(" *** mtp | network client connecting to remote server: %s |"
                " tcp_client_connect_rs *** \n", ip);

        pr_info(" *** mtp | remote server destination ip: %s:%d | "
                "tcp_client_connect_rs ***\n", ip, port);

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        saddr.sin_addr.s_addr = htonl(create_addr_from_str(ip));
        kfree(ip);

        ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr,\
                                        sizeof(saddr), O_RDWR);
        
        pr_info(" *** mtp | connection attempt return value: %d | "
                "tcp_client_connect_rs *** \n", ret);

        if(ret && (ret != -EINPROGRESS))
        {
                pr_info(" *** mtp | network client error: %d while "
                        "connecting to rs[%s] | tcp_client_connect_rs *** \n",
                        ret, ip);
                goto fail;
        }

        return 0;
fail:
        sock_release(conn_socket);
        return -1;
}

int tcp_client_connect(void)
{
        struct sockaddr_in saddr;
        /*
        struct sockaddr_in daddr;
        struct socket *data_socket = NULL;
        */
        //unsigned char destip[5] = {10,14,15,180,'\0'};
        unsigned char destip[5] = {10,129,41,200,'\0'};
        //unsigned char destip[5] = {10,14,13,217,'\0'};
        /*
        char *response = kmalloc(4096, GFP_KERNEL);
        char *reply = kmalloc(4096, GFP_KERNEL);
        */
        int len = 49;
        char in_msg[len+1];
        char out_msg[len+1];
        int ret = -1;

        //DECLARE_WAITQUEUE(reg_wait, current);
        DECLARE_WAIT_QUEUE_HEAD(reg_wait);
        
        ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &cli_conn_socket);
        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while creating first socket. | "
                        "tcp_client_connect ***\n", ret);
                goto err;
        }

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(PORT);
        saddr.sin_addr.s_addr = htonl(create_address(destip));

        ret = 
        cli_conn_socket->ops->connect(cli_conn_socket,\
                                      (struct sockaddr *)&saddr,\
                                      sizeof(saddr), O_RDWR);

        if(ret && (ret != -EINPROGRESS))
        {
                pr_info(" *** mtp | Error: %d while connecting using conn "
                        "socket. | tcp_client_connect ***\n", ret);
                goto fail;
        }

        /* The portion below this can be inserted into the main ktb code as per
         * need.
         */
//resend:
        pr_info(" *** mtp | client sending REGRS | tcp_client_connect ***\n");
        memset(out_msg, 0, len+1);
        strcat(out_msg, "REGRS:2325"); 
        tcp_client_send(cli_conn_socket, out_msg, strlen(out_msg),\
                        MSG_DONTWAIT, 0);

        /* the wait_event_timeout is a better approach as, if the server
         * goes down then you can keep looping here (in this approach)
         */
        wait_event_timeout(reg_wait,\
                           !skb_queue_empty(&cli_conn_socket->sk->\
                           sk_receive_queue), 5*HZ);
        /*
        while(1)
        {
        */
                if(!skb_queue_empty(&cli_conn_socket->sk->sk_receive_queue))
                {
                        pr_info(" *** mtp | client receiving message | "
                                "tcp_client_connect ****\n");

                        memset(in_msg, 0, len+1);

                        ret=tcp_client_receive(cli_conn_socket, in_msg,\
                                               MSG_DONTWAIT);

                        if(ret > 0)
                        {
                                if(memcmp(in_msg, "RSREGD", 6) == 0)
                                {
                                        pr_info(" *** mtp | client REGRS success"
                                                " | tcp_client_connect ***\n");
                                        goto success; 
                                }
                                else
                                {
                                        //pr_info("client re-sending REGRS\n");
                                        //goto resend;
                                        pr_info(" *** 1.mtp | client REGRS failed"
                                                " | tcp_client_connect ***\n");
                                        goto fail;
                                }
                        }
                }
                else
                {
                        pr_info(" *** 2.mtp | client REGRS failed | "
                                " tcp_client_connect ***\n");
                        goto fail;
                }
        /*
                add_wait_queue(&cli_conn_socket->sk->sk_wq->wait, &reg_wait);
                while(skb_queue_empty(&cli_conn_socket->sk->sk_receive_queue))
                {
                        __set_current_state(TASK_INTERRUPTIBLE);
                        schedule_timeout(HZ);
                }
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&cli_conn_socket->sk->sk_wq->wait, &reg_wait);
        }
        */
success:
        //tcp_client_fwd_filter();
        return 0;
fail:
        sock_release(cli_conn_socket);
        cli_conn_socket = NULL;
err:
        return -1;
}

int tcp_client_init(void)
{
        pr_info(" *** mtp | network client init | network_client_init *** \n");
        return tcp_client_connect();
        //return 0;
}

void tcp_client_exit(void)
{
        int len = 49;
        char response[len+1];
        char reply[len+1];

        //DECLARE_WAITQUEUE(exit_wait, current);
        DECLARE_WAIT_QUEUE_HEAD(exit_wait);

        memset(&reply, 0, len+1);
        strcat(reply, "ADIOS"); 
        //tcp_client_send(cli_conn_socket, reply);
        tcp_client_send(cli_conn_socket, reply, strlen(reply), MSG_DONTWAIT, 0);

        //while(1)
        //{
                /*
                tcp_client_receive(cli_conn_socket, response);
                add_wait_queue(&cli_conn_socket->sk->sk_wq->wait, &exit_wait)
                */
        wait_event_timeout(exit_wait,\
                           !skb_queue_empty(&cli_conn_socket->sk->\
                           sk_receive_queue), 5*HZ);
        if(!skb_queue_empty(&cli_conn_socket->sk->sk_receive_queue))
        {
                memset(&response, 0, len+1);
                tcp_client_receive(cli_conn_socket, response, MSG_DONTWAIT);
                //remove_wait_queue(&cli_conn_socket->sk->sk_wq->wait,&exit_wait);
        }

        //}

        if(cli_conn_socket != NULL)
        {
                sock_release(cli_conn_socket);
                cli_conn_socket = NULL;
        }
        pr_info(" *** mtp | network client exiting | network_client_exit *** \n");
}
