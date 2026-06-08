#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/select.h>
#include <stdint.h>     // --- NEW: 用于 uint64_t 和 uint32_t

#define BUF_SIZE 65536  // 扩大至 64KB，极大提升吞吐量

#define DEFAULT_LOCAL_PORT    8080  
#define DEFAULT_REMOTE_PORT   8081 
#define DEFAULT_R_P   1024      
#define DEFAULT_M_S   "Lbxx:"   
#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define HEADER_BUFFER_FULL -10
#define BAD_HTTP_PROTOCOL -11

#define MAX_HEADER_SIZE 8192

#if defined(OS_ANDROID)
#include <android/log.h>
#define LOG(fmt...) __android_log_print(ANDROID_LOG_DEBUG,__FILE__,##fmt)
#else
#define LOG(fmt...)  do { fprintf(stderr,"%s %s ",__DATE__,__TIME__); fprintf(stderr, ##fmt); } while(0)
#endif


// --- NEW: tcp-brutal 定义开始 ---
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

#define TCP_BRUTAL_PARAMS 23301

struct brutal_params {
    uint64_t rate;      // 发送速率 (Bytes per second)
    uint32_t cwnd_gain; // 拥塞窗口增益，10 代表 1.0
} __attribute__((packed));
// --- NEW: tcp-brutal 定义结束 ---


// --- 线程安全的上下文结构体 ---
typedef struct {
    char remote_host[256];
    int remote_port;
    char header_buffer[MAX_HEADER_SIZE];
    int is_http_tunnel;
} proxy_ctx_t;

typedef struct {
    int client_sock;
    struct sockaddr_in client_addr;
} client_info_t;

// --- 全局只读配置 (线程安全) ---
int local_port;
char r_h[128]; 
int r_p; 
char m_s[128];
int server_sock; 
int brutal_rate_mbps; // --- NEW: tcp-brutal 发送速率变量

enum 
{
    FLG_NONE = 0,       
    R_C_DEC = 1,        
    W_S_ENC = 2         
};

static int io_flag; 
static int r_flag; 
static int m_flag; 

// --- 函数声明 ---
void server_loop();
void *client_thread(void *arg);
void handle_client(int client_sock, struct sockaddr_in client_addr);
void forward_header(int destination_sock, proxy_ctx_t *ctx);
void forward_data_bidirectional(int client_sock, int remote_sock);
void rewrite_header(proxy_ctx_t *ctx);
int do_send(int socket, char * buffer, int len, int do_encode);
int do_recv(int socket, char * buffer, int len, int do_decode);
void hand_mproxy_info_req(int sock, proxy_ctx_t *ctx);
void get_info(char * output, proxy_ctx_t *ctx);
const char * get_work_mode(proxy_ctx_t *ctx);
int create_connection(proxy_ctx_t *ctx);
void set_tcp_nodelay(int sock);
void try_enable_tcp_brutal(int sock); // --- NEW: 声明


// --- NEW: tcp-brutal 启用与参数配置函数 ---
void try_enable_tcp_brutal(int sock) {
    char cc[] = "brutal";
    
    // 尝试将拥塞控制算法设为 brutal。若内核未安装此模块，该调用将静默失败。
    if (setsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, cc, strlen(cc)) == 0) {
        struct brutal_params params;
        
        // 将 Mbps 转换为 Bps (Bytes per second)
        // 1 Mbps = 1,000,000 bits / 8 = 125,000 Bytes
        params.rate = (uint64_t)brutal_rate_mbps * 1000000 / 8;
        
        // 官方建议将 cwnd_gain 设置在 1.5 到 2.0 之间 (这里使用 1.5 倍)
        params.cwnd_gain = 15; 
        
        if (setsockopt(sock, IPPROTO_TCP, TCP_BRUTAL_PARAMS, &params, sizeof(params)) < 0) {
            LOG("Warning: Failed to set TCP Brutal params\n");
        }
    }
}


// --- 核心优化：使用 MSG_PEEK 实现无副作用的整块读取，告别单字节 Syscall 风暴 ---
int read_header(int fd, char * buffer)
{
    memset(buffer, 0, MAX_HEADER_SIZE);
    while (1) {
        int peek_len = recv(fd, buffer, MAX_HEADER_SIZE - 1, MSG_PEEK);
        if (peek_len <= 0) return CLIENT_SOCKET_ERROR;
        
        buffer[peek_len] = '\0';
        char *end1 = strstr(buffer, "\r\n\r\n");
        char *end2 = strstr(buffer, "\n\n");
        
        if (end1) {
            int header_len = end1 - buffer + 4;
            return recv(fd, buffer, header_len, 0); // 真正读取提取的部分
        } else if (end2) {
            int header_len = end2 - buffer + 2;
            return recv(fd, buffer, header_len, 0); 
        }
        
        if (peek_len == MAX_HEADER_SIZE - 1) return HEADER_BUFFER_FULL;
        usleep(1000); // 稍微等待一下网络包
    }
}

void extract_server_path(const char * header, char * output)
{
    char * p = strstr(header,"GET /");
    if(p) {
        char * p1 = strchr(p+4,' ');
        if(p1) {
            strncpy(output,p+4,(int)(p1  - p - 4) );
            output[(int)(p1 - p - 4)] = '\0';
        }
    }
}

int extract_host(proxy_ctx_t *ctx)
{
    char *header = ctx->header_buffer;
    if(!m_flag)
    {
        if(!r_flag)
        {
            if(strncmp(header, "CONNECT ", 8) == 0)  
            {
                char * _p1 = strchr(header,' ');
                char * _p2 = strchr(_p1 + 1,':');
                char * _p3 = strchr(_p1 + 1,' ');

                if(_p2 && _p3)
                {
                    char s_port[10];
                    bzero(s_port,10);
                    strncpy(ctx->remote_host,_p1+1,(int)(_p2  - _p1) - 1);
                    ctx->remote_host[(int)(_p2  - _p1) - 1] = '\0';
                    strncpy(s_port,_p2+1,(int) (_p3 - _p2) -1);
                    ctx->remote_port = atoi(s_port);
                } else if (_p3)
                {
                    strncpy(ctx->remote_host,_p1+1,(int)(_p3  - _p1) -1);
                    ctx->remote_host[(int)(_p3  - _p1) - 1] = '\0';
                    ctx->remote_port = 80;
                }
                return 0;
            }

            char * p = strstr(header,"Host:");
            if(!p) return BAD_HTTP_PROTOCOL;
            char * p1 = strchr(p,'\n');
            if(!p1) return BAD_HTTP_PROTOCOL; 

            char * p2 = strchr(p + 5,':'); 

            if(p2 && p2 < p1) 
            {
                int p_len = (int)(p1 - p2 -1);
                char s_port[16];
                strncpy(s_port,p2+1,p_len);
                s_port[p_len] = '\0';
                ctx->remote_port = atoi(s_port);

                int h_len = (int)(p2 - p - 6);
                strncpy(ctx->remote_host,p + 6 ,h_len); 
                ctx->remote_host[h_len] = '\0';
            } else 
            {   
                int h_len = (int)(p1 - p - 7); 
                strncpy(ctx->remote_host,p + 6,h_len);
                ctx->remote_host[h_len] = '\0';
                ctx->remote_port = 80;
            }
        } else
        {
            strncpy(ctx->remote_host, r_h, strlen(r_h));
            ctx->remote_host[strlen(r_h)] = '\0';
            ctx->remote_port = r_p;
        }
    } else
    {
        int is_connect = (strncmp(header, "CONNECT ", 8) == 0);
        char * _p = strstr(header,m_s);
        
        if(_p && is_connect)
        {
            char * _p1 = strchr(_p,' ');
            char * _p2 = strchr(_p1 + 1,':');
            char * _p3 = strchr(_p1 + 1,'\r');

            if(_p2 && _p3)
            {
                char s_port[10];
                bzero(s_port,10);
                strncpy(ctx->remote_host,_p1+1,(int)(_p2  - _p1) - 1);
                ctx->remote_host[(int)(_p2  - _p1) - 1] = '\0';
                strncpy(s_port,_p2+1,(int) (_p3 - _p2) -1);
                ctx->remote_port = atoi(s_port);
            } else if (_p3)
            {
                strncpy(ctx->remote_host,_p1+1,(int)(_p3  - _p1) -1);
                ctx->remote_host[(int)(_p3  - _p1) -1] = '\0';
                ctx->remote_port = 80;
            }
            return 0;
        }

        char * p = strstr(header,m_s);
        if(!p) 
        {
            if(r_flag) {
                strncpy(ctx->remote_host, r_h, strlen(r_h));
                ctx->remote_host[strlen(r_h)] = '\0';
                ctx->remote_port = r_p;
                return 0;
            } else return BAD_HTTP_PROTOCOL;
        }
        char * p1 = strchr(p,'\n');
        if(!p1) return BAD_HTTP_PROTOCOL; 
        
        int m_l = strlen(m_s);
        char * p2 = strchr(p + m_l,':'); 

        if(p2 && p2 < p1) 
        {
            int p_len = (int)(p1 - p2 -1);
            char s_port[16];
            strncpy(s_port,p2+1,p_len);
            s_port[p_len] = '\0';
            ctx->remote_port = atoi(s_port);

            int h_len = (int)(p2 - p - m_l - 1 );
            strncpy(ctx->remote_host,p + m_l + 1  ,h_len); 
            ctx->remote_host[h_len] = '\0';
        } else 
        {   
            int h_len = (int)(p1 - p - m_l - 2); 
            strncpy(ctx->remote_host,p + m_l + 1,h_len);
            ctx->remote_host[h_len] = '\0';
            ctx->remote_port = 80;
        }
    }
    return 0;
}

int send_tunnel_ok(int client_sock)
{
    char * resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int len = strlen(resp);
    if(send(client_sock, resp, len, 0) < 0) return -1;
    return 0;
}

void hand_mproxy_info_req(int sock, proxy_ctx_t *ctx) {
    char server_path[255];
    memset(server_path, 0, 255);
    char response[8192];
    extract_server_path(ctx->header_buffer, server_path);
    
    char info_buf[1024];
    get_info(info_buf, ctx);
    sprintf(response,"HTTP/1.0 200 OK\nServer: MProxy/0.2 (High-Perf)\n"
                     "Content-type: text/html; charset=utf-8\n\n"
                     "<html><body><pre>%s</pre></body></html>\n", info_buf);

    send(sock, response, strlen(response), 0);
}

void get_info(char * output, proxy_ctx_t *ctx)
{
    // --- NEW: 在信息页展示当前的 tcp-brutal 配置 ---
    sprintf(output, "======= mproxy (v0.2) ========\n"
                    "%s\n"
                    "start server on %d\n"
                    "TCP Brutal Rate: %d Mbps\n"
                    "current thread hop is %s:%d\n",
            get_work_mode(ctx), local_port, brutal_rate_mbps, 
            ctx ? ctx->remote_host : "N/A", 
            ctx ? ctx->remote_port : 0);
}

const char * get_work_mode(proxy_ctx_t *ctx) 
{
    if(!r_flag && !m_flag) {
        if(io_flag == FLG_NONE) return "start as normal http proxy";
        else if(io_flag == R_C_DEC) return "start as remote forward proxy (decode)";
    } else {
        return "start as -r or -m mode";
    }
    return "unknow";
}

void set_tcp_nodelay(int sock) {
    int optval = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
}

// --- 核心优化：单线程处理单客户端连接 ---
void *client_thread(void *arg) {
    client_info_t *info = (client_info_t *)arg;
    handle_client(info->client_sock, info->client_addr);
    close(info->client_sock);
    free(info);
    return NULL;
}

void handle_client(int client_sock, struct sockaddr_in client_addr)
{
    set_tcp_nodelay(client_sock);
    try_enable_tcp_brutal(client_sock); // --- NEW: 尝试在与客户端通信的 socket 开启 brutal
    
    proxy_ctx_t ctx;
    memset(&ctx, 0, sizeof(proxy_ctx_t));
    
    if(read_header(client_sock, ctx.header_buffer) < 0) return;

    if(strstr(ctx.header_buffer,"GET /mproxy") != NULL) 
    {
        hand_mproxy_info_req(client_sock, &ctx);
        return; 
    }

    // 放宽隧道匹配规则，支持常见请求方法
    if(strncmp(ctx.header_buffer, "CONNECT", 7) == 0 ||
       strncmp(ctx.header_buffer, "GET", 3) == 0 ||
       strncmp(ctx.header_buffer, "POST", 4) == 0 ||
       strncmp(ctx.header_buffer, "PUT", 3) == 0 ||
       strncmp(ctx.header_buffer, "DELETE", 6) == 0 ||
       strncmp(ctx.header_buffer, "OPTIONS", 7) == 0 ||
       strncmp(ctx.header_buffer, "HEAD", 4) == 0 ||
       strncmp(ctx.header_buffer, "PATCH", 5) == 0)
    {
        ctx.is_http_tunnel = 1;
    }

    if(extract_host(&ctx) < 0) return;

    int remote_sock = create_connection(&ctx);
    if (remote_sock < 0) return;

    if(!ctx.is_http_tunnel && strlen(ctx.header_buffer) > 0) 
    {
        forward_header(remote_sock, &ctx); 
    } else if (ctx.is_http_tunnel)
    {
        send_tunnel_ok(client_sock);
    }

    // 启动高性能双向转发
    forward_data_bidirectional(client_sock, remote_sock);
}

void forward_header(int destination_sock, proxy_ctx_t *ctx)
{
    rewrite_header(ctx);
    int len = strlen(ctx->header_buffer);
    do_send(destination_sock, ctx->header_buffer, len, (io_flag == W_S_ENC));
}

int do_send(int socket, char * buffer, int len, int do_encode)
{
    if(do_encode) {
        for(int i = 0; i < len; i++) buffer[i] ^= 1;
    }
    int total_sent = 0;
    while(total_sent < len) {
        int n = send(socket, buffer + total_sent, len - total_sent, 0);
        if (n <= 0) return -1;
        total_sent += n;
    }
    return total_sent;
}

int do_recv(int socket, char * buffer, int len, int do_decode)
{
    int n = recv(socket, buffer, len, 0);
    if(n > 0 && do_decode) {
        for(int i = 0; i < n; i++) buffer[i] ^= 1;
    }
    return n;
}

// 核心优化修复：使用 memmove 替代 memcpy 防止内存重叠导致段错误
void rewrite_header(proxy_ctx_t *ctx)
{
    char * p = strstr(ctx->header_buffer,"http://");
    char * p0 = strchr(ctx->header_buffer,'\0');
    char * p5 = strstr(ctx->header_buffer,"HTTP/"); 
    int len = strlen(ctx->header_buffer);
    if(p)
    {
        char * p1 = strchr(p + 7,'/');
        if(p1 && (p5 > p1)) 
        {
            memmove(p, p1, (int)(p0 - p1)); // 安全覆盖
            ctx->header_buffer[len - (p1 - p)] = '\0';
        } else 
        {
            char * p2 = strchr(p,' ');  
            if(p2) {
                memmove(p + 1, p2, (int)(p0 - p2)); // 安全覆盖
                *p = '/';  
                ctx->header_buffer[len - (p2 - p) + 1] = '\0';
            }
        }
    }
    
    if(m_flag)
    {
        char * p6 = strstr(ctx->header_buffer,"Host:");   
        char * p00 = strchr(ctx->header_buffer,'\0');                    
        char * p7 = strchr(p6,' '); 
        char * p8 = strstr(ctx->header_buffer,m_s);              
        char * p9 = p8 ? strchr(p8,' ') : NULL;
        if(p6 && p7 && p8 && p9 && (p8 > p6))
        {
            memmove(p7, p9, (int)(p00 - p9));  // 安全覆盖
            ctx->header_buffer[len - (p9 - p7)] = '\0';
        }
    }
}

// 核心优化：单线程 `select` 高速双向转发
void forward_data_bidirectional(int client_sock, int remote_sock) {
    int max_fd = (client_sock > remote_sock) ? client_sock : remote_sock;
    char buffer[BUF_SIZE];
    
    int c2s_decode = (io_flag == R_C_DEC);
    int c2s_encode = (io_flag == W_S_ENC);
    int s2c_decode = (io_flag == W_S_ENC);
    int s2c_encode = (io_flag == R_C_DEC);

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(remote_sock, &read_fds);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 处理 Client -> Remote (C2S)
        if (FD_ISSET(client_sock, &read_fds)) {
            int n = do_recv(client_sock, buffer, BUF_SIZE, c2s_decode);
            if (n <= 0) break;
            if (do_send(remote_sock, buffer, n, c2s_encode) <= 0) break;
        }

        // 处理 Remote -> Client (S2C)
        if (FD_ISSET(remote_sock, &read_fds)) {
            int n = do_recv(remote_sock, buffer, BUF_SIZE, s2c_decode);
            if (n <= 0) break;
            if (do_send(client_sock, buffer, n, s2c_encode) <= 0) break;
        }
    }

    shutdown(client_sock, SHUT_RDWR);
    shutdown(remote_sock, SHUT_RDWR);
    close(remote_sock);
}

int create_connection(proxy_ctx_t *ctx) {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return CLIENT_SOCKET_ERROR;

    if ((server = gethostbyname(ctx->remote_host)) == NULL) return CLIENT_RESOLVE_ERROR;
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(ctx->remote_port);

    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return CLIENT_CONNECT_ERROR;
    }
    
    set_tcp_nodelay(sock);
    try_enable_tcp_brutal(sock); // --- NEW: 尝试在与远端通信的 socket 开启 brutal
    return sock;
}

int create_server_socket(int port) {
    int srv_sock, optval = 1;
    struct sockaddr_in server_addr;

    if ((srv_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return SERVER_SOCKET_ERROR;
    if (setsockopt(srv_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) return SERVER_SETSOCKOPT_ERROR;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) return SERVER_BIND_ERROR;
    if (listen(srv_sock, 1024) < 0) return SERVER_LISTEN_ERROR; // 提升内核队列以应对高并发

    return srv_sock;
}

void server_loop() {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1) {
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (*client_sock < 0) {
            free(client_sock);
            continue;
        }

        client_info_t *info = malloc(sizeof(client_info_t));
        info->client_sock = *client_sock;
        info->client_addr = client_addr;
        free(client_sock);

        // 创建新线程处理连接
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, info) == 0) {
            pthread_detach(tid); // 线程结束后自动回收资源，避免僵尸线程
        } else {
            close(info->client_sock);
            free(info);
        }
    }
}

void usage(void)
{
    printf("Usage:\n");
    printf(" -l <port number>  specifyed local listen port \n");
    printf(" -h <remote server and port> specifyed next hop server name to forward all trafic unhandled, prior to -m & -r\n");
    printf(" -r <server and port> specifyed server name to forward 'HTTP'&'CONNECT' to, no matter what host is\n");
    printf(" -m <ml key words>  specifyed key words replaced & recognized as 'Host:' function, prior to -r\n");
    printf(" -d run as daemon\n");
    printf(" -E encode data when forwarding data\n");
    printf(" -D decode data when receiving data\n");
    printf(" -b <Mbps> specify TCP Brutal send rate in Mbps (default 100)\n"); // --- NEW
    printf(" Notice:-h -r -m can not be used together.\n");
    exit (8);
}

void start_server(int daemon_mode)
{
    // 忽略管道断开信号，防止客户端强退导致服务端崩溃
    signal(SIGPIPE, SIG_IGN); 

    if ((server_sock = create_server_socket(local_port)) < 0) 
    { 
        LOG("Cannot run server on %d\n",local_port);
        exit(server_sock);
    }
    
    if(daemon_mode)
    {
        pid_t pid;
        if((pid = fork()) == 0)
        {
            server_loop();
        } else if (pid > 0 ) 
        {
            LOG("mproxy started in background, pid is: [%d]\n",pid);
            exit(0);
        } else 
        {
            LOG("Cannot daemonize\n");
            exit(pid);
        }
    } else 
    {
        server_loop();
    }
}

int main(int argc, char *argv[]) 
{
    local_port = DEFAULT_LOCAL_PORT;
    io_flag = FLG_NONE;
    r_flag = 0;
    m_flag = 0;
    brutal_rate_mbps = 100; // --- NEW: 初始化默认速率
    strcpy(m_s, DEFAULT_M_S);
    int daemon_mode = 0; 
    
    int opt;
    // --- NEW: 增加 'b:' 识别参数
    char optstrs[] = ":l:h:r:m:dEDb:";
    char *p = NULL;
    while(-1 != (opt = getopt(argc, argv, optstrs)))
    {
        switch(opt)
        {
            case 'l':
                local_port = atoi(optarg);
                break;
            case 'b': // --- NEW: 截获并赋值 tcp-brutal 发送速率
                brutal_rate_mbps = atoi(optarg);
                if (brutal_rate_mbps <= 0) brutal_rate_mbps = 100; // 防呆机制
                break;
            case 'h': // 保持你的原有解析逻辑不动
            case 'r':
            case 'm':
                // 确保你使用前面的 CLI 解析配置
                if(opt == 'r') {
                    p = strchr(optarg, ':');
                    if(p) { strncpy(r_h, optarg, p - optarg); r_h[p - optarg] = '\0'; r_p = atoi(p+1); }
                    else { strcpy(r_h, optarg); r_p = DEFAULT_R_P; }
                    r_flag = 1;
                } else if(opt == 'm') {
                    strcpy(m_s, optarg);
                    m_flag = 1;
                }
                break;
            case 'd': daemon_mode = 1; break;
            case 'E': io_flag = W_S_ENC; break;
            case 'D': io_flag = R_C_DEC; break;
            case ':':
            case '?': usage();
        }
    }

    LOG("Server started on port %d... (Brutal Target Rate: %d Mbps)\n", local_port, brutal_rate_mbps);
    start_server(daemon_mode);
    return 0;
}
