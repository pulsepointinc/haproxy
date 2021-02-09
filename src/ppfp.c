#include <sys/ioctl.h>
#include <net/if.h>
#include <common/cfgparse.h>
#include <proto/sample.h>
#include <openssl/ssl.h>
#include "proto/arg.h"
#include "proto/obj_type.h"
#include "fplib.h"

/**
 * Example usage:
 * global
 *   ppfp-enabled                    true
 *   ppfp-interface                  lo
 *   ppfp-tls-port                   443
 *   ppfp-aes-key                    AABBCCDDEEFF00112233445566778899
 *   ppfp-hmac-key                   AABBCCDDEEFF00112233445566778899
 *   ppfp-ticket-pfx-hex             BADA55
 *   ppfp-tls-num-tickets            3
 *   ppfp-cap-ring-size              2048
 *   ppfp-cap-pkt-max-size           2048
 *   ppfp-cap-max-locktime-ms        500
 *   ppfp-syn-map-bucket-size        32
 *   ppfp-syn-map-bucket-count       1024
 *   ppfp-tls-map-bucket-size        32
 *   ppfp-tls-map-bucket-count       1024
 *   ppfp-tls-session-timeout-sec    14515200
 * ...
 * backend test-proxy-srv
 *   mode            http
 *   ...
 *   http-request add-header X-PPFP-FingerPrint %[fpdata()]
 *   ...
 */

/**
 * @brief global configuration; updated via configuration
 */
FP_LIB_CONFIG fplib_cfg;

int tls_listen_port;

/**
 * @brief global libfingerprint handle
 */
FP_LIB_HANDLE *fph = NULL;
/**
 * @brief global index used by _ssl_get_peer to obtain haproxy "connection" structs from SSL objects
 */
int haproxy_conn_app_data_index = 0;
/**
 * @brief global enabled flag
 */
int ppfp_enabled = 0;

/* utility functions */

/**
 * @brief write binary string into a destination buffer by reading a hex encoded char buffer; DOES NOT append trailing \0
 * @note This function does not append a trailing NULL terminator!
 * @param dest destination binary buffer pointer; must be of size max_dest_bytes or bigger
 * @param src aribtrary source hex string
 * @param max_dest_bytes maximum number of bytes to write
 * @return number of bytes written into dest
 */
int from_hex(unsigned char *dest, char *src, int max_dest_bytes)
{
    unsigned char one_byte;
    char *cur_ptr;
    int written = 0;
    if (src == NULL)
    {
        return -1;
    }
    while (written < max_dest_bytes)
    {
        cur_ptr = src + written * 2;
        if (*cur_ptr == 0 || *(cur_ptr + 1) == 0)
        {
            break;
        }
        one_byte = 0;
        if (sscanf(cur_ptr, "%02hhx", &one_byte) != 1)
        {
            break;
        }
        dest[written++] = one_byte;
    }
    return written;
}

static int _ppfp_write_int_or_error(char **args, char **err, int min_value, int max_value, int *dest)
{
    int int_value = 0;
    if (*(args[1]) == 0)
    {
        memprintf(err, "'%s' expects an int greater than %d and less than %d.", args[0], min_value, max_value);
        return -1;
    }
    int_value = atoi(args[1]);
    if (int_value < min_value || int_value > max_value)
    {
        memprintf(err, "'%s' expects an int greater than %d and less than %d.", args[0], min_value, max_value);
        return -1;
    }
    *dest = int_value;
    return 0;
}

static int _ppfp_write_u_int16_t_or_error(char **args, char **err, int min_value, int max_value, u_int16_t *dest)
{
    int int_value = 0;
    int retval = _ppfp_write_int_or_error(args, err, min_value, max_value, &int_value);
    if (retval < 0)
    {
        return retval;
    }
    *dest = int_value;
    return retval;
}

static int _ppfp_write_u_int32_t_or_error(char **args, char **err, int min_value, int max_value, u_int32_t *dest)
{
    int int_value = 0;
    int retval = _ppfp_write_int_or_error(args, err, min_value, max_value, &int_value);
    if (retval < 0)
    {
        return retval;
    }
    *dest = int_value;
    return retval;
}

static int _ppfp_write_binhex_or_error(char **args, char **err, int min_bytes, int max_bytes, unsigned char *dest, int *opt_size)
{
    int copied = 0;
    if (*(args[1]) == 0)
    {
        memprintf(err, "'%s' expects a binary string between %d and %d bytes encoded as hex", args[0], min_bytes, max_bytes);
        return -1;
    }
    bzero(dest, max_bytes);
    copied = from_hex(dest, args[1], max_bytes);
    if (copied < min_bytes)
    {
        memprintf(err, "'%s' expects a binary string between %d and %d bytes encoded as hex; read %d bytes", args[0], min_bytes, max_bytes, copied);
        return -1;
    }
    if (opt_size != NULL)
    {
        *opt_size = copied;
    }
    return 0;
}

/**
 * @brief populates the IP address (e.g. 1.2.3.4) of an interface into dest
 * @param dest destination ip string pointer (e.g. 1.2.3.4)
 * @param interface_name interface name string (e.g. eth0)
 * 
 * @return 0 on success
 */
static int _get_ipv4_addr(char *dest, char *interface_name)
{
    struct ifreq ifr;
    int fd = 0;
    size_t if_name_len = strlen(interface_name);
    if (if_name_len < sizeof(ifr.ifr_name))
    {
        memcpy(ifr.ifr_name, interface_name, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    }
    else
    {
        // interface name too long
        return -1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        return -2;
    }
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
    {
        close(fd);
        return -3;
    }
    close(fd);
    strcpy(dest, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return 0;
}

/**
 * @brief configures the capture string stored in fplib_cfg.cap_config.cap_bpf_filter by looking at device and port configs
 * @return 0 on success
 */
static int _configure_capstring()
{
    int errcode = 0;
    char cap_bpf_filter[1024];
    char cap_dst_ipv4[16];
    bzero(cap_dst_ipv4, 1024);
    bzero(cap_bpf_filter, 16);

    if ((errcode = _get_ipv4_addr(cap_dst_ipv4, fplib_cfg.cap_config.cap_device_name)) != 0)
    {
        return -1;
    }

    if (snprintf(cap_bpf_filter, 1024, "tcp dst port %d and dst host %s and ((tcp[tcpflags] & (tcp-syn) != 0) or ((tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))))", tls_listen_port, cap_dst_ipv4) <= 0)
    {
        return -2;
    }

    if (fplib_cfg.cap_config.cap_bpf_filter)
    {
        free(fplib_cfg.cap_config.cap_bpf_filter);
    }
    fplib_cfg.cap_config.cap_bpf_filter = strdup(cap_bpf_filter);
    return 0;
}

/* end of utility functions */

/* module functions */

/**
 * @brief haproxy specific method of obtaining IP and port of incoming connection from an SSL reference
 * @note this function needs adjustement depending on version of haproxy!
 * @param ssl_obj SSL object
 * @param src_addr IP address destination array pointer
 * @param src_port TCP source port destination pointer
 * @return 0 on success
 */
extern int _ssl_get_peer(SSL *ssl_obj, char *src_addr, int *src_port)
{
    struct connection *conn;
    if (ssl_obj == NULL)
    {
        return -1;
    }
    conn = SSL_get_ex_data(ssl_obj, haproxy_conn_app_data_index);
    if (conn == NULL)
    {
        return -2;
    }
    if (conn->addr.from.ss_family != AF_INET)
    {
        return -3;
    }
    *src_port = get_host_port(&conn->addr.from);
    if (inet_ntop(AF_INET, &((struct sockaddr_in *)&conn->addr.from)->sin_addr, src_addr, INET_ADDRSTRLEN) == NULL)
    {
        return -4;
    }
    return 0;
}
/**
 * @brief check function for "fpdata" variables
 */
static int _fetch_check_fn(struct arg *arg, char **err_msg)
{
    // do not bother checking anything
    return 1;
}

/**
 * @brief fetch function for "fpdata" variables; 
 */
static int _fetch_fn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
    struct connection *cli_conn = objt_conn(smp->sess->origin);
    int port;
    char src_ip_str[INET_ADDRSTRLEN];
    struct buffer *temp;
    FP_LIB_FINGERPRINT fp;
    char fp_buffer[1024];
    if (!cli_conn)
        return 0;
    port = get_host_port(&cli_conn->addr.from);
    switch (cli_conn->addr.from.ss_family)
    {
    case AF_INET:
        if (inet_ntop(AF_INET, &((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr, src_ip_str, INET_ADDRSTRLEN) == NULL)
        {
            return 0;
        }
        break;
    case AF_INET6:
        // ((struct sockaddr_in6 *)&cli_conn->addr.from)->sin6_addr;
        return 0;
    default:
        return 0;
    }

    temp = get_trash_chunk();
    chunk_reset(temp);

    FP_LIB_FINGERPRINT_init(&fp);
    if (fph != NULL)
    {
        if (FP_LIB_HANDLE_get_FINGERPRINT(fph, src_ip_str, port, &fp, NULL) != 0)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    FP_LIB_FINGERPRINT_print(&fp, fp_buffer, 1024);

    // write fingerpting to temp buffer
    chunk_appendf(temp, "%s", fp_buffer);
    // reset type to str
    smp->data.type = SMP_T_STR;
    // update buffers
    smp->data.u.str.area = temp->area;
    smp->data.u.str.data = temp->data;
    // flag the sample to show it uses constant memory
    smp->flags |= SMP_F_CONST;
    return 1;
}

/**
 * @brief initializes ppfp config that may be reused later
 */
static int init_ppfp_config(void)
{
    return FP_LIB_CONFIG_init(&fplib_cfg);
}

/**
 * @brief module init function. Returns 0 if OK, or a combination of ERR_*.
 */
static int init_ppfp(void)
{
    int errcode = 0;
    char errmsg[FP_LIB_ERRMSG_SIZE];
    bzero(errmsg, FP_LIB_ERRMSG_SIZE);

    if (ppfp_enabled != 1)
    {
        return 0;
    }

    if ((errcode = _configure_capstring()) != 0)
    {
        ha_alert("PPFP: Unable to configure PPFP capture; errcode %d", errcode);
        return ERR_ALERT | ERR_FATAL;
    }

    // attempt to figure out the SSL exdata index used to store connections by haproxy by
    // creating a dummy index and subtracting 2 (because haproxy uses two index slots)
    // note that later versions of haproxy seem to just rely on connections stored in SSL_BIOs
    // obviating the need for these gymnastics; see example in cfp lib for that

    haproxy_conn_app_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL) - 2;

    fplib_cfg.tls_config.tls_get_peer_address_fn = &_ssl_get_peer;

    // create new handle
    FP_LIB_HANDLE_free(fph);
    if ((errcode = FP_LIB_HANDLE_new(&fplib_cfg, &fph, errmsg)) != 0)
    {
        ha_alert("PPFP: FP_LIB_HANDLE_new failed with code %d: %s", errcode, errmsg);
        return ERR_ALERT | ERR_FATAL;
    }

    if ((errcode = FP_LIB_HANDLE_start_capture(fph, errmsg)) != 0)
    {
        ha_alert("PPFP: FP_LIB_HANDLE_start_capture failed with code %d: %s\n", errcode, errmsg);
        return ERR_ALERT | ERR_FATAL;
    }

    if ((errcode = FP_LIB_HANDLE_instr_all_SSL_CTX(fph, errmsg)) != 0)
    {
        ha_alert("PPFP: FP_LIB_HANDLE_instr_all_SSL_CTX failed with code %d: %s", errcode, errmsg);
        return ERR_ALERT | ERR_FATAL;
    }

    return 0;
}

/**
 * @brief module de-init function.
 */
static void deinit_ppfp(void)
{
    FP_LIB_HANDLE_free(fph);
}

/* configuration keyword setter functions */

static int _ppfp_set_enabled(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
    if (*(args[1]) == 0)
    {
        memprintf(err, "'%s' expects true/false", args[0]);
        return -1;
    }
    if (strcmp("true", args[1]) == 0)
    {
        ppfp_enabled = 1;
    }
    else
    {
        ppfp_enabled = 0;
    }
    return 0;
}

static int _ppfp_set_interface(char **args, int section_type, struct proxy *curpx,
                               struct proxy *defpx, const char *file, int line,
                               char **err)
{
    if (*(args[1]) == 0)
    {
        memprintf(err, "'%s' expects an interface name.", args[0]);
        return -1;
    }
    if (fplib_cfg.cap_config.cap_device_name)
    {
        free(fplib_cfg.cap_config.cap_device_name);
    }
    fplib_cfg.cap_config.cap_device_name = strdup(args[1]);
    return 0;
}

static int _ppfp_set_tls_port(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
    return _ppfp_write_int_or_error(args, err, 0, 65536, &tls_listen_port);
}

static int _ppfp_set_aes_key(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
    return _ppfp_write_binhex_or_error(args, err, FP_LIB_TLS_AES_KEY_LEN, FP_LIB_TLS_AES_KEY_LEN, fplib_cfg.tls_config.tls_aes_key, NULL);
}

static int _ppfp_set_hmac_key(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
    return _ppfp_write_binhex_or_error(args, err, FP_LIB_TLS_HMAC_KEY_LEN, FP_LIB_TLS_HMAC_KEY_LEN, fplib_cfg.tls_config.tls_hmac_key, NULL);
}

static int _ppfp_set_ticket_pfx(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
    return _ppfp_write_binhex_or_error(args, err, 3, 5, fplib_cfg.tls_config.tls_tn_prefix, &fplib_cfg.tls_config.tls_tn_prefix_len);
}

static int _ppfp_set_num_tickets(char **args, int section_type, struct proxy *curpx,
                                 struct proxy *defpx, const char *file, int line,
                                 char **err)
{
    return _ppfp_write_int_or_error(args, err, 3, 65536, &fplib_cfg.tls_config.tls_num_tickets);
}

static int _ppfp_set_cap_ring_size(char **args, int section_type, struct proxy *curpx,
                                   struct proxy *defpx, const char *file, int line,
                                   char **err)
{
    return _ppfp_write_u_int16_t_or_error(args, err, 8, 65536, &fplib_cfg.cap_config.cap_ring_buffer_size);
}

static int _ppfp_set_cap_pkt_max_size(char **args, int section_type, struct proxy *curpx,
                                      struct proxy *defpx, const char *file, int line,
                                      char **err)
{
    return _ppfp_write_u_int16_t_or_error(args, err, 0, 65536, &fplib_cfg.cap_config.cap_max_packet_size);
}

static int _ppfp_set_cap_max_locktime_ms(char **args, int section_type, struct proxy *curpx,
                                         struct proxy *defpx, const char *file, int line,
                                         char **err)
{
    return _ppfp_write_u_int32_t_or_error(args, err, 0, 65536, &fplib_cfg.cap_config.lock_wait_time_ms);
}

static int _ppfp_set_syn_map_bucket_size(char **args, int section_type, struct proxy *curpx,
                                         struct proxy *defpx, const char *file, int line,
                                         char **err)
{
    return _ppfp_write_int_or_error(args, err, 1, 65536, &fplib_cfg.cap_config.syn_map_bucket_size);
}

static int _ppfp_set_syn_map_bucket_count(char **args, int section_type, struct proxy *curpx,
                                          struct proxy *defpx, const char *file, int line,
                                          char **err)
{
    return _ppfp_write_int_or_error(args, err, 1, 65536, &fplib_cfg.cap_config.syn_map_bucket_count);
}

static int _ppfp_set_tls_map_bucket_size(char **args, int section_type, struct proxy *curpx,
                                         struct proxy *defpx, const char *file, int line,
                                         char **err)
{
    return _ppfp_write_int_or_error(args, err, 1, 65536, &fplib_cfg.tls_config.tls_map_bucket_size);
}

static int _ppfp_set_tls_map_bucket_count(char **args, int section_type, struct proxy *curpx,
                                          struct proxy *defpx, const char *file, int line,
                                          char **err)
{
    return _ppfp_write_int_or_error(args, err, 1, 65536, &fplib_cfg.tls_config.tls_map_bucket_count);
}

static int _ppfp_set_tls_session_timeout(char **args, int section_type, struct proxy *curpx,
                                         struct proxy *defpx, const char *file, int line,
                                         char **err)
{
    return _ppfp_write_int_or_error(args, err, 1, 2147483647, &fplib_cfg.tls_config.tls_session_timeout_sec);
}

/* registration */

/**
 * @brief list of "fetch" keywords provided by this module ("fpdata")
 */
static struct sample_fetch_kw_list fetch_keywords =
    {ILH,
     {
         {"fpdata", _fetch_fn, ARG1(1, STR), _fetch_check_fn, SMP_T_STR, /*SMP_USE_HRQHV*/ SMP_USE_L4CLI},
         {NULL, NULL, 0, 0, 0},
     }};

/**
 * @brief list of global configuration keywords required by this module
 */
static struct cfg_kw_list _ppfp_kws =
    {{},
     {
         {CFG_GLOBAL, "ppfp-enabled", _ppfp_set_enabled},
         {CFG_GLOBAL, "ppfp-interface", _ppfp_set_interface},
         {CFG_GLOBAL, "ppfp-tls-port", _ppfp_set_tls_port},
         {CFG_GLOBAL, "ppfp-aes-key", _ppfp_set_aes_key},
         {CFG_GLOBAL, "ppfp-hmac-key", _ppfp_set_hmac_key},
         {CFG_GLOBAL, "ppfp-ticket-pfx-hex", _ppfp_set_ticket_pfx},
         {CFG_GLOBAL, "ppfp-tls-num-tickets", _ppfp_set_num_tickets},
         {CFG_GLOBAL, "ppfp-cap-ring-size", _ppfp_set_cap_ring_size},
         {CFG_GLOBAL, "ppfp-cap-pkt-max-size", _ppfp_set_cap_pkt_max_size},
         {CFG_GLOBAL, "ppfp-cap-max-locktime-ms", _ppfp_set_cap_max_locktime_ms},
         {CFG_GLOBAL, "ppfp-syn-map-bucket-size", _ppfp_set_syn_map_bucket_size},
         {CFG_GLOBAL, "ppfp-syn-map-bucket-count", _ppfp_set_syn_map_bucket_count},
         {CFG_GLOBAL, "ppfp-tls-map-bucket-size", _ppfp_set_tls_map_bucket_size},
         {CFG_GLOBAL, "ppfp-tls-map-bucket-count", _ppfp_set_tls_map_bucket_count},
         {CFG_GLOBAL, "ppfp-tls-session-timeout-sec", _ppfp_set_tls_session_timeout},
         {0, NULL, NULL},
     }};

INITCALL0(STG_REGISTER, init_ppfp_config);
INITCALL1(STG_REGISTER, cfg_register_keywords, &_ppfp_kws);
INITCALL1(STG_REGISTER, sample_register_fetches, &fetch_keywords);
REGISTER_POST_CHECK(init_ppfp);
REGISTER_POST_DEINIT(deinit_ppfp);
REGISTER_BUILD_OPTS("Built with PPFP support.");