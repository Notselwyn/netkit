#include <linux/slab.h>
#include <linux/types.h>

#include "iface.h"

#include "xor/xor.h"

#include "../core/iface.h"
#include "../mem/mngt.h"

/*static int enc_decode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int retv = 0;
    u8 *enc_req_buf = req_buf;
    size_t enc_req_buflen = req_buflen;
    u8 *enc_res_buf;
    size_t enc_res_buflen;
    
    *res_buf = NULL;
    *res_buflen = 0;

    retv = enc_xor_decode(enc_req_buf, enc_req_buflen, &enc_res_buf, &enc_res_buflen);
    if (retv < 0)
        return retv;

    //enc_req_buf = enc_res_buf;
    enc_req_buflen = enc_res_buflen;

    retv = enc_netkit_encode(enc_req_buf, enc_req_buflen, &enc_res_buf, &enc_res_buflen);
    kzfree(enc_req_buf, enc_req_buflen);
    if (retv < 0)
        return retv;//

    *res_buf = enc_res_buf;
    *res_buflen = enc_res_buflen;

    return retv;
}*/

/***
 * function to get rid of the `struct enc_list_entry*` argument for the list
 */
static int enc_last_process(const struct enc_list_entry *next_entry, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    pr_err("[*] doing core process...\n");
    return core_process(req_buf, req_buflen, res_buf, res_buflen);
}


/**
 * heap guide (req):
 *  - caller allocates
 *  - caller free's
 * 
 * heap guide (res):
 *  - callee allocates
 *  - caller free's
 */
int enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    struct enc_list_entry *enc_func_last;
    struct enc_list_entry *enc_func_xor;
    struct enc_list_entry *first_entry;
    struct enc_list_entry *first_next_entry;
    LIST_HEAD(func_list);

    enc_func_last = kzmalloc(sizeof(*enc_func_last), GFP_KERNEL);
    if (!enc_func_last)
        return -ENOMEM;

    enc_func_xor = kzmalloc(sizeof(*enc_func_xor), GFP_KERNEL);
    if (!enc_func_xor)
    {
        kzfree(enc_func_last, sizeof(*enc_func_last));
        return -ENOMEM;
    }

    enc_func_last->func = enc_last_process;
    list_add(&enc_func_last->list, &func_list);

    enc_func_xor->func = enc_xor_process;
    list_add(&enc_func_xor->list, &func_list);

    pr_err("[*] starting linked list (req_buflen: %lx)...\n", req_buflen);
    /*retv = enc_decode(req_buf, req_buflen, &enc_decoded_buf, &enc_decoded_buflen);
    if (retv < 0)
    {
        // failed layer should include failure
        *res_buf = enc_decoded_buf;
        *res_buflen = enc_decoded_buflen;

        return retv;
    }*/

    first_entry = list_first_entry(&func_list, struct enc_list_entry, list);
    first_next_entry = list_entry(first_entry->list.next, struct enc_list_entry, list);
    first_entry->func(first_next_entry, req_buf, req_buflen, res_buf, res_buflen);

    pr_err("[+] successfully returned from first_entry->func\n");

    kzfree(enc_func_last, sizeof(*enc_func_last));
    kzfree(enc_func_xor, sizeof(*enc_func_xor));

    return 0;

    /*packet = packet_init((struct raw_packet_buf*)post_init_proto_buf, post_init_proto_buflen);
    kzfree(post_proto_buf);
    
    if (IS_ERR(packet))
        return PTR_ERR(packet);

    *res_buf = comm_process(packet->command, packet->content, &res_comm_buf, &res_comm_buflen);
    kzfree(packet);*/

    //enc_decode(req_buf, req_buflen, &mid_buf, &mid_buflen);
}
