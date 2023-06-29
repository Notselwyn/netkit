#ifndef TYPES_H
#define TYPES_H

#define GET_REF(var) ({ ((ref_count_t*)var)->ref_count += 1; })
#define PUT_REF(var) ({ \
    ((ref_count_t*)var)->ref_count -= 1; \
    if (((ref_count_t*)var)->ref_count == 0) \
        ((ref_count_t*)var)->destructor((void*)var); \
})

typedef struct ref_count {
    u8 ref_count;
    int (*destructor)(void*);
} ref_count_t;

#endif