#ifndef TG_TRUSTED_ALLOC_H
#define TG_TRUSTED_ALLOC_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

//#include "list_allocator.h"

#include "tg_common_alloc.h"

struct TG_free_list_t__ TG_ALLOC_HEAD__;
const int TG_ALLOC_MIN_SIZE__ = 512; //2*sizeof(struct TG_free_list_t__);

void *TG_LIST_ALLOCATE__(size_t req_size)
{
  size_t sz = ALIGN(req_size);
  size_t size = sz + sizeof(struct TG_free_list_t__);
  if(size < TG_ALLOC_MIN_SIZE__)
    size = TG_ALLOC_MIN_SIZE__;
  flp cur = TG_ALLOC_HEAD__.next;
  flp prev = &TG_ALLOC_HEAD__;
  flp split;

  // Walk the list until we find a block large enough
  // if the block is x bytes larger than we need and the left over will
  // be at least min-size large, break it up
#if LIST_ALLOCATOR_DEBUG > 1
  if(lad_int > 1) {
    fprintf(stderr,"~~~Request size: 0x%lx  Total size: 0x%lx\n", req_size, size);
  }
#endif
  while( cur->size < size )
  {
#if LIST_ALLOCATOR_DEBUG > 1
    if(lad_int > 1) {
      fprintf(stderr,"~~~~~Walking list and skipping chunk sized: 0x%lx\n", cur->size);
    }
#endif

    prev = cur;
    cur = cur->next;
    // assert(cur && "We have no block large enough to satisfy allocation");
    if(cur == 0) {
      exit(-1);
    }
  }

  // Cur now points to a block big enough to at least handle this request,
  // check if we have enough room to split the block up
  if( ((cur->size - size) > TG_ALLOC_MIN_SIZE__) )
  {
    // Get the address of the split block
    // Add some padding so we don't create a ton of little blocks
    size_t addr = (size_t)cur + size;
    split = (flp)addr;
#if LIST_ALLOCATOR_DEBUG > 1
    if(lad_int > 1)
    {
      fprintf(stderr,"~~~Splitting block in free list\n");
      fprintf(stderr,"~~~~~Addr: %p BlockSize: 0x%lx RequestSize: 0x%lx NewAddr: %p\n",
          cur, cur->size, size, split);
    }
#endif
    // Fix all our sizes and pointers
    prev->next = split;
    split->size = cur->size - size;
    split->next = cur->next;

    cur->size = size;
  } else {
    // We don't have enough room to split the block, but still need
    // to take it off the free list
    prev->next = cur->next;
  }

  cur->next = NULL;

#if LIST_ALLOCATOR_DEBUG
  if(lad_int) {
    cur->next = (struct TG_free_list_t__ *)0xDEADBEEF; // for debugging free
    fprintf(stderr,"~ALLOCATING ADDRESS: %p PTR: %p SIZE: %lx\n",cur+1,cur,cur->size);
  }
#endif

  // Skip past metadata and return data section
  cur++;
  return cur;
}

void TG_LIST_FREE__(void *arg)
{
  flp ptr = (flp)arg;
  // The passed in pointer is actually pointing to the data not metadata
  // so back it up to point to metadata
  ptr--;

#if LIST_ALLOCATOR_DEBUG
  if(lad_int)
  {
    fprintf(stderr,"~~Freeing block at: %p of size: %lu (0x%lx)\t\tptr: %p\n",
        ptr,ptr->size,ptr->size,ptr->next);
  }
#endif

  // Add this object to free list
  ptr->next = TG_ALLOC_HEAD__.next;
  TG_ALLOC_HEAD__.next = ptr;
}

size_t TG_LIST_GET_SIZE__(void *arg)
{
  flp ptr = (flp)arg;
  ptr--;
  return ptr->size - sizeof(struct TG_free_list_t__);
}


void* bound_malloc(size_t size)
{
  void *ret = TG_LIST_ALLOCATE__(size);
  return ret;
}

void bound_free(void* ptr)
{
  TG_LIST_FREE__(ptr);
}

void* bound_calloc(size_t num, size_t size)
{
  void* ptr = bound_malloc(num*size);
  memset(ptr, '\0', num*size);
  return ptr;
}

void* bound_realloc(void* ptr, size_t size)
{
  if (ptr == NULL)
  {
    /*
       In case that ptr is a null pointer, the function behaves like malloc, assigning
       a new block of size bytes and returning a pointer to its beginning.
     */
    return bound_malloc(size);
  }

  if (size == 0)
  {
    /*
       If size is zero, the return value depends on the particular library
       implementation (it may or may not be a null pointer), but the returned
       pointer shall not be used to dereference an object in any case.
     */
    bound_free(ptr);
    return NULL;
  }

  size_t old_sz = TG_LIST_GET_SIZE__(ptr);
  if (old_sz >= size)
  {
    // Don't care if it is smaller
    return ptr;
  }
  else
  {
    void *new_ptr = bound_malloc(size);
    memcpy(new_ptr, ptr, old_sz);
    bound_free(ptr);
    return new_ptr;
  }
}



#endif //TG_TRUSTED_ALLOC_H
