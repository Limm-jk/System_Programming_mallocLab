/*
 * mm-explicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201602057	 
 * @name : 임준규
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define HDRSIZE 4
#define FTRSIZE 4
#define WSIZE 4 //word 크기
#define DSIZE 8 //double word 크기 
#define CHUNKSIZE (1 << 12) //초기 힙 크기 설정
#define OVERHEAD 8 //header footer합

#define MAX(x,y) ( (x) > (y) ? (x) : (y) ) //x,y중 큰값
#define MIN(x,y) ( (x) < (y) ? (x) : (y) ) //x,y중 작은값

#define PACK(size, alloc) ((unsigned)((size) | (alloc))) // size와 alloc을 묶음

#define GET(p) (*(unsigned int *) (p)) // p의 위치에서 word크기의 값 읽음
#define PUT(p, val) (*(unsigned int *)(p) = (unsigned)(val)) //p의 위치에 word크기의 val값 쓴다
#define GET8(p) (*(unsigned long *) (p)) // p의 위치에서 word크기의 값 읽음
#define PUT8(p, val) (*(unsigned long *)(p) = (unsigned long)(val)) //p의 위치에 word크기의 val값 쓴다

#define GET_SIZE(p) (GET(p) & ~0x7) // header blocksize읽음
#define GET_ALLOC(p) (GET(p) & 0x1) // p위치의 word를 읽고 하위 한비트 반환(할당여부 0 == NO)

#define HDRP(bp) ((char *)(bp) - WSIZE) // bp의 header주소계산
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) //bp의 footer주소계산

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *) (bp) - WSIZE)))//bp를 이용하여 다음 block의 주소계산
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *) (bp) - DSIZE))) // bp를 이용하여 이전 bock의 주소계산

#define NEXT_FREEP(bp) ((char *)(bp))
#define NEXT_FREEP(bp) ((char *)(bp) + WSIZE)

#define NEXT_FREE_BLKP(bp) ((char *)GET8((char *)(bp)))//bp를 이용하여 다음 block의 주소계산
#define PREV_FREE_BLKP(bp) ((char *)GET8((char *)(bp) + WSIZE)) // bp를 이용하여 이전 bock의 주소계산

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)


static char* h_ptr;
static char* heap_start;
static char* epilogue;

void* find_fit(size_t asize); // Free 블럭에 할당을 위해 first fit과 best fit 수행
void place(size_t csize, size_t asize); // Free 블럭에 할당한다. 공간이 많이 남으면 split를 수행//bestfit
void extend_heap(size_t asize); // 할당될 공간이 부족할 경우 힙 확장
void coalesce(void* bp); // Free 블럭을 조건에 맞게 연결(free의 4가지 case)

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	if ((h_ptr = mem_sbrk(DSIZE + 4 * HDRSIZE)) == NULL)
		return -1;
	heap_start = h_ptr;

	PUT(h_ptr + DSIZE, 0);
	PUT(h_ptr + DSIZE + HDRSIZE, PACK(OVERHEAD, 1));
	PUT(h_ptr + DSIZE + HDRSIZE + FTRSIZE, PACK(OVERHEAD, 1));
	PUT(h_ptr + DSIZE + 2 * HDRSIZE + FTRSIZE, PACK(0, 1));

	h_ptr += DSIZE + DSIZE;
	epilogue = h_ptr + HDRSIZE;

	if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
		return -1;
}

/*
 * malloc
 */
void *malloc (size_t size) {
    return NULL;
}

/*
 * free
 */
void free (void *ptr) {
    if(!ptr) return;
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
    return NULL;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    return NULL;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
