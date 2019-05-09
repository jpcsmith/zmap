#include <stdint.h>

typedef struct {
	char type[4];
	int value_len;
	void *value;
} tag_info;

/**
 * Frees memory allocated within a tag info and sets the relevant pointers to
 * NULL.
 */
void free_tag_info(tag_info *tag);

/**
 * Create a tag info for the tag with value `value`. The value is copied. It
 * can be NULL. The data in the tag_info must be freed with free_tag_info()
 */
tag_info make_raw_tag(const void *type, const void *value, int value_len);

/**
 * Creates and returns a tag info for 32bit int tag. The data stored within the
 * tag_info must be freed with free_tag_info().
 */
tag_info make_uint32_tag(const void *type, uint32_t value);

/**
 * Create a tag with the type "PAD" and 0x2d to the indicated length being the
 * data.
 */
tag_info make_pad_tag(int length);

/**
 * Pack the provided tags into the buffer. Return the number of bytes written
 * to the buffer.
 */
int pack_tags(const tag_info *tags, int num_tags, void *buffer, int buffer_len);

/**
 * Returns the number of bytes written.
 */
int write_chlo_stream_frame(void *buffer, int buffer_len, const tag_info *tags,
			    int num_tags);

/**
 * Returns a random connection id already placed in network order. The 4
 * high-order bytes of the connection ID will be the ASCII chars "SCAN".
 */
uint64_t random_connection_id();
