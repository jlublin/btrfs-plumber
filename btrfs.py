from construct import *

SUPERBLOCK_MAGIC = b'_BHRfS_M'
SUPERBLOCK_OFFSETS = [0x1_0000, 0x400_0000, 0x40_0000_0000, 0x4_0000_0000_0000]
CSUM_SIZE = 32
FSID_SIZE = 16
UUID_SIZE = 16

CHUNK_ITEM_KEY = 228

Key = Struct(
	"objectid" / Int64ul,
	"type" / Int8ul,
	"offset" / Int64ul
	) # 17 bytes

Stripe = Struct(
	"devid" / Int64ul,
	"offset" / Int64ul,
	"dev_uuid" / Byte[UUID_SIZE]
	) # 32 bytes

Chunk = Struct(
	"length" / Int64ul,
	"owner" / Int64ul,
	"stripe_len" / Int64ul,
	"type" / Int64ul,
	"io_align" / Int32ul,
	"io_width" / Int32ul,
	"sector_size" / Int32ul,
	"num_stripes" / Int16ul,
	"sub_stripes" / Int16ul,
	"stripes" / Stripe[this.num_stripes]
	) # 48 bytes + stripes

DevItem = Struct(
	"devid" / Int64ul,
	"total_bytes" / Int64ul,
	"bytes_used" / Int64ul,
	"io_align" / Int32ul,
	"io_width" / Int32ul,
	"sector_size" / Int32ul,
	"type" / Int64ul,
	"generation" / Int64ul,
	"start_offset" / Int64ul,
	"dev_group" / Int32ul,
	"seek_speed" / Int8ul,
	"bandwidth" / Int8ul,
	"uuid" / Byte[16],
	"fsid" / Byte[FSID_SIZE],
	) # 98 bytes

Superblock = Struct(
	"csum" / Byte[CSUM_SIZE],
	"fsid" / Byte[FSID_SIZE],
	"bytenr" / Int64ul,
	"flags" / Int64ul,
	"magic" / Byte[8],
	"generation" / Int64ul,
	"root" / Int64ul,
	"chunk_root" / Int64ul,
	"log_root" / Int64ul,
	"log_rot_transid" / Int64ul,
	"total_bytes" / Int64ul,
	"bytes_used" / Int64ul,
	"root_dir_objectid" / Int64ul,
	"num_devices" / Int64ul,
	"sector_size" / Int32ul,
	"node_size" / Int32ul,
	"leafsize" / Int32ul,
	"stripesize" / Int32ul,
	"sys_chunk_array_size" / Int32ul,
	"chunk_root_generation" / Int64ul,
	"compat_flags" / Int64ul,
	"compat_ro_flags" / Int64ul,
	"incompat_flags" / Int64ul,
	"csum_type" / Int16ul,
	"root_level" / Int8ul,
	"chunk_root_level" / Int8ul,
	"log_root_level" / Int8ul,
	"dev_item" / DevItem,
	"label" / Byte[256],
	"cache_generation" / Int64ul,
	"uuid_tree_generation" / Int64ul,
	"metadata_uuid" / Byte[16],
	"_reserved" / Byte[224],
	"sys_chunk_array" / Byte[2048],
	"root_backups" / Byte[672]
	) # 4096 bytes
# sys_chunk_array: key | chunk | stripe1 | stripe2... | key ...

Header = Struct(
	"csum" / Byte[CSUM_SIZE],
	"fsid" / Byte[FSID_SIZE],
	"bytenr" / Int64ul,
	"flags" / Int64ul,
	"chunk_tree_uuid" / Byte[UUID_SIZE],
	"generation" / Int64ul,
	"owner" / Int64ul,
	"nritems" / Int32ul,
	"level" / Int8ul
	)

KeyPtr = Struct(
	"key" / Key,
	"blockptr" / Int64ul,
	"generation" / Int64ul
	)

Item = Struct(
	"key" / Int64ul,
	"offset" / Int32ul,
	"size" / Int32ul
	)

# Filesystem root

DirItem = Struct(
	"location" / Key,
	"transid" / Int64ul,
	"data_len" / Int16ul,
	"name_len" / Int16ul,
	"type" / Int8ul
	)

InodeRef = Struct(
	"index" / Int64ul,
	"name_len" / Int16ul
	)


def bootstrap_chunk_tree(superblock):

	chunk_tree_cache = {} # (Logical, size) to stripe [[devid, offset]...]
	offset = 0
	chunk_array = bytes(superblock.sys_chunk_array)

	while(offset < superblock.sys_chunk_array_size):

		key = Key.parse(chunk_array[offset:])

		# sys_chunk_array should only contain chunk_items

		if(key.type != CHUNK_ITEM_KEY):
			print('Invalid key {} at offset {} in sys_chunk_array'.format(
				key.type, offset))
			return None

		offset += Key.sizeof()

		chunk = Chunk.parse(chunk_array[offset:])

		if(chunk.num_stripes == 0):
			print('Invalid number of stripes in chunk (0)')
			return None

		chunk_tree_cache[(key.offset, chunk.length)] = \
			[(x.devid, x.offset) for x in chunk.stripes]

		offset += Chunk.sizeof(chunk)

	return chunk_tree_cache


def logical_to_physical(cache, logical):
	'''logical -> (size, [[devid, offset]...]'''

	for cache_logical, size in cache:
		if(logical >= cache_logical and logical < cache_logical + size):
			return (size,
				[(x[0], x[1] + logical - cache_logical) for x in cache[(cache_logical, size)]])

	return None



def read_chunk_tree_root(dev, chunk_root_logical, cache):

	physical = logical_to_physical(cache, chunk_root_logical)
	print(cache)
	print(chunk_root_logical)
	print(physical)


if(__name__ == '__main__'):
	dev1 = open('btrfs_test1.img', 'rb')

	dev1.seek(SUPERBLOCK_OFFSETS[0])
	superblock = Superblock.parse_stream(dev1)

	chunk_tree_cache = bootstrap_chunk_tree(superblock)

	chunk_tree_root = read_chunk_tree_root(dev1, superblock.chunk_root, chunk_tree_cache)

	dev1.close()
