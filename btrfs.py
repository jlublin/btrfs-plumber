import io
from construct import *
import crc32c

# TODO: verify that we do not use RAID0/5/6. RAID1 is OK
# TODO: only CRC32 checksums

SUPERBLOCK_MAGIC = b'_BHRfS_M'
SUPERBLOCK_OFFSETS = [0x1_0000, 0x400_0000, 0x40_0000_0000, 0x4_0000_0000_0000]
CSUM_SIZE = 32
FSID_SIZE = 16
UUID_SIZE = 16

INODE_ITEM_KEY = 1
INODE_REF_KEY = 12
DIR_ITEM_KEY = 84
DIR_INDEX_KEY = 96
EXTENT_DATA_KEY = 108
EXTENT_CSUM_KEY = 128
ROOT_ITEM_KEY = 132
ROOT_BACKREF_KEY = 144
ROOT_REF_KEY = 156
EXTENT_ITEM_KEY = 168
CHUNK_ITEM_KEY = 228

ROOT_TREE_OBJECTID = 1
EXTENT_TREE_OBJECTID = 2
CHUNK_TREE_OBJECTID = 3
DEV_TREE_OBJECTID = 4
FS_TREE_OBJECTID = 5
ROOT_TREE_DIR_OBJECTID = 6
CSUM_TREE_OBJECTID = 7
QUOTA_TREE_OBJECTID = 8
UUID_TREE_OBJECTID = 9
FREE_SPACE_TREE_OBJECTID = 10

EXTENT_CSUM_OBJECTID = 2**64 - 10

FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7
FT_XATTR = 8

FILE_EXTENT_INLINE = 0
FILE_EXTENT_REG = 1
FILE_EXTENT_PREALLOC = 2

COMPRESS_NONE = 0
COMPRESS_ZLIB = 1
COMPRESS_LZO = 2
COMPRESS_ZSTD = 3

Key = Struct(
	"objectid" / Int64ul,
	"type" / Int8ul,
	"offset" / Int64ul
	) # 17 bytes

Stripe = Struct(
	"devid" / Int64ul,
	"offset" / Int64ul,
	"dev_uuid" / Bytes(UUID_SIZE)
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
	"uuid" / Bytes(16),
	"fsid" / Bytes(FSID_SIZE),
	) # 98 bytes

Superblock = Struct(
	"csum" / Bytes(CSUM_SIZE),
	"fsid" / Bytes(FSID_SIZE),
	"bytenr" / Int64ul,
	"flags" / Int64ul,
	"magic" / Bytes(8),
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
	"label" / Bytes(256),
	"cache_generation" / Int64ul,
	"uuid_tree_generation" / Int64ul,
	"metadata_uuid" / Bytes(16),
	"_reserved" / Bytes(224),
	"sys_chunk_array" / Bytes(2048),
	"root_backups" / Bytes(672)
	) # 4096 bytes

Header = Struct(
	"csum" / Bytes(CSUM_SIZE),
	"fsid" / Bytes(FSID_SIZE),
	"bytenr" / Int64ul,
	"flags" / Int64ul,
	"chunk_tree_uuid" / Bytes(UUID_SIZE),
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
	"key" / Key,
	"offset" / Int32ul,
	"size" / Int32ul
	)

# Filesystem root

DirItem = Struct(
	"location" / Key,
	"transid" / Int64ul,
	"data_len" / Int16ul,
	"name_len" / Int16ul,
	"type" / Int8ul,
	"name" / Bytes(this.name_len) # TODO, only if not XATTRS...
	)

DirIndex = DirItem

InodeRef = Struct(
	"index" / Int64ul,
	"name_len" / Int16ul,
	"name" / Bytes(this.name_len)
	)

Timespec = Struct(
	"sec" / Int64ul,
	"nsec" / Int32ul
	)

InodeItem = Struct(
	"generation" / Int64ul,
	"transid" / Int64ul,
	"size" / Int64ul,
	"nbytes" / Int64ul,
	"block_group" / Int64ul,
	"nlink" / Int32ul,
	"uid" / Int32ul,
	"gid" / Int32ul,
	"mode" / Int32ul,
	"rdev" / Int64ul,
	"flags" / Int64ul,
	"sequence" / Int64ul,
	"_reserved" / Int64ul[4],
	"atime" / Timespec,
	"ctime" / Timespec,
	"mtime" / Timespec,
	"otime" / Timespec
	)

FileExtentItem = Struct(
	"generation" / Int64ul,
	"ram_bytes" / Int64ul,
	"compression" / Int8ul,
	"encryption" / Int8ul,
	"other_encoding" / Int16ul,
	"type" / Int8ul,
	"data" / If(this.type == FILE_EXTENT_INLINE, GreedyBytes),
	"disk_bytenr" / If(this.type != FILE_EXTENT_INLINE, Int64ul),
	"disk_num_bytes" / If(this.type != FILE_EXTENT_INLINE, Int64ul),
	"offset" / If(this.type != FILE_EXTENT_INLINE, Int64ul),
	"num_bytes" / If(this.type != FILE_EXTENT_INLINE, Int64ul)
	)

CsumItem = Struct(
	"csum" / GreedyRange(Int32ul)
	)

ExtentItem = Struct(
	"refs" / Int64ul,
	"generation" / Int64ul,
	"flags" / Int64ul
	)

ExtentInlineRef = Struct(
	"type" / Int8ul,
	"offset" / Int64ul
	)

ExtentDataRef = Struct(
	"root" / Int64ul,
	"objectid" / Int64ul,
	"offset" / Int64ul,
	"count" / Int32ul
	)

RootItem = Struct(
	"inode" / InodeItem,
	"generation" / Int64ul,
	"root_dirid" / Int64ul,
	"bytenr" / Int64ul,
	"byte_limit" / Int64ul,
	"bytes_used" / Int64ul,
	"last_snapshot" / Int64ul,
	"flags" / Int64ul,
	"refs" / Int32ul,
	"drop_progress" / Key,
	"drop_level" / Int8ul,
	"level" / Int8ul,
	"generation_v2" / Int64ul,
	"uuid" / Bytes(UUID_SIZE),
	"parent_uuid" / Bytes(UUID_SIZE),
	"received_uuid" / Bytes(UUID_SIZE),
	"ctransid" / Int64ul,
	"otransid" / Int64ul,
	"stransid" / Int64ul,
	"rtransid" / Int64ul,
	"ctime" / Timespec,
	"otime" / Timespec,
	"stime" / Timespec,
	"rtime" / Timespec,
	"_reserved" / Int64ul[8]
	)

RootBackRef = Struct(
	"dirid" / Int64ul,
	"sequence" / Int64ul,
	"name_len" / Int16ul,
	"name" / Bytes(this.name_len)
	)

RootRef = RootBackRef

def compare_keys(key1, key2):
	# -> -1 (key1 < key2), 0 (equal) or 1 (key1 > key2)

	full_key1 = (key1.objectid << 72) + (key1.type << 64) + key1.offset
	full_key2 = (key2.objectid << 72) + (key2.type << 64) + key2.offset

	return full_key1 - full_key2


def compare_csum_keys(logical, csum_item):
	# -> -1 (key1 < key2), 0 (equal) or 1 (key1 > key2)

	csum_start = csum_item.key.offset
	csum_end = csum_start + (csum_item.size//4) * 4096

	if(logical < csum_start):
		return -1

	elif(logical >= csum_end):
		return 1

	else:
		return 0


class LogicalMap:

	def __init__(self, logical, size, maps):
		self.logical = logical
		self.size = size
		self.maps = maps


class BtrfsItem:

	def __init__(self, keyobj, data, node, index):

		self.key = keyobj.key
		self.offset = keyobj.offset
		self.size = keyobj.size

		self.item = keyobj
		self.data = data

		self.node = node
		self.index = index


	def next(self):
		return self.node.next(self.index)


class BtrfsNode:

	def __init__(self, fs, logical, parent=None, index=None):


		self.fs = fs
		self.data = self.fs.read_node(logical)
		self.logical = logical
		self.parent = parent
		self.index = index

		stream = io.BytesIO(self.data)

		self.header = Header.parse_stream(stream)

		self.data_root = stream.tell() + self.fs.physical(self.logical)[1] # TODO: parse from self.data
		self.num_items = self.header.nritems

		self.is_leaf = (self.header.level == 0)

		# keyobjs may be either items (leafs) or keyptrs (internal nodes)
		if(self.is_leaf):
			self.keyobjs = Item[self.num_items].parse_stream(stream)

		else:
			self.keyobjs = KeyPtr[self.num_items].parse_stream(stream)

		# Parse items? No, takes unessecary time, store data


	def first_key(self):
		if(self.is_leaf):
			keyobj = self.keyobjs[0]
			data = self.fs.parse_item(keyobj, self.data_root)
			return BtrfsItem(keyobj, data, self, 0)

		else:
			node = BtrfsNode(self.fs, self.keyobjs[0].blockptr, self, 0)
			return node.first_key()


	def find_all(self):

		item = self.first_key()

		if(item):
			yield item
		else:
			return

		while True:
			item = item.next()
			if(item):
				yield item
			else:
				return


	def find(self, key):

		# Binary search in node keys
		lower = 0
		upper = len(self.keyobjs) - 1

		while True:
			i = (lower + upper)//2

			c = compare_keys(key, self.keyobjs[i].key)

			if(c == 0):
				if(self.is_leaf):
					keyobj = self.keyobjs[i]
					data = self.fs.parse_item(keyobj, self.data_root)
					return BtrfsItem(keyobj, data, self, i)
				else:
					node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
					return node.find(key)

			elif(lower == upper):
				if(self.is_leaf): # Key not found
					return None

				else:
					# keyobjs are KeyPtrs
					if(i == 0 and c < 0): # Key not found
						return None

					if(c < 0):
						if(i == 0):
							return None

						node = BtrfsNode(self.fs, self.keyobjs[i-1].blockptr, self, i-1)
						return node.find(key)


					else:
						node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
						return node.find(key)

			elif(c < 0):
				if(i == 0):
					return None

				upper = i - 1

			else:
				lower = i + 1


	def find_objectid(self, objectid):
		# Return first objectid

		# Binary search in node keys
		lower = 0
		upper = len(self.keyobjs) - 1

		while True:
			i = (lower + upper)//2

			c = objectid - self.keyobjs[i].key.objectid

			if(c == 0):
				if(self.is_leaf):
					# Look left, we want the first objectid
					while(True):
						if(i == 0):
							break

						if(self.keyobjs[i-1].key.objectid == objectid):
							i -= 1
						else:
							break


					keyobj = self.keyobjs[i]
					data = self.fs.parse_item(keyobj, self.data_root)
					return BtrfsItem(keyobj, data, self, i)

				else:
					# Look left, we want the first objectid
					while True:
						if(i == 0):
							break

						if(self.keyobjs[i-1].key.objectid == objectid):
							i -= 1
						else:
							break

					node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
					return node.find_objectid(objectid)

			elif(lower == upper):
				if(self.is_leaf): # Key not found
					return None

				else:
					# keyobjs are KeyPtrs
					if(i == 0 and c < 0): # Key not found
						return None

					if(c < 0):
						if(i == 0):
							return None

						node = BtrfsNode(self.fs, self.keyobjs[i-1].blockptr, self, i-1)
						return node.find_objectid(objectid)


					else:
						node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
						return node.find_objectid(objectid)

			elif(c < 0):
				if(i == 0):
					return None

				upper = i - 1

			else:
				lower = i + 1


	def find_csum(self, logical):

		# Return csum containing logical
		# We want the last offset <= logical, replace compare_keys to reflect this

		# Binary search in node keys
		lower = 0
		upper = len(self.keyobjs) - 1

		key = Container(objectid=EXTENT_CSUM_OBJECTID,
		                type=EXTENT_CSUM_KEY,
		                offset=logical)

		while True:
			i = (lower + upper)//2


			if(self.is_leaf):
				keyobj = self.keyobjs[i]
				data = self.fs.parse_item(keyobj, self.data_root)
				item = BtrfsItem(keyobj, data, self, i)

				c = compare_csum_keys(logical, item)

			else:
				c = compare_keys(key, self.keyobjs[i].key)


			if(c == 0):
				if(self.is_leaf):
					keyobj = self.keyobjs[i]
					data = self.fs.parse_item(keyobj, self.data_root)
					return BtrfsItem(keyobj, data, self, i)
				else:
					node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
					return node.find_csum(logical)

			elif(lower == upper):
				if(self.is_leaf): # Key not found
					return None

				else:
					# keyobjs are KeyPtrs
					if(i == 0 and c < 0): # Key not found
						return None

					if(c < 0):
						if(i == 0):
							return None

						node = BtrfsNode(self.fs, self.keyobjs[i-1].blockptr, self, i-1)
						return node.find_csum(logical)

					else:
						node = BtrfsNode(self.fs, self.keyobjs[i].blockptr, self, i)
						return node.find_csum(logical)

			elif(c < 0):
				if(i == 0):
					return None

				upper = i - 1

			else:
				lower = i + 1


	def find_all_csum(self, logical):

		item = self.find_csum(logical)

		if(item):
			yield item
		else:
			return

		while True:
			item = item.next()

			if(item):
				if(item.key.objectid == EXTENT_CSUM_OBJECTID and
				   item.key.type == EXTENT_CSUM_KEY):
					yield item
				else:
					continue

			else:
				return


	# TODO with generic generator? (next_generator?)
	def find_all_objectid(self, objectid):

		item = self.find_objectid(objectid)

		if(item):
			yield item
		else:
			return

		while True:
			item = item.next()
			if(item and item.key.objectid == objectid):
				yield item
			else:
				return


	def next(self, index): # TODO: add filtering?

		if(self.is_leaf):
			if(index < self.num_items - 1):
				keyobj = self.keyobjs[index+1]
				data = self.fs.parse_item(keyobj, self.data_root)
				return BtrfsItem(keyobj, data, self, index+1)

			else:
				if(not self.parent):
					return None

				return self.parent.next(self.index)

		else:
			if(index < self.num_items - 1):
				node = BtrfsNode(self.fs, self.keyobjs[index+1].blockptr, self, index+1)
				return node.first_key()

			else:
				if(not self.parent):
					return None

				self.parent.next(self.index)

class Btrfs:

	def __init__(self, devices):
		self.chunk_tree_cache = {}
		self.subvolume_trees = {}

		self.dev = [open(dev, 'rb') for dev in devices]
		self.dev[0].seek(SUPERBLOCK_OFFSETS[0])
		self.superblock = Superblock.parse_stream(self.dev[0])
		self.node_size = self.superblock.node_size

		self.chunk_tree_cache = self.bootstrap_chunk_tree()

		self.read_chunk_tree(self.superblock.chunk_root)

		self.read_tree_roots()


	def bootstrap_chunk_tree(self):

		chunk_tree_cache = {} # (Logical, size) to stripe [[devid, offset]...]
		offset = 0
		chunk_array = bytes(self.superblock.sys_chunk_array)

		while(offset < self.superblock.sys_chunk_array_size):

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


	def logical_to_physical(self, logical):
		'''logical -> (size, [[devid, offset]...]'''

		for cache_logical, size in self.chunk_tree_cache:
			if(logical >= cache_logical and logical < cache_logical + size):
				return (size,
					[(x[0], x[1] + logical - cache_logical) for x in self.chunk_tree_cache[(cache_logical, size)]])

		return None


	def physical(self, logical, size=0):
		'''logical -> [physical], verifies size'''

		for cache_logical, chunk_size in self.chunk_tree_cache:
			if(logical >= cache_logical and logical < cache_logical + chunk_size):

#				print(logical, cache_logical, chunk_size)

				if(logical + size > cache_logical + chunk_size):
					raise Exception('Logical addressing does not fit in chunk')

#				print(self.chunk_tree_cache[(cache_logical, chunk_size)])
				m = { devid: x + logical - cache_logical
				      for devid, x in self.chunk_tree_cache[(cache_logical, chunk_size)].items() }
				return m


		return KeyError('No such logical address found in chunk tree')


# TODO: a read which checks size etc..? read(struct, logical, verify=False)?


	def read_chunk_tree(self, chunk_root_logical):

		physical_map = self.logical_to_physical(chunk_root_logical)

		self.dev[0].seek(physical_map[1][0][1])
		chunk_root_header = Header.parse_stream(self.dev[0])
		data_root = self.dev[0].tell()

		if(chunk_root_header.level == 0):
			items = Item[chunk_root_header.nritems].parse_stream(self.dev[0])
			for item in items:

				if(item.key.type != CHUNK_ITEM_KEY):
					continue


				self.dev[0].seek(data_root + item.offset)
				chunk = Chunk.parse_stream(self.dev[0])

#				print(item)
#				print(chunk)

				self.chunk_tree_cache[(item.key.offset, chunk.length)] = \
					{x.devid: x.offset for x in chunk.stripes}

		else:
			key_ptrs = KeyPtr[chunk_root_header.nritems].parse_stream(self.dev[0])
			for key_ptr in key_ptrs:
				read_chunk_tree(key_ptr.blockptr)


	def read_tree_roots(self):

		root_addr = self.physical(self.superblock.root)

		self.dev[0].seek(root_addr[1])
		root_tree_root_header = Header.parse_stream(self.dev[0])
		data_root = self.dev[0].tell()

		if(root_tree_root_header.level != 0):
			raise Exception('Root tree root is not a leaf node')

		items = Item[root_tree_root_header.nritems].parse_stream(self.dev[0])

		for item in items:

#			print('Root tree item:', item.key.type, item.key.objectid)

			if(item.key.type == ROOT_ITEM_KEY and
			   item.key.objectid == FS_TREE_OBJECTID):

				self.fs_tree = self.parse_item(item, data_root)

			elif(item.key.type == ROOT_ITEM_KEY and
			     item.key.objectid == CSUM_TREE_OBJECTID):

				self.csum_tree = self.parse_item(item, data_root)

			elif(item.key.type == ROOT_ITEM_KEY and
			     item.key.objectid >= 256):

				self.subvolume_trees[item.key.objectid] = self.parse_item(item, data_root)

			elif(item.key.type == DIR_ITEM_KEY and
			     item.key.objectid == ROOT_TREE_DIR_OBJECTID):

				dir_item = self.parse_item(item, data_root)

			elif(item.key.type == ROOT_ITEM_KEY and
			     item.key.objectid == EXTENT_TREE_OBJECTID):

				self.extent_tree = self.parse_item(item, data_root)

			else:
				continue


	def read_node(self, logical):

		node_addr = self.physical(logical)
		self.dev[0].seek(node_addr[1])

		return self.dev[0].read(self.node_size)


	def find_range(self, node_logical, key_start, key_end, filter= lambda x: True):
		pass # TODO make find_all use this with full range?


	def find_all(self, node_logical, filter=lambda x: True):
		# TODO: filter_objectid, filter_type, filter_offset?
		#       or lambda?
		'''Generator which finds all items in a node (full tree or part of tree)'''

		node_addr = self.physical(node_logical)

		self.dev[0].seek(node_addr[1])
		node_header = Header.parse_stream(self.dev[0])
		data_root = self.dev[0].tell()

		if(node_header.level == 0):
			items = Item[node_header.nritems].parse_stream(self.dev[0])

			for item in items:

				if(not filter(item.key)):
					continue

				payload = self.parse_item(item, data_root)

				yield item, payload

		else:
			key_ptrs = KeyPtr[node_header.nritems].parse_stream(self.dev[0])
			for key_ptr in key_ptrs:
				yield from self.find_all(key_ptr.blockptr, filter)


	def parse_item(self, item, data_root):

		if(item.key.type == DIR_ITEM_KEY):
			type = DirItem

		elif(item.key.type == DIR_INDEX_KEY):
			type = DirIndex

		elif(item.key.type == INODE_REF_KEY):
			type = InodeRef

		elif(item.key.type == INODE_ITEM_KEY):
			type = InodeItem

		elif(item.key.type == ROOT_ITEM_KEY):
			type = RootItem

		elif(item.key.type == ROOT_REF_KEY):
			type = RootRef

		elif(item.key.type == ROOT_BACKREF_KEY):
			type = RootBackRef

		elif(item.key.type == EXTENT_DATA_KEY):
			type = FileExtentItem

		elif(item.key.type == EXTENT_CSUM_KEY):
			type = CsumItem

		else:
			raise Exception('Unknown type {} passed to parse_item()'.format(
				item.key.type))

		self.dev[0].seek(data_root + item.offset)
		payload_data = self.dev[0].read(item.size)
		payload = type.parse(payload_data)

		return payload


	def find_key(self, root_node, key, nodes=()):
		# Nodes is list of nodes logical addresses with root at 0,
		# node_0, node_1, ..., node_x
		# or root node
		# Nodes should add index? ((node1, 5), (node2, -1))
		# root, key, nodes, indices

		# Perform binary search in each node until found
		# TODO: return full path of nodes? -> item, payload, nodepath?
		#       then add find next to get a find_range?

		node = BtrfsNode(self, root_node, None, 0)
		return node.find(key)


	def find_path(self, root_inode, path):
		# TODO:
		# Where do I find root? use constant 256 for start (is this always true?)
		# also add which tree (fs/subvolume)?

		node = BtrfsNode(self, self.fs_tree.bytenr)
		items = node.find_all_objectid(root_inode)

		for item in items:

			if(item.key.type != DIR_INDEX_KEY):
				continue

			if(item.data.name == path[0]):

				# TODO: is this accessible by next/prev?
				inode_item = node.find(item.data.location)

				if(len(path) > 1):
					return self.find_path(inode_item.key.objectid, path[1:])

				else:
					return inode_item


	def find_checksums(self, logical_start, logical_end):

		if(logical_start & 0xfff != 0):
			raise Exception('logical_start not a multiple of 4096')

		if(logical_end & 0xfff != 0):
			raise Exception('logical_end not a multiple of 4096')

		csums = []
		current = logical_start

		node = BtrfsNode(self, self.csum_tree.bytenr)
		items = node.find_all_csum(logical_start)

		for item in items:
			csum_start = item.key.offset
			csum_end = csum_start + (item.size//4) * 4096

			# If checksums were missing then break loop
			if(csum_start > current):
				break

			while(current >= csum_start and current < csum_end):
				pos = (current - csum_start) // 4096
				csums.append(item.data.csum[pos])

				current += 4096

				if(current == logical_end):
					break

		if(current != logical_end):
			raise Exception('Could not find all checksums!')

		return csums


	def list_files(self):

		node = BtrfsNode(btrfs, btrfs.fs_tree.bytenr)
		items = node.find_all()

		for item in node.find_all():

			print('{}\t{}\t{}'.format(item.key.objectid, item.key.type, item.key.offset))

			if(item.key.type == DIR_ITEM_KEY):

				if(item.data.type == FT_REG_FILE):
					print('Is file', item.data.name, item.key.objectid)

				elif(item.data.type == FT_DIR):
					print('Dir:', item.data.name, item.key.objectid)

			if(item.key.type == DIR_INDEX_KEY):

				print('Index:', item.data.name)

#			if(item.key.type == INODE_ITEM_KEY):
#				print('Inode item:', item.data)

			if(item.key.type == INODE_REF_KEY):
				print('Inode ref:', item.data.name)


if(__name__ == '__main__'):
	import getopt
	import sys

	shortopts = ''
	longopts = []
	optslist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)

	btrfs = Btrfs(['btrfs_test1.img', 'btrfs_test2.img'])

	# read <item-type> <key>
	# read inode <inode-number>
	# read csum <logical>
	# read path <path> -> extents information
	# find file <path> -> metadata and stuff?
	# readdir <path> -> all files/dirs with objectids?
	# subvolume list
	# physical <logical> -> list of (device -> physical)

	if(len(args) > 0):

		if(args[0] == 'read'):

			if(args[1] == 'inode'):
				inode_nr = int(args[2])
				key = Container(objectid=inode_nr, type=INODE_ITEM_KEY, offset=0)
				inode = btrfs.find_key(btrfs.fs_tree.bytenr, key)

				if(inode == None):
					print('Inode not found')
					sys.exit(1)

				print(inode.item)
				print(inode.data)


			if(args[1] == 'csum'):
				logical = int(args[2])
				key = Container(objectid=EXTENT_CSUM_OBJECTID, type=EXTENT_CSUM_KEY, offset=logical)
				result = btrfs.find_key(btrfs.csum_tree.bytenr, key)

				if(result == None):
					print('Csum not found')
					sys.exit(1)

				print(result.item)
				print(result.data)

			if(args[1] == 'path'):
				path = args[3]
				item = btrfs.find_path(256, path.encode().split(b'/'))

				node = BtrfsNode(btrfs, btrfs.fs_tree.bytenr)
				extents = node.find_all_objectid(item.key.objectid)

				if(args[2] == 'info'):
					print(item.key)
					print(item.data)

					for item in extents:
						if(item.key.type != EXTENT_DATA_KEY):
							continue

						print(item.key)
						print(item.data)

				elif(args[2] == 'data'):
					x = 0
					size = item.data.size
					for item in extents:
						if(item.key.type != EXTENT_DATA_KEY):
							continue

						if(item.key.offset != 0):
							raise Exception('Missing extent data for file')

						if(item.data.compression != COMPRESS_NONE):
							raise Exception('Extent is compressed which is not supported')

						if(item.data.type == FILE_EXTENT_INLINE):
							sys.stdout.buffer.write(item.data.data)
							extent_size = len(item.data.data)

						elif(item.data.type == FILE_EXTENT_REG):
							extent_size = item.data.num_bytes
							len = min(extent_size, size-x)
							addr = btrfs.physical(item.data.disk_bytenr, len)

							btrfs.dev[0].seek(addr[1])
							data = btrfs.dev[0].read(len)
							l = sys.stdout.buffer.write(data)
							if(l != min(extent_size, size-x)):
								raise Exception('!!!!!')

						else:
							raise Exception('Invalid extent data type found!')

						x += extent_size


		if(args[0] == 'chunks'):
			print(btrfs.chunk_tree_cache)


		if(args[0] == 'files'):
			files = btrfs.list_files()
			print('Files:', files)

		if(args[0] == 'subvolume'):
			if(args[1] == 'list'):
				node = BtrfsNode(btrfs, btrfs.superblock.root)
				for item in node.find_all():
					if(item.key.type != ROOT_REF_KEY):
						continue
					print('Subvolume {}/{} (parent: {}): {}'.format(
					      item.key.offset, item.data.dirid,
					      item.key.objectid, item.data.name))

		if(args[0] == 'checksums'):
			node = BtrfsNode(btrfs, btrfs.csum_tree.bytenr)
			for item in node.find_all():
				print('{} - {} 4k pages = {} bytes'.format(
					item.key.offset, item.size//4, item.size//4*2**12))

		if(args[0] == 'verify'):
			import crc32c

			if(args[1] == 'file'):

				path = args[2]
				item = btrfs.find_path(256, path.encode().split(b'/'))

				node = BtrfsNode(btrfs, btrfs.fs_tree.bytenr)
				extents = node.find_all_objectid(item.key.objectid)

				x = 0

				for extent in extents:

					if(extent.key.type != EXTENT_DATA_KEY):
						continue

					if(extent.key.offset != 0):
						raise Exception('Missing extent data for file')

					if(extent.data.compression != COMPRESS_NONE):
						raise Exception('Extent is compressed which is not supported')

					if(extent.data.type == FILE_EXTENT_INLINE):
						# Read node header -> csum
						extent_size = len(extent.data.data)

						node_data = extent.node.data
						csum = crc32c.crc32c(node_data[CSUM_SIZE:])
						node_csum = Int32ul.parse(node_data[0:CSUM_SIZE])

						if(csum != node_csum):
							print('Checksum error, {} != {}'.format(
								csum, node_csum))
						else:
							print('Node checksum @{} OK'.format(extent.node.logical))

					elif(extent.data.type == FILE_EXTENT_REG):
						extent_size = extent.data.disk_num_bytes
						addr = btrfs.physical(extent.data.disk_bytenr, extent_size)

						btrfs.dev[0].seek(addr[1])
						data = btrfs.dev[0].read(extent_size)

						# Verify this extent
						for i in range(extent_size // 4096):
							block = data[4096*i:4096*(i+1)]
							block_csum = crc32c.crc32c(block)
							extent_csum = btrfs.find_checksums(extent.data.disk_bytenr, extent.data.disk_bytenr + extent_size)[i]
							logical = extent.data.disk_bytenr + i * 4096

							if(block_csum != extent_csum):
								print('Checksum @{} ERROR, {} != {}'.format(
									logical, block_csum, extent_csum))
							else:
								print('Checksum @{} OK'.format(logical))

					else:
						raise Exception('Invalid extent data type found!')

					x += extent_size

		elif(args[0] == 'physical'):

			logical = int(args[1])

			physical = btrfs.physical(logical)

			for drive, address in physical.items():
				print('{}: {}'.format(drive, address))
