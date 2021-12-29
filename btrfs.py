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

# See man inode(7)
S_IFMT   = 0o170000
S_IFSOCK = 0o140000
S_IFLNK  = 0o120000
S_IFREG  = 0o100000
S_IFBLK  = 0o060000
S_IFDIR  = 0o040000
S_IFCHR  = 0o020000
S_IFIFO  = 0o010000

S_NAMES = \
{
	S_IFSOCK: 'socket',
	S_IFLNK: 'symbolic link',
	S_IFREG: 'regular file',
	S_IFBLK: 'block device',
	S_IFDIR: 'directory',
	S_IFCHR: 'character device',
	S_IFIFO: 'FIFO'
}


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


	def prev(self):
		return self.node.prev(self.index)


class BtrfsNode:

	def __init__(self, fs, logical, parent=None, index=None):

		self.fs = fs
		self.data, self.dev_id = self.fs.read_node(logical)
		self.logical = logical
		self.parent = parent
		self.index = index

		stream = io.BytesIO(self.data)

		self.header = Header.parse_stream(stream)

		self.data_root = stream.tell()
		self.num_items = self.header.nritems

		self.is_leaf = (self.header.level == 0)

		# keyobjs may be either items (leafs) or keyptrs (internal nodes)
		if(self.is_leaf):
			self.keyobjs = Item[self.num_items].parse_stream(stream)

		else:
			self.keyobjs = KeyPtr[self.num_items].parse_stream(stream)

		# Parse items? No, takes unneseccary time, store data


	def parse_item(self, item):

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

		stream = io.BytesIO(self.data)
		stream.seek(self.data_root + item.offset)

		payload_data = stream.read(item.size)
		payload = type.parse(payload_data)

		return payload


	def first_key(self):
		if(self.is_leaf):
			keyobj = self.keyobjs[0]
			data = self.parse_item(keyobj)
			return BtrfsItem(keyobj, data, self, 0)

		else:
			node = BtrfsNode(self.fs, self.keyobjs[0].blockptr, self, 0)
			return node.first_key()


	def last_key(self):
		if(self.is_leaf):
			keyobj = self.keyobjs[-1]
			data = self.parse_item(keyobj)
			return BtrfsItem(keyobj, data, self, self.num_items-1)

		else:
			node = BtrfsNode(self.fs, self.keyobjs[-1].blockptr, self, self.num_items-1)
			return node.last_key()


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
					data = self.parse_item(keyobj)
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
					data = self.parse_item(keyobj)
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
				data = self.parse_item(keyobj)
				item = BtrfsItem(keyobj, data, self, i)

				c = compare_csum_keys(logical, item)

			else:
				c = compare_keys(key, self.keyobjs[i].key)


			if(c == 0):
				if(self.is_leaf):
					keyobj = self.keyobjs[i]
					data = self.parse_item(keyobj)
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

				if(upper < lower):
					lower = upper

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
				data = self.parse_item(keyobj)
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


	def prev(self, index):

		if(self.is_leaf):
			if(index > 0):
				keyobj = self.keyobjs[index-1]
				data = self.parse_item(keyobj)
				return BtrfsItem(keyobj, data, self, index-1)

			else:
				if(not self.parent):
					return None

				return self.parent.prev(self.index)

		else:
			if(index > 0):
				node = BtrfsNode(self.fs, self.keyobjs[index-1].blockptr, self, index-1)
				return node.last_key()

			else:
				if(not self.parent):
					return None

				self.parent.prev(self.index)


class Btrfs:

	def __init__(self, devices):
		self.chunk_tree_cache = {}
		self.subvolume_trees = {}
		self.dev = {}
		self.dev_name = {}

		self.dev0_name = devices[0]

		for dev in devices:
			f = open(dev, 'rb')
			f.seek(SUPERBLOCK_OFFSETS[0])
			superblock = Superblock.parse_stream(f)
			self.dev[superblock.dev_item.devid] = f
			self.dev_name[superblock.dev_item.devid] = dev

			if(dev == self.dev0_name):
				self.dev0_id = superblock.dev_item.devid
				self.superblock = superblock

		self.node_size = self.superblock.node_size

		self.chunk_tree_cache = self.bootstrap_chunk_tree()

		self.read_chunk_tree(self.superblock.chunk_root)

		self.read_tree_roots(self.superblock.root)


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
				{x.devid: x.offset for x in chunk.stripes}

			offset += Chunk.sizeof(chunk)

		return chunk_tree_cache


	def physical(self, logical, size=0):
		'''logical -> [physical], verifies size'''

		for cache_logical, chunk_size in self.chunk_tree_cache:
			if(logical >= cache_logical and logical < cache_logical + chunk_size):

				if(logical + size > cache_logical + chunk_size):
					raise Exception('Logical addressing does not fit in chunk')

				m = { devid: x + logical - cache_logical
				      for devid, x in self.chunk_tree_cache[(cache_logical, chunk_size)].items() }
				return m


		return KeyError('No such logical address found in chunk tree')


# TODO: a read which checks size etc..? read(struct, logical, verify=False)?


	def read_chunk_tree(self, chunk_root_logical):

		physical = self.physical(chunk_root_logical)
		dev_id = next(iter(physical.keys()))

		self.dev[dev_id].seek(physical[dev_id])
		chunk_root_header = Header.parse_stream(self.dev[dev_id])
		data_root = self.dev[dev_id].tell()

		if(chunk_root_header.level == 0):
			items = Item[chunk_root_header.nritems].parse_stream(self.dev[dev_id])
			for item in items:

				if(item.key.type != CHUNK_ITEM_KEY):
					continue


				self.dev[dev_id].seek(data_root + item.offset)
				chunk = Chunk.parse_stream(self.dev[dev_id])

				self.chunk_tree_cache[(item.key.offset, chunk.length)] = \
					{x.devid: x.offset for x in chunk.stripes}

		else:
			key_ptrs = KeyPtr[chunk_root_header.nritems].parse_stream(self.dev[dev_id])
			for key_ptr in key_ptrs:
				self.read_chunk_tree(key_ptr.blockptr)


	def read_tree_roots(self, root_logical):

		root_addr = self.physical(root_logical)
		dev_id = next(iter(root_addr.keys()))

		self.dev[dev_id].seek(root_addr[dev_id])
		root_tree_root_header = Header.parse_stream(self.dev[dev_id])
		data_root = self.dev[dev_id].tell()

		# NOTE: Apparently the root tree may use non-leaf nodes in contrast to
		#       some documentation I found earlier

		if(root_tree_root_header.level == 0):
			items = Item[root_tree_root_header.nritems].parse_stream(self.dev[dev_id])

			for item in items:

				if(item.key.type == ROOT_ITEM_KEY and
				   item.key.objectid == FS_TREE_OBJECTID):

					self.fs_tree = self.parse_item(item, dev_id, data_root)

				elif(item.key.type == ROOT_ITEM_KEY and
					 item.key.objectid == CSUM_TREE_OBJECTID):

					self.csum_tree = self.parse_item(item, dev_id, data_root)

				elif(item.key.type == ROOT_ITEM_KEY and
					 item.key.objectid >= 256):

					self.subvolume_trees[item.key.objectid] = self.parse_item(item, dev_id, data_root)

				elif(item.key.type == DIR_ITEM_KEY and
					 item.key.objectid == ROOT_TREE_DIR_OBJECTID):

					dir_item = self.parse_item(item, dev_id, data_root)

				elif(item.key.type == ROOT_ITEM_KEY and
					 item.key.objectid == EXTENT_TREE_OBJECTID):

					self.extent_tree = self.parse_item(item, dev_id, data_root)

				else:
					continue

		else:
			key_ptrs = KeyPtr[root_tree_root_header.nritems].parse_stream(self.dev[dev_id])
			for key_ptr in key_ptrs:
				self.read_tree_roots(key_ptr.blockptr)


	def read_node(self, logical):

		node_addr = self.physical(logical)
		dev_id = next(iter(node_addr.keys()))
		self.dev[dev_id].seek(node_addr[dev_id])

		return self.dev[dev_id].read(self.node_size), dev_id


	def parse_item(self, item, dev_id, data_root):

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

		self.dev[dev_id].seek(data_root + item.offset)
		payload_data = self.dev[dev_id].read(item.size)
		payload = type.parse(payload_data)

		return payload


	def find_key(self, root_node, key):
		# TODO: Remove and only use BtrfsNode.find() ?
		node = BtrfsNode(self, root_node, None, 0)
		return node.find(key)


	def find_path(self, root_inode, path, node=None):
		# TODO:
		# Where do I find root? use constant 256 for start (is this always true?)

		if(not node):
			node = BtrfsNode(self, self.fs_tree.bytenr)

		items = node.find_all_objectid(root_inode)

		for item in items:

			if(item.key.type != DIR_INDEX_KEY):
				continue

			if(item.data.name == path[0]):

				# Handle subvolumes specifically
				if(item.data.location.type == ROOT_ITEM_KEY):
					node = BtrfsNode(self, self.subvolume_trees[item.data.location.objectid].bytenr)

					if(len(path) > 1):
						return self.find_path(256, path[1:], node)

					else:
						key = Container(objectid=256,
										type=INODE_ITEM_KEY,
										offset=0)

						inode_item = node.find(key)
						return inode_item

				# TODO: is this accessible by next/prev?
				inode_item = node.find(item.data.location)

				if(len(path) > 1):
					return self.find_path(inode_item.key.objectid, path[1:], node)

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

			if(current == logical_end):
				break

		if(current != logical_end):
			raise Exception('Could not find all checksums!')

		return csums


	def list_files(self):

		node = BtrfsNode(self, self.fs_tree.bytenr)
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
