#!/usr/bin/env python3

from construct import *

STATE_FILE = 'btrfs_plumber_state'

def print_help():
	help_str = '''\
usage: btrfs-plumber.py [--help] <command> [<args>]

Commands:
    init <disk>... Initialize btrfs-plumber with disks
    read           Read items
    ls             list files and directories
    chunks         Print all chunk mappings (logical -> physical)
    files          List all files
    subvolume      Print information about subvolumes
    checksums      Print all checksum items
    verify         Verify files and objects
'''
	print(help_str)


if(__name__ == '__main__'):
	import btrfs
	import getopt
	import sys
	import os
	import yaml
	import tempfile

	shortopts = ''
	longopts = ['help']
	optslist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)

	if('help' in optslist):
		print_help()
		sys.exit(1)

	# read <item-type> <key>
	# read inode <inode-number>
	# read csum <logical>
	# read path <path> -> extents information
	# find file <path> -> metadata and stuff?
	# readdir <path> -> all files/dirs with objectids?
	# subvolume list
	# physical <logical> -> list of (device -> physical)

	if(len(args) > 0):

		# Move to get_state_path or similar
		temp_dir = tempfile.gettempdir()

		state_path = os.path.join(
			temp_dir,
			'{}_{}'.format(STATE_FILE, os.getsid(0)))

		if(args[0] == 'init'):
			state = {}
			state['disks'] = args[1:]

			# Verify disks
			try:
				fs = btrfs.Btrfs(state['disks'])
			except:
				print('Invalid disks: {}'.format(args[1:]))
				sys.exit(1)

			# Store disks to session state file
			try:
				with open(state_path, 'wt') as f:
					yaml.safe_dump(state, f)
			except:
				# State file was invalid, remove it
				print('Could not create state file {}'.format(state_path))
				sys.exit(1)

			sys.exit(0)

		else:
			try:
				with open(state_path, 'rt') as f:
					state = yaml.safe_load(f)
					fs = btrfs.Btrfs(state['disks'])

			except:
				# State file was invalid, remove it if it exists
				try:
					os.unlink(state_path)
				except:
					pass

				print('Please initialize drives first! (btrfs-plumber init)')
				sys.exit(1)

		if(args[0] == 'read'):

			if(args[1] == 'inode'):
				inode_nr = int(args[2])
				key = Container(objectid=inode_nr, type=btrfs.INODE_ITEM_KEY, offset=0)
				inode = fs.find_key(fs.fs_tree.bytenr, key)

				if(inode == None):
					print('Inode not found')
					sys.exit(1)

				print(inode.item)
				print(inode.data)


			elif(args[1] == 'csum'):
				logical = int(args[2])
				key = Container(objectid=btrfs.EXTENT_CSUM_OBJECTID, type=btrfs.EXTENT_CSUM_KEY, offset=logical)
				result = fs.find_key(fs.csum_tree.bytenr, key)

				if(result == None):
					print('Csum not found')
					sys.exit(1)

				print(result.item)
				print(result.data)

			elif(args[1] == 'path'):
				path = args[3]
				item = fs.find_path(256, path.encode().split(b'/'))

				node = btrfs.BtrfsNode(fs, fs.fs_tree.bytenr)
				extents = node.find_all_objectid(item.key.objectid)

				if(args[2] == 'info'):
					print(item.key)
					print(item.data)

					for item in extents:
						if(item.key.type != btrfs.EXTENT_DATA_KEY):
							continue

						print(item.key)
						print(item.data)

				elif(args[2] == 'data'):
					x = 0
					size = item.data.size
					for item in extents:
						if(item.key.type != btrfs.EXTENT_DATA_KEY):
							continue

						if(item.key.offset != 0):
							raise Exception('Missing extent data for file')

						if(item.data.compression != btrfs.COMPRESS_NONE):
							raise Exception('Extent is compressed which is not supported')

						if(item.data.type == btrfs.FILE_EXTENT_INLINE):
							sys.stdout.buffer.write(item.data.data)
							extent_size = len(item.data.data)

						elif(item.data.type == btrfs.FILE_EXTENT_REG):
							extent_size = item.data.num_bytes
							len = min(extent_size, size-x)
							addr = fs.physical(item.data.disk_bytenr, len)
							dev_id = next(iter(addr.keys()))

							fs.dev[dev_id].seek(addr[dev_id])
							data = fs.dev[dev_id].read(len)
							l = sys.stdout.buffer.write(data)
							if(l != min(extent_size, size-x)):
								raise Exception('!!!!!')

						else:
							raise Exception('Invalid extent data type found!')

						x += extent_size


		elif(args[0] == 'chunks'):
			print(fs.chunk_tree_cache)


		elif(args[0] == 'files'):
			files = fs.list_files()
			print('Files:', files)

		elif(args[0] == 'subvolume'):
			if(args[1] == 'list'):
				node = btrfs.BtrfsNode(fs, fs.superblock.root)
				for item in node.find_all():
					if(item.key.type != btrfs.ROOT_REF_KEY):
						continue
					print('Subvolume {}/{} (parent: {}): {}'.format(
					      item.key.offset, item.data.dirid,
					      item.key.objectid, item.data.name))

		elif(args[0] == 'checksums'):
			node = btrfs.BtrfsNode(fs, fs.csum_tree.bytenr)
			for item in node.find_all():
				print('{} - {} 4k pages = {} bytes'.format(
					item.key.offset, item.size//4, item.size//4*2**12))

		elif(args[0] == 'verify'):
			import crc32c

			if(args[1] == 'file'):

				path = args[2]
				item = fs.find_path(256, path.encode().split(b'/'))

				node = btrfs.BtrfsNode(fs, fs.fs_tree.bytenr)
				extents = node.find_all_objectid(item.key.objectid)

				x = 0

				for extent in extents:

					if(extent.key.type != btrfs.EXTENT_DATA_KEY):
						continue

					if(extent.key.offset != 0):
						raise Exception('Missing extent data for file')

					if(extent.data.compression != btrfs.COMPRESS_NONE):
						raise Exception('Extent is compressed which is not supported')

					if(extent.data.type == btrfs.FILE_EXTENT_INLINE):
						# Read node header -> csum
						extent_size = len(extent.data.data)

						node_data = extent.node.data
						csum = crc32c.crc32c(node_data[btrfs.CSUM_SIZE:])
						node_csum = Int32ul.parse(node_data[0:btrfs.CSUM_SIZE])

						if(csum != node_csum):
							print('Checksum error, {} != {}'.format(
								csum, node_csum))
						else:
							print('Node checksum @{} OK'.format(extent.node.logical))

					elif(extent.data.type == btrfs.FILE_EXTENT_REG):
						extent_size = extent.data.disk_num_bytes
						addr = fs.physical(extent.data.disk_bytenr, extent_size)
						dev_id = next(iter(addr.keys()))

						fs.dev[dev_id].seek(addr[dev_id])
						data = fs.dev[dev_id].read(extent_size)

						# Verify this extent
						for i in range(extent_size // 4096):
							block = data[4096*i:4096*(i+1)]
							block_csum = crc32c.crc32c(block)
							extent_csum = fs.find_checksums(extent.data.disk_bytenr, extent.data.disk_bytenr + extent_size)[i]
							logical = extent.data.disk_bytenr + i * 4096

							if(block_csum != extent_csum):
								print('Checksum @logical {} ERROR, {} != {}'.format(
									logical, block_csum, extent_csum))
							else:
								print('Checksum @logical {} OK'.format(logical))

					else:
						raise Exception('Invalid extent data type found!')

					x += extent_size

			elif(args[1] == 'logical'):

				logical = int(args[2])
				addr_map = fs.physical(logical)

				node = btrfs.BtrfsNode(fs, fs.csum_tree.bytenr)
				csum = node.find_csum(logical)
				csum_index = (logical-csum.key.offset) // 4096

				checksum = csum.data.csum[csum_index]
				checksum_logical = csum.node.logical + btrfs.Header.sizeof() + \
				                   csum.item.offset + csum_index * 4

				print('Checksum 0x{:02x} @logical {}'
				      .format(checksum, checksum_logical))

				for disk in addr_map:

					# TODO: proper disk mapping
					fs.dev[disk].seek(addr_map[disk])
					block = fs.dev[disk].read(4096)
					block_csum = crc32c.crc32c(block)

					if(block_csum == checksum):
						print('Checksum @logical {} @disk {} : {} OK'
						      .format(logical, disk, addr_map[disk]))
					else:
						print('Checksum @logical {} @disk {} : {} ERROR, mismatch: 0x{:02x}'
						      .format(logical, disk, addr_map[disk], block_csum))



		elif(args[0] == 'ls'):

			if(len(args) < 2):
				inode_id = 256
				is_dir = True
				key = Container(objectid=inode_id, type=btrfs.INODE_ITEM_KEY, offset=0)
				item = fs.find_key(fs.fs_tree.bytenr, key)

			else:
				path = args[1].encode().strip(b'/').split(b'/')
				item = fs.find_path(256, path)

				if(not item):
					print('Item not found or subvolume (TODO)')
					sys.exit(1)

				inode_id = item.key.objectid
				mode = item.data.mode
				is_dir = (mode & btrfs.S_IFMT) == btrfs.S_IFDIR

			if(not is_dir):
				# TODO: use ls -l output format
				print('{}\t{:04o}\t{}'.format(
					path[-1].decode(), mode & (~btrfs.S_IFMT), btrfs.S_NAMES[(mode & btrfs.S_IFMT)]))

			else:
				for item in item.node.find_all_objectid(inode_id):
					if(item.key.type != btrfs.DIR_INDEX_KEY):
						continue

					if(item.data.type == btrfs.FT_DIR):
						print('{}/'.format(item.data.name.decode()))
					else:
						print(item.data.name.decode())


		elif(args[0] == 'physical'):

			logical = int(args[1])

			physical = fs.physical(logical)

			for drive, address in physical.items():
				print('{}: {}'.format(fs.dev_name[drive], address))

	else:
		print_help()
