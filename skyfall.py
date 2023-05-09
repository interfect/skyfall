#!/usr/bin/env python3

import json
import re
import io
import os
import time
import sys
import pprint
import argparse
import logging
from typing import Any, Optional, Tuple, Iterator, List

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

try:
    import leb128
except ImportError:
    logger.critical("Error: install the leb128 module: pip install leb128")
    sys.exit(1)
    
try:
    import cbor2
except ImportError:
    logger.critical("Error: install the leb128 module: pip install leb128")
    sys.exit(1)

try:
    import multibase
except ImportError:
    logger.critical("Error: install the multibase module: pip install multibase")
    sys.exit(1)

try:
    from chitose.agent import BskyAgent
except ImportError:
    logger.critical("Error: install the chitose module: pip install chitose")
    sys.exit(1)

from urllib.error import HTTPError

class CID:
    """
    Represents an IPLD CID, which is a hash-based key for identifying data.
    
    The content is a string base-32 lower-case unpadded "multibase" CID format.
    
    But we can't extend str or cbor2 won't be able to detect us when
    serializing, and it will just serialize the plain string.
    """
    
    def __init__(self, value: str):
        """
        Wrap a string as a CID.
        """
        self.value = value
    
    def __repr__(self):
        """
        Make a human-readable representation of this CID.
        """
        return "CID('" + str(self) + "')"
        
    def __str__(self):
        """
        Make a normal string representation of this CID.
        """
        return self.value
        
    def __eq__(self, other):
        """
        Return True if this CID equals another object.
        """
        
        return isinstance(other, CID) and self.value == other.value
        
    def __hash__(self):
        """
        Make CIDs hashable for use as dict keys.
        """
        return hash(self.value)
        
    @staticmethod
    def decode_bytes(cid_bytes: bytes) -> "CID":
        """
        Decode a CID represented as raw, non-0-prefixed bytes. 
        """
        return CID(multibase.encode('base32', cid_bytes).decode('utf-8'))
        
    @staticmethod
    def encode_bytes(cid: "CID") -> bytes:
        """
        Encode a CID to raw, non-0-prefixed bytes. 
        """
        
        return multibase.decode(str(cid).encode('utf-8'))
        
    @staticmethod
    def decode_reader(stream) -> Tuple["CID", int]:
        """
        Read one non-0-prefixed raw-bytes CID from a byte stream and return it,
        along with the number of bytes consumed.
        
        Stream must be peekable.
        """
    
        lead_bytes = stream.peek(2)
        if lead_bytes == b'\x12\x20':
            # CID v0
            # 32-byte hash after this header, so 34 total.
            return (CID.decode_bytes(stream.read(34)), 34)
        else:
            # CID v1
            bytes_used = 0
            version, b = leb128.u.decode_reader(stream)
            bytes_used += b 
            assert version == 1
            codec, b = leb128.u.decode_reader(stream)
            bytes_used += b
            hash_type, b = leb128.u.decode_reader(stream)
            bytes_used += b
            hash_length, b = leb128.u.decode_reader(stream)
            bytes_used += b
            hash_data = stream.read(hash_length)
            bytes_used += hash_length
            
            # Now put it back together
            cid_bytes = io.BytesIO()
            cid_bytes.write(leb128.u.encode(version))
            cid_bytes.write(leb128.u.encode(codec))
            cid_bytes.write(leb128.u.encode(hash_type))
            cid_bytes.write(leb128.u.encode(hash_length))
            cid_bytes.write(hash_data)
            return CID.decode_bytes(cid_bytes.getbuffer().tobytes()), bytes_used
        

    @staticmethod    
    def tag_hook(decoder, tag, shareable_index=None):
        """
        CBOR decoding hook for tag 42, representing an IPLD link.
        We decode it as a string base32 CID.
        """
        if tag.tag != 42:
            return tag
            
        # We have bytes as the value.
        cid_stream = io.BufferedReader(io.BytesIO(tag.value))
        # Read the leading base indicator
        lead_byte = cid_stream.read(1)
        assert(lead_byte == b'\x00')
        
        # Convert bytes of the CID to a string
        return CID.decode_reader(cid_stream)[0]
        
    @staticmethod
    def default_encoder(encoder, value):
        """
        CBOR "default" encoding hook for CIDs to give then tag 42.
        """
        if isinstance(value, CID):
            # The examples in the cbor2 docs say you can just encode() a
            # CBORTag, but actually you can't. Instead we need to use the
            # secret encode_semantic() method:
            # https://github.com/agronholm/cbor2/blob/9ba9e2fa9aa1af23d836aa8c96de77883aafd74c/cbor2/encoder.py#L490
            encoder.encode_semantic(cbor2.CBORTag(42, b'\x00' + CID.encode_bytes(value)))
        else:
            raise ValueError(f'Cannot encode a {type(value)} as CBOR') 
        
def decode_dag_cbor(data: bytes) -> dict:
    """
    Decode IPLD DAG-CBOR format to Python objects.
    IPLD links are decoded as CID objects containing the string CID linked to.
    """
    
    return cbor2.decoder.loads(data, tag_hook=CID.tag_hook)
    
def encode_dag_cbor(data: dict) -> bytes:
    """
    Encode IPLD DAG-CBOR format from Python objects. CID objects will be stored
    as IPLD links with tag 42.
    
    Round-trips with decode_dag_cbor.
    
    >>> test_cid = CID('bafybeialnrrsx3ytkbuqkxhn5crhx7btg6ugloyobta77xxh2kga3b2zde')
    >>> test_structure = {'target': test_cid}
    >>> print(test_structure)
    {'target': CID('bafybeialnrrsx3ytkbuqkxhn5crhx7btg6ugloyobta77xxh2kga3b2zde')}
    >>> round_trip = decode_dag_cbor(encode_dag_cbor(test_structure))
    >>> print(round_trip)
    {'target': CID('bafybeialnrrsx3ytkbuqkxhn5crhx7btg6ugloyobta77xxh2kga3b2zde')}
    """
    
    return cbor2.encoder.dumps(data, default=CID.default_encoder)
    
def decode_car_of_dag_cbor(stream) -> dict:
    """
    Decode an IPLD CAR file from a stream of bytes.
    
    Returns a dict with a 'header' key, and additionally CID keys pointing to
    their stored values. Values are all decoded as DAC-CBOR objects. All IPLD
    links will be CID strings.
    """
    
    logger.info("Decoding CAR archive...")
    
    # Read the header.
    header_length = leb128.u.decode_reader(stream)[0]
    header = decode_dag_cbor(stream.read(header_length))
    
    result = {"header": header}
    
    item_count = 0
    
    while len(stream.peek(1)) > 0:
        item_length = leb128.u.decode_reader(stream)[0]
        item = stream.read(item_length)
        # Decode self-delimiting multihash CID, and then the data after it.
        cid_text, cid_byte_length = CID.decode_reader(io.BufferedReader(io.BytesIO(item)))
        # The item is DAG-CBOR
        result[cid_text] = decode_dag_cbor(item[cid_byte_length:])
        
        # Report progress since this can appear to hang...
        item_count += 1
        if item_count % 1000 == 0:
            logger.debug(f"Decoded {item_count} blocks from CAR...")
            
    logger.debug(f"Decoded {item_count} total blocks from CAR")
        
    return result
    
def extension_for_mime_type(mime_type: Optional[str]) -> str:
    """
    Map a MIME type to an extension.
    """
    
    # What extensions should we use when saving embeds?        
    MIME_TO_EXT = {
        'image/jpeg': 'jpg',
        'image/png': 'png'
    }
    
    if mime_type not in MIME_TO_EXT:
        logger.warning(f"Unknown MIME type: {mime_type}")
        return "dat"
    return MIME_TO_EXT[mime_type]
    
class Datastore:
    """
    Abstract interface for a place to put blocks (of feed data) and blobs (like images).
    """
    
    def get_block(self, actor_did: str, block_cid: CID, collection: Optional[str] = None, rkey: Optional[str] = None) -> Optional[dict]:
        raise NotImplementedError()
        
    def put_block(self, actor_did: str, block_cid: CID, block_data: dict):
        raise NotImplementedError()
        
    def get_blob_file(self, actor_did: str, blob_cid: CID, mime_type: Optional[str]) -> Optional[str]:
        raise NotImplementedError()
        
    def put_blob(self, actor_did: str, blob_cid: CID, mime_type: Optional[str], blob_data: bytes):
        raise NotImplementedError()
    
class DiskDatastore(Datastore):
    """
    Disk-backed storage for blocks (of repos) and blobs.
    """
    
    def __init__(self, root_dir: str):
        """
        Make or connect to the data store at the given root directory.
        """
        
        self.root_dir = root_dir
        
    def did_to_path(self, actor_did: str):
        """
        Turn a DID identifier into something that can be used in a path.
        """
        return re.sub("[^A-Za-z0-9._-]", "_", actor_did)
    
    def _get_block_path(self, actor_did: str, block_cid: CID, store: str = "blocks") -> str:
        """
        Get the path at which a block would be stored, for the given poster.
        """
        
        # Make the DID into a directory name
        did_path = self.did_to_path(actor_did)
        
        # Make the CID into a directory hierarchy
        # Most CIDs start out "bafyrei" because of the "b" prefix and the CIDv1 and length stuff.
        cid_str = str(block_cid)
        cid_breaks = [0, 7, 9, 11, 13, len(cid_str)]
        cid_parts = [cid_str[cid_breaks[i]:cid_breaks[i+1]] for i in range(len(cid_breaks) - 1)]
        
        # String it all together
        parts = [self.root_dir, store, did_path] + cid_parts
        return os.path.join(*parts)
        
    def _get_blob_path(self, actor_did: str, blob_cid: CID, mime_type: Optional[str]) -> str:
        """
        Get the path that a blob would be stored at, if it were stored.
        """
        
        # Store it like a block, but in a different directory and with an extension
        return self._get_block_path(actor_did, blob_cid, store="blobs") + "." + extension_for_mime_type(mime_type)
        
    
    def get_block(self, actor_did: str, block_cid: CID, collection: Optional[str] = None, rkey: Optional[str] = None) -> Optional[dict]:
        """
        Get the decoded block from the repo for the given account, with the
        given CID, or None if it is not stored.
        
        Collection and rkey hints are ignored.
        """
        
        block_path = self._get_block_path(actor_did, block_cid)
        
        if os.path.exists(block_path):
            return decode_dag_cbor(open(block_path, 'rb').read())
            
    def put_block(self, actor_did: str, block_cid: CID, block_data: dict):
        """
        Save a downloaded block from a repo. Block should be parsed IPLD-CBOR
        as a dict.
        """
        
        block_path = self._get_block_path(actor_did, block_cid)
        
        if os.path.exists(block_path):
            # Already have it
            return
            
        os.makedirs(os.path.dirname(block_path), exist_ok=True)
        # Write to a different file so we can't be mistaken for having the
        # value already.
        open(block_path + '.tmp', 'wb').write(encode_dag_cbor(block_data))
        os.rename(block_path + '.tmp', block_path)
            
    def get_blob_file(self, actor_did: str, blob_cid: CID, mime_type: Optional[str]) -> Optional[str]:
        """
        Get a filename for the given blob, with the given MIME type, as posted
        by the given account, or None if it is not stored.
        """
        
        blob_path = self._get_blob_path(actor_did, blob_cid, mime_type)
        if os.path.exists(blob_path):
            # We have it
            return blob_path
        else:
            # Not available here
            return None
            
    def put_blob(self, actor_did: str, blob_cid: CID, mime_type: Optional[str], blob_data: bytes):
        """
        Save downloaded bytes to a blob file.
        """
        
        blob_path = self._get_blob_path(actor_did, blob_cid, mime_type)
        if os.path.exists(blob_path):
            # Skip it
            return
        
        os.makedirs(os.path.dirname(blob_path), exist_ok=True)
        # Write to a different file so we can't be mistaken for having the
        # value already.
        open(blob_path + '.tmp', 'wb').write(blob_data)
        os.rename(blob_path + '.tmp', blob_path)
        
class SyncingDatastore(DiskDatastore):
    """
    Datastore that stores data locally on disk, but fetches it from a remote AT
    server if it is not available locally.
    """
    
    def __init__(self, root_dir: str, agent: BskyAgent, blob_delay: float = 0.0, skip_blobs: bool = False):
        """
        Make a data store storing data at the given path, and using the given agent to fetch unavailable data.
        
        Wait blob_delay after successfully fetching a blob. If skip_blobs is True, don't fetch blobs.
        """
        super().__init__(root_dir)
        self.agent = agent
        self.blob_delay = blob_delay
        self.skip_blobs = skip_blobs
        
    def get_block(self, actor_did: str, block_cid: CID, collection: Optional[str] = None, rkey: Optional[str] = None) -> Optional[dict]:
        """
        Get the block from the local store. If not there, sync it and related blocks.
        
        If collection and rkey are set, use them to request just the blocks for
        the relevant record. Otherwise, sync the whole repo if the block isn't
        found.
        """
        
        block = super().get_block(actor_did, block_cid)
        if block is not None:
            return block
        
        # Now we need to sync it
        
        if collection is not None and rkey is not None:
            logger.info(f"Get CAR file for blocks for collection {collection} and rkey {rkey}")
            # Most records won't be synced like this so we don't need to spray across directories hopefully.
            car_path = os.path.join(self.root_dir, 'records', self.did_to_path(actor_did), str(block_cid) + '.car')
            car_bytes = self.agent.com.atproto.sync.get_record(did=actor_did, collection=collection, rkey=rkey)
        else:
            # TODO: Implement sync based on what we already have for this DID.
            # For now just get the *current checkout* of the whole repo.
            logger.info(f"Get CAR file for repo {actor_did}")
            car_path = os.path.join(self.root_dir, 'repos', self.did_to_path(actor_did) + '.car')
            # TODO: handle the case where the checkout has changed since we got the HEAD we were looking for.
            
            # TODO: This is probably big; the library should maybe hand back a stream
            # here?
            car_bytes = self.agent.com.atproto.sync.get_checkout(did=actor_did)
        
        os.makedirs(os.path.dirname(car_path), exist_ok=True) 
        open(car_path + '.tmp', 'wb').write(car_bytes)
        # Drop from memory
        del car_bytes
        os.rename(car_path + '.tmp', car_path)
        logger.info(f"Saved CAR to {car_path}")
        
        # Now we read it back and insert it all.
        car_records = decode_car_of_dag_cbor(open(car_path, 'rb'))
        
        logger.info(f"Storing {len(car_records) - 1} blocks from CAR into datastore...")
        item_count = 0 
        for k, v in car_records.items():
            if k == 'header':
                # Skip the header
                continue
            # Store all the blocks in ourselves.
            self.put_block(actor_did, k, v)
            # Report progress since this can appear to hang...
            item_count += 1
            if item_count % 1000 == 0:
                logger.debug(f"Inserted {item_count} blocks into datastore...")
        logger.debug(f"Inserted {item_count} total blocks into datastore")
            
        # Now try again, and fail if the block is missing.
        return super().get_block(actor_did, block_cid)
        
    def get_blob_file(self, actor_did: str, blob_cid: CID, mime_type: Optional[str]) -> Optional[str]:
        """
        Get the blob file from the local store. If not there, sync it.
        """
        
        filename = super().get_blob_file(actor_did, blob_cid, mime_type)
        if filename is not None:
            return filename
            
        if self.skip_blobs:
            # Don't bother downloading blobs
            return None
            
        try:
            # Fetch it to memory
            blob_data = self.agent.com.atproto.sync.get_blob(actor_did, blob_cid)
        except HTTPError as e:
            logger.error(f'Error downloading blob {blob_cid} from poster {actor_did}: %s' % e.read())
            return None
        
        # Save it
        self.put_blob(actor_did, blob_cid, mime_type, blob_data)
        
        if self.blob_delay > 0:
            logger.info(f"Waiting for {self.blob_delay} seconds after retrieving new blob")
            # Wait to avoid annoying the server
            time.sleep(self.blob_delay)
        
        # And return where we put it
        return super().get_blob_file(actor_did, blob_cid, mime_type)

class MerkleSearchTree:
    """
    Class to allow querying in a Merkle Search Tree.
    
    Keys are all bytes.
    """
    
    # Maximum possible TID (ID for a record in a collection in the tree), probably
    TID_MAX = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    
    def __init__(self, db: Datastore, actor_did: str, root_cid: CID):
        """
        Make a new Merkel Search Tree for the given account, rooted at the
        given CID. It will look up blocks in the given Datastore.
        """
        
        self.db = db
        self.actor_did = actor_did
        self.root_cid = root_cid
        
    def _reconstruct_keys(self, node_object: dict) -> List[bytes]:
        """
        Given an MST node, construct the full keys for all its children.
        """
        
        keys = []
        key = b''
        for entry in node_object['e']:
            # Each key is a prefix of the last one, plus some new stuff.
            key = key[:entry['p']] + entry['k']
            keys.append(key)
        
        return keys
        
    def items(self) -> Iterator[Tuple[bytes, Any]]:
        """
        Yield pairs of all keys and values in the tree.
        """
        
        # Do an in-order traversal
        def traverse(node_cid: CID) -> Iterator[Tuple[bytes, Any]]:
            # Get node object
            node_object = self.db.get_block(self.actor_did, node_cid)
            if node_object is None:
                logger.error("Missing tree node")
                return
            # First do the left subtree
            if 'l' in node_object and node_object['l'] is not None:
                for result in traverse(node_object['l']):
                    yield result
            
            # Reconstruct all the keys for this node.
            keys = self._reconstruct_keys(node_object)
            
            # Then do each item
            for key, entry in zip(keys, node_object['e']):
                # Yield the key and the value
                yield (key, entry['v'])
                if 't' in entry and entry['t'] is not None:
                    # Recurse on the right subtree
                    for result in traverse(entry['t']):
                        yield result
            
        return traverse(self.root_cid)
    
    def _index_in_node(self, node_object: dict, target_key: bytes, entry_keys: Optional[List[bytes]] = None) -> int:
        """
        Given a node object, find the index at which the key would be.
        
        -1: Before the first key
        Any other number: at or after that child.
        """
        if entry_keys is not None:
            # Re-use reconstructed keys
            keys = entry_keys
        else:
            # Reconstruct keys ourselves.
            keys = self._reconstruct_keys(node_object)
        # TODO: Just do a linear scan for now.
        # We could do binary search but this is like a 4-ary tree or something.
        index = -1
        for candidate_key in keys:
            if candidate_key <= target_key:
                index += 1
        return index
        
    def _stack_to(self, target_key: bytes) -> List[Tuple[dict, int]]:
        """
        Get the stack of all node objects and child indexes down to the one containing or not containing the given key.
        
        The given key is either at the final index in the final node object, or not in the tree.
        """
        
        stack = []
        node_cid = self.root_cid
        
        while node_cid is not None:
            # Get the object
            node_object = self.db.get_block(self.actor_did, node_cid)
            if node_object is None:
                logger.error("Missing tree node")
                return
            # Get the keys at this node
            entry_keys = self._reconstruct_keys(node_object)
            # Get the index in the node (-1 for left subtree)
            index = self._index_in_node(node_object, target_key, entry_keys=entry_keys)
            # Put it on the stack
            stack.append((node_object, index))
            
            if index == -1:
                # Key is in the left subtree, so go to that node.
                node_cid = node_object.get('l')
            elif len(node_object.get('e', [])) == 0:
                # Node has no entries. Tree is empty maybe?
                node_cid = None
            else:
                # Key is in an entry or its right subtree
                entry_key = entry_keys[index]
                if target_key == entry_key:
                    # We found it, stop here
                    node_cid = None
                else:
                    # It's not here but it could be in the right subtree if any
                    entry_object = node_object.get('e')[index]
                    node_cid = entry_object.get('t')
        
        # Now we have stacked up the whole state of the search.
        return stack
        
    def get(self, target_key: bytes) -> Optional[CID]:
        """
        Return the CID of the record at the given key, or None if the key is
        not in the tree.
        """
        
        # Do the whole search and just look at the last thing.
        node_object, index = self._stack_to(target_key)[-1]
        # So the key is either in this object at this entry, or not in the tree.
        
        if index == -1 or len(node_object.get('e', [])) == 0:
            # It isn't here at all.
            return None
        
        # Reconstruct the keys again. TODO: avoid repeating this?
        item_keys = self._reconstruct_keys(node_object)
        
        if item_keys[index] == target_key:
            # We actually have the item! Get the value!
            return node_object['e'][index]['v']
        else:
            # The item would be in the right subtree of the item here, except
            # that we stopped the search so we know it isn't. So it isn't in
            # the tree.
            return None

    def find_before(self, before_key: bytes, limit: Optional[int] = 1) -> Iterator[Tuple[bytes, CID]]:
        """
        Yield pairs of keys and values in reverse order, starting with the
        first key before the given key, and proceeding until the limit is
        reached or we run out of keys.
        """
        
        stack = self._stack_to(before_key)
        
        emitted = 0
        
        while len(stack) > 0 and (limit is None or emitted < limit):
            # Get the bottom frame
            node_object, index = stack[-1]
            
            if index == -1:
                # Nothing is left earlier in the tree at this level.
                stack.pop()
                continue
            
            # Get the keys. TODO: Avoid repeating! This will be O(order^2!)
            item_keys = self._reconstruct_keys(node_object)
            
            if len(item_keys) == 0:
                # Node is empty somehow.
                stack.pop()
                continue
            
            if before_key != item_keys[index]:
                # Emit the item here, unless it is exactly the key
                yield item_keys[index], node_object['e'][index]['v']
                emitted += 1
            
            # Move left
            index -= 1
            stack.pop()
            stack.append((node_object, index))
            
            if index >= 0:
                # There is an item that might have a right subtree. If so, recurse into the right subtree as far as we can go.
                child_node_cid = node_object['e'][index].get('t')
            else:
                # Start at the right edge of the left subtree, if any
                child_node_cid = node_object.get('l')
            while child_node_cid is not None:
                child_node_object = self.db.get_block(self.actor_did, child_node_cid)
                if child_node_object is None:
                    logger.error("Missing tree node")
                    return
                
                child_child_count = len(child_node_object['e'])
                
                # Start at the end of that child.
                child_node_index = child_child_count - 1
                stack.append((child_node_object, child_node_index))
                
                # Then look in its rightmost child
                if child_node_index == -1:
                    # Rightmost child is in the left subtree, if any
                    child_node_cid = child_node_object.get('l')
                else:
                    # Rightmost child is in the right subtree of the last item, if any.
                    child_node_cid = child_node_object['e'][child_node_index].get('t')
                    
    def find_before_from_collection(self, collection: bytes, before_key: bytes, limit: Optional[int] = 1) -> Iterator[Tuple[bytes, CID]]:
        """
        Iterate over items in the given collection (i.e. starting with the
        given key prefix), at or before the given key prefix, in reverse order.
        Stops when an item not in the collection is encountered or after
        producing limit items.
        """
        
        for k, v in self.find_before(before_key, limit):
            if not k.startswith(collection):
                # Out of the collection!
                return
            yield k, v
                
def dump_blob_object(db: Datastore, actor_did: str, blob_object: dict) -> Optional[str]:
    """
    Dump a blob-referencing object to a filename. Return the filename, or None
    if it can't be gotten.
    
    Takes a blob object with '$type' set to 'blob', a 'ref' CID, and maybe a 'mimeType'.
    """
    
    blob_cid = blob_object.get('ref')
    blob_mime = blob_object.get('mimeType', 'unknown/unknown')
    
    return db.get_blob_file(actor_did, blob_cid, blob_mime)
    
def linkify(href: str, text: str) -> str:
    """
    Make an OSC-8 link to a URL.
    """
    
    return f"\033]8;;{href}\033\\{text}\033]8;;\033\\"
    
def filename_to_url(filename: str) -> str:
    """
    Turn a filename into a URL for use with an OSC-8 hyperlink.
    """
    
    return f"file://localhost{os.path.realpath(filename)}"
    
def cid_to_url(blob_cid: CID) -> str:
    """
    Turn a blob CID into an HTTP URL on an IPFS gateway.
    """
    
    return f"https://ipfs.io/ipfs/{blob_cid}"
    
def blob_link(db: Datastore, actor_did: str, blob_object: dict, link_text: str, alt_text: str) -> str:
    """
    Turn a blob object into a clickable OSC-8 hyperlink.
    Links to the blob on the local filesystem if possible.
    If the blob is not available, displays the alt text.
    """
    
    blob_file = dump_blob_object(db, actor_did, blob_object)
    if blob_file is not None:
        # Link to local file on disk
        return linkify(filename_to_url(blob_file), link_text)
    else:
        return alt_text
        
def handle_post(action: dict, actor: str= ""):
    """
    Nicely format a skeet used to give context to another skeet.
    """
    pp = pprint.PrettyPrinter(indent=4)
    print(f"     > {actor} Skeeted:")
    print("")
    formatted = re.sub('\n', '\n     > ', action['text'])
    print(f"     > {formatted}")
    print("")
    if 'reply' in action:
        # This is a reply
        print(f"     > In reply to: {action['reply']['parent']['uri']}")
        if action['reply']['parent']['uri'] != action['reply']['root']['uri']:
            print(f"     > In thread: {action['reply']['root']['uri']}")
    for facet in action.get('facets', []):
        # It has a link or something. Facets have text ranges and a
        # collection of features.
        for feature in facet.get('features', []):
            if feature['$type'] == 'app.bsky.richtext.facet#link':
                print(f"     > With link to: {feature['uri']}")
            else:
                print("    > With unknown feature:")
                print("    > ", re.sub("\n", "\n     > ", pp.pformat(feature)))
    if 'embed' in action:
        # It comes with a file or something.
        embed = action['embed']
        if embed['$type'] == 'app.bsky.embed.images':
            print("    > With images:")
            for image in embed['images']:
                if image.get('alt', False):
                    print(f"    >   {image['alt']}")
        elif embed['$type'] == 'app.bsky.embed.record' and 'record' in embed and 'uri' in embed['record']:
            print(f"     > As a quote-skeet of: {embed['record']['uri']}")
        elif embed['$type'] == 'app.bsky.embed.recordWithMedia' and 'record' in embed and 'uri' in embed['record']:
            print(f"     > As a quote-skeet with media of: {embed['record']['uri']}")
        elif embed['$type'] == 'app.bsky.embed.recordWithMedia' and 'record' in embed and 'record' in embed['record'] and 'uri' in embed['record']['record']:
            # TODO: how deep can these nest???
            print(f"     > As a quote-skeet with media of: {embed['record']['record']['uri']}")
        else:
            print("     > With unknown embed:")
            print("     > ", re.sub("\n", "\n     > ", pp.pformat(embed)))

def get_and_dump_record(db: Datastore, uri: str, cid: str):
    """
    Go get and report a record that is used to give context to another record.
    """
    pp = pprint.PrettyPrinter(indent=4)
    try:
        did, nsi, rkey = re.split("/", re.sub("^at://", "", uri))
        # This will get the record if it is not found, without also getting the
        # whole other repo.
        action = db.get_block(did, cid, collection=nsi, rkey=rkey)
    except HTTPError as e:
        # Print the response body
        print('    > Error getting record. %s' % e.read())
        return
    except Exception as e:
        print('    > Error getting record. %s' % e)
        return

    if not action:
        print(f"{uri} not found")
        return
    if '$type' not in action:
        print("    > Not an action")
        return
    schema = action['$type']
    if schema == 'app.bsky.feed.post':
        handle_post(action, actor=did)
    elif schema == 'app.bsky.feed.repost':
        print(f"    > {did} Reskeeted: {action['subject'].get('uri')}")
    else:
        print(f'    > {did} Unknown action: {schema}')
        pp.pprint(action)


def dump_action(db: dict, actor_did: str, cid: CID, skip_records: bool = False):
    """
    Dump a Bluesky social action (post, like, profile, etc.).
    
    If skip_records is true, don't fetch and inline reskeeted/liked/replied-to
    records.
    """
    
    pp = pprint.PrettyPrinter(indent=4)
    
    action = db.get_block(actor_did, cid)
    if action is None:
        logger.error("Missing action")
        return
        
    if '$type' not in action:
        logger.error("Not an action")
        return
    
    if 'createdAt' in action:
        print(f"=== At: {action['createdAt']} ===")
    
    schema = action['$type']
    if schema == 'app.bsky.actor.profile':
        # Print their profile
        # Profiles usually are first in the tree due to the names of things.
        print(f"Profile information for: {action.get('displayName')}{' [BOT]' if action.get('bot') else ''}")
        print("")
        print(action.get('description'))
        print("")
        if action.get('avatar'):
            # See if we can get the avatar.
            # If it isn't downloaded and --skip_blobs is set, we won't have it.
            print(blob_link(db, actor_did, action['avatar'], "View Avatar", "Avatar unavailable"))
    elif schema == 'app.bsky.feed.like':
        print(f"Liked post: {action['subject']['uri']}")
        if not skip_records:
            get_and_dump_record(db, uri=action['subject']['uri'], cid=action['subject']['cid'])
    elif schema == 'app.bsky.feed.post':
        print("Skeeted:")
        print("")
        print(action['text'])
        print("")
        if 'reply' in action:
            # This is a reply
            print(f"In reply to: {action['reply']['parent']['uri']}")
            if not skip_records:
                get_and_dump_record(db, uri=action['reply']['parent']['uri'], cid=action['reply']['parent']['cid'])
            if action['reply']['parent']['uri'] != action['reply']['root']['uri']:
                print(f"In thread: {action['reply']['root']['uri']}")
                if not skip_records:
                    get_and_dump_record(db, uri=action['reply']['root']['uri'], cid=action['reply']['root']['cid'])
        for facet in action.get('facets', []):
            # It has a link or something. Facets have text ranges and a
            # collection of features.
            for feature in facet.get('features', []):
                if feature['$type'] == 'app.bsky.richtext.facet#link':
                    print(f"With link to: {linkify(feature['uri'], feature['uri'])}")
                else:
                    print("With unknown feature:")
                    pp.pprint(feature)
        if 'embed' in action:
            # It comes with a file or something.
            embed = action['embed']
            if embed['$type'] == 'app.bsky.embed.images':
                print("With images")
                for image in embed['images']:
                    # See if we can get the image.
                    # If it isn't downloaded and --skip_blobs is set, we won't have it.
                    desc = image.get('alt') or "(Undescribed image)"
                    print("  ", blob_link(db, actor_did, image['image'], f"View Image: {desc}", desc))
            elif embed['$type'] == 'app.bsky.embed.record' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet of: {embed['record']['uri']}")
                if not skip_records:
                    get_and_dump_record(db, uri=embed['record']['uri'], cid=embed['record']['cid'])
            elif embed['$type'] == 'app.bsky.embed.recordWithMedia' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet with media of: {embed['record']['uri']}")
                if not skip_records:
                    get_and_dump_record(db, uri=embed['record']['uri'], cid=embed['record']['cid'])
            else:
                print("With unknown embed:")
                pp.pprint(embed)
    elif schema == 'app.bsky.feed.repost':
        print(f"Reskeeted: {action['subject'].get('uri')}")
        if not skip_records:
            get_and_dump_record(db, uri=action['subject']['uri'], cid=action['subject']['cid'])
    elif schema == 'app.bsky.graph.block':
        print(f"Blocked: {action['subject']}")
    elif schema == 'app.bsky.graph.follow':
        print(f"Followed: {action['subject']}")
    else:
        print(f'Unknown action: {schema}')
        pp.pprint(action)
        
def get_tree(db: Datastore, actor_did: str, root_cid: CID) -> Optional[MerkleSearchTree]:
    """
    Get the MerkleSearchTree for an account, from the given root commit, if its
    root is here.
    """
    
    root = db.get_block(actor_did, root_cid)
    if root is None:
        logger.error("Missing root commit")
        return
    
    # Whose profile is this again?
    assert actor_did == root['did']
    
    data_cid = root['data']
    data = db.get_block(actor_did, data_cid)
    if data is None:
        # Tree isn't here
        return None
        
    # Now we decode the Merkle Search Tree (MST).
    # See https://atproto.com/specs/atp#repo-data-layout
    mst = MerkleSearchTree(db, actor_did, data_cid)
    
    return mst
                
def dump_repo(db: Datastore, actor_did: str, mst: MerkleSearchTree, skip_records: bool = False):
    """
    Given a repo with its actor and their account tree, traverse it.
    
    If skip_records is True, don't include referenced content.
    """
    
    # We track the keys we interpreted normally
    seen_keys = set()
    
    profile_cid = mst.get(b'app.bsky.actor.profile/self')
    if profile_cid is not None:
        # Report the profile
        print("")
        print("Profile:")
        dump_action(db, actor_did, profile_cid, skip_records=skip_records)
        seen_keys.add(b'app.bsky.actor.profile/self')
    else:
        print("No profile found.")
        
    def dump_collection(collection: bytes):
        """
        Dump a collection in reverse order.
        """
        for k, v in mst.find_before_from_collection(collection + b'/', collection + b'/' + MerkleSearchTree.TID_MAX, limit=None):
            dump_action(db, actor_did, v, skip_records=skip_records)
            seen_keys.add(k)
    
    # Do each kind of action, each in its own reverse-chronological order
    
    print("")
    print("Skeets (newest first):")
    dump_collection(b'app.bsky.feed.post')
    
    print("")
    print("Reskeets (newest first):")
    dump_collection(b'app.bsky.feed.repost')
    
    print("")
    print("Likes (newest first):")
    dump_collection(b'app.bsky.feed.like')
    
    print("")
    print("Follows (newest first):")
    dump_collection(b'app.bsky.graph.follow')
    
    print("")
    print("Blocks (newest first):")
    dump_collection(b'app.bsky.graph.block')
   
   
    # Then do a final scan over the whole tree forward, looking for anything we
    # didn't manage to pull the first time.
    unhandled_count = 0
    extraneous_count = 0
    for k, v in mst.items():
        if k not in seen_keys:
            logger.warning(f"Found unhandled key {k}")
            if k.startswith(b'app.bsky') and isinstance(v, CID):
                # Still looks like a bsky action so try and handle it.
                dump_action(db, actor_did, v, skip_records=skip_records)
                unhandled_count += 1
                logger.warning(f"Path: {[x[1] for x in mst._stack_to(k)]}")
            else:
                logger.error(f"Extraneous key: {repr(k)} with value {repr(v)}")
                extraneous_count += 1
            
    logger.info(f"Handled {len(seen_keys)} actions; {unhandled_count} unhandled actions; found {extraneous_count} unusable keys")
            

def decode_json(response: bytes) -> dict:
    """
    Decode JSON bytes to a dict structure.
    """
    return json.loads(response.decode('utf-8'))

def main():
    """
    Main function. Download ATP repo and explain it.
    """
    
    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description='Sync and explore Bluesky ATP data without an account'
    )
    parser.add_argument(
        "target",
        type=str,
        help="Handle ('somebody.bsky.social'), DID ('did:plc:xxxxx'), URI ('at://...'), or .car filename to fetch feed from"
    )
    parser.add_argument(
        '--out_dir',
        type=str,
        default='./store',
        help="Directory for local data store to populate. Default: %(default)s)"
    )
    parser.add_argument(
        '--server',
        default='https://bsky.social',
        help="AT Protocol Personal Data Server, as an HTTP URL. Default: %(default)s"
    )
    parser.add_argument(
        '--blob_delay',
        type=float,
        default=1.0,
        help="Wait this long after downloading a blob to avoid annoying the server."
    )
    parser.add_argument(
        '--skip_blobs',
        action='store_true',
        help="Don't download blobs from the server"
    )
    parser.add_argument(
        '--skip_records',
        action='store_true',
        help="Don't download referenced content (re-skeeted skeets, etc.)"
    )
    parser.add_argument(
        '--local',
        action='store_true',
        help="Don't use the network; work locally only."
    )
    parser.add_argument(
        '--root',
        type=CID,
        help="Use the given CID as the root commit instead of whatever is current."
    )

    options = parser.parse_args()
    
    if options.local:
        # Don't use an API client
        agent = None
        
        # Use a local data store only
        data_store = DiskDatastore(options.out_dir)
    else:
        logger.info(f"Using API: {options.server}")
        
        # Make an API client
        agent = BskyAgent(service=options.server)
        
        # Make a data store to hold our synced data.
        data_store = SyncingDatastore(options.out_dir, agent, options.blob_delay, options.skip_blobs)
    
    if os.path.exists(options.target):
        logger.info(f"Interpreting {options.target} as a local file.")
        car_filename = options.target
        
        # Read the whole CAR
        car_records = decode_car_of_dag_cbor(open(car_filename, 'rb'))
        
        if options.root is not None:
            # Use a specific root
            head_root = options.root
            logger.info(f"Using specific root: {head_root}")
        else:
            # Guess the root from the header
            logger.info(f"Autodetecting root from CAR header")
            head_root = car_records['header']['roots'][0]
        # And then get the DID from the root commit
        actor_did = car_records[head_root]['did']
        
        del car_records['header']
        
        logger.info(f"Storing {len(car_records)} blocks from CAR into datastore...")
        
        for k, v in car_records.items():
            # Store all the blocks in the data store for this actor.
            data_store.put_block(actor_did, k, v)
    else:
        if options.target.startswith('did:'):
            logger.info(f"Interpreting {options.target} as a DID.")
            actor_did = options.target
            # Just get all keys
            item_key = None
        elif options.target.startswith('at://'):
            # Like at://did:plc:uraielgolztbeqrrv5c7qbce/app.bsky.feed.post/3juuag73erg22
            logger.info(f"Interpreting {options.target} as a URI.")
            # Drop the prefix and split on the first slash
            actor_did, item_key_string = options.target[5:].split('/', 1)
            # And make sure the item key is bytes
            item_key = item_key_string.encode('utf-8')
            logger.info(f"Need to fetch {item_key} from profile with DID {actor_did}")
        else:
            logger.info(f"Interpreting {options.target} as a handle, because it does not exist as a file and does not start with 'did:'.")
            repo = options.target
            
            if agent is None:
                # We really need the network for this.
                logger.critical("Cannot resolve a handle locally.")
                sys.exit(1)
            
            did_response = decode_json(agent.com.atproto.identity.resolve_handle(handle=repo))
            actor_did = did_response['did']
            logger.info(f"Resolved {repo} to {actor_did}")
            # Just get all keys
            item_key = None
        if options.root is not None:
            head_root = options.root
            logger.info(f"Using specific root: {head_root}")
        else:
            logger.info("Get HEAD of repo")
            if agent is None:
                # We really need the network for this.
                logger.critical("Cannot resolve a handle locally.")
                sys.exit(1)
            head_response = decode_json(agent.com.atproto.sync.get_head(did=actor_did))
            head_root = CID(head_response['root'])
            logger.info(f"Repo is rooted at {head_root}")
        
    # Now we always have head_root and actor_did
    
    # Open up the tree (AKA database shard) for the actor
    mst = get_tree(data_store, actor_did, head_root)
    if mst is None:
        # Root of MST tree is not available
        logger.error("Account Merkle Search Tree root is not available")
        sys.exit(1)
    
    if item_key is not None:
        # We want a particular key
        item = mst.get(item_key)
        if item is None:
            # It isn't there
            logger.error(f"Item {item_key} not found in Merkle Search Tree")
            sys.exit(1)
        else:
            # We found it
            print(f"Single item {item_key}:")
            dump_action(data_store, actor_did, item, skip_records=options.skip_records)
            logger.info(f"Retrieved single item")
    else:
        logger.info(f"Dumping feed rooted at {head_root} from repo for {actor_did}") 
        dump_repo(data_store, actor_did, mst, skip_records=options.skip_records)


try:
    main()
except HTTPError as e:
    # Print the response body
    print('Error: %s' % e.read())
    
    
    

