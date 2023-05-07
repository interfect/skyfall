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
from typing import Any, Optional, Tuple, Iterator

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
    
    while len(stream.peek(1)) > 0:
        item_length = leb128.u.decode_reader(stream)[0]
        item = stream.read(item_length)
        # Decode self-delimiting multihash CID, and then the data after it.
        cid_text, cid_byte_length = CID.decode_reader(io.BufferedReader(io.BytesIO(item)))
        # The item is DAG-CBOR
        result[cid_text] = decode_dag_cbor(item[cid_byte_length:])
        
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
    
    def get_block(self, actor_did: str, block_cid: CID) -> Optional[dict]:
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
        
    
    def get_block(self, actor_did: str, block_cid: CID) -> Optional[dict]:
        """
        Get the decoded block from the repo for the given account, with the
        given CID, or None if it is not stored.
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
        
        Wait blob_delay after successfully fetching a blob.
        """
        super().__init__(root_dir)
        self.agent = agent
        self.blob_delay = blob_delay
        self.skip_blobs = skip_blobs
        
    def get_block(self, actor_did: str, block_cid: CID) -> Optional[dict]:
        """
        Get the block from the local store. If not there, sync it and related blocks.
        """
        
        block = super().get_block(actor_did, block_cid)
        if block is not None:
            return block
        
        # Now we need to sync it
        # TODO: Implement sync based on what we already have for this DID. For now just get the whole repo.
        
        logger.info(f"Get CAR file for repo {actor_did}")
        
        car_path = os.path.join(self.root_dir, 'repos', self.did_to_path(actor_did) + '.car')
        os.makedirs(os.path.dirname(car_path), exist_ok=True)
        # TODO: This is probably big; the library should maybe hand back a stream
        # here?
        car_bytes = self.agent.com.atproto.sync.get_repo(did=actor_did)
        open(car_path + '.tmp', 'wb').write(car_bytes)
        del car_bytes
        os.rename(car_path + '.tmp', car_path)
        logger.info(f"Saved feed data to {car_path}")
        
        # Now we read it back and insert it all.
        car_records = decode_car_of_dag_cbor(open(car_path, 'rb'))
        
        for k, v in car_records.items():
            if k == 'header':
                # Skip the header
                continue
            # Store all the blocks in ourselves.
            self.put_block(actor_did, k, v)
            
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
            logger.info(f"Waiting for {blob_delay} seconds after retrieving new blob")
            # Wait to avoid annoying the server
            time.sleep(self.blob_delay)
        
        # And return where we put it
        return super().get_blob_file(actor_did, blob_cid, mime_type)

class MerkleSearchTree:
    """
    Class to allow querying in a Merkle Search Tree.
    
    Keys are all bytes.
    """
    
    def __init__(self, db: Datastore, actor_did: str, root_cid: CID):
        """
        Make a new Merkel Search Tree for the given account, rooted at the
        given CID. It will look up blocks in the given Datastore.
        """
        
        self.db = db
        self.actor_did = actor_did
        self.root_cid = root_cid
        
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
            
            # Reset key prefix at every node.
            key = b''
            
            # Then do each item
            for entry in node_object['e']:
                # Compose the full key based on the key just to the left of
                # here.
                key = key[:entry['p']] + entry['k']
                # Yield the key and the value
                # TODO: Can't yield from caller here.
                yield (key, entry['v'])
                if 't' in entry and entry['t'] is not None:
                    # Recurse on the right subtree
                    for result in traverse(entry['t']):
                        yield result
            
        return traverse(self.root_cid)
        


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
    
def blob_link(db: Datastore, actor_did: str, blob_object: dict, link_text: str) -> str:
    """
    Turn a blob object into a clickable OSC-8 hyperlink.
    Links to the blob on the local filesystem if possible, and on IPFS otherwise.
    """
    
    blob_file = dump_blob_object(db, actor_did, blob_object)
    if blob_file is not None:
        # Link to local file on disk
        return linkify(filename_to_url(blob_file), link_text + " (local)")
    else:
        # Link to file on IPFS via gateway, in hopes it is there.
        blob_cid = blob_object.get('ref')
        if blob_cid is None:
            return "<No Ref>"
        return linkify(cid_to_url(blob_cid), link_text + " (may be available in IPFS)")
        
def dump_action(db: dict, actor_did: str, cid: CID):
    """
    Dump a Bluesky social action (post, like, profile, etc.).
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
            # See if we can get the avatar
            print(blob_link(db, actor_did, action['avatar'], "View Avatar"))
    elif schema == 'app.bsky.feed.like':
        print(f"Liked post: {action['subject']['uri']}")
    elif schema == 'app.bsky.feed.post':
        print("Skeeted:")
        print("")
        print(action['text'])
        print("")
        if 'reply' in action:
            # This is a reply
            print(f"In reply to: {action['reply']['parent']['uri']}")
            if action['reply']['parent']['uri'] != action['reply']['root']['uri']:
                print(f"In thread: {action['reply']['root']['uri']}")
        for facet in action.get('facets', []):
            # It has a link or something. Facest have text ranges and a
            # collection of features.
            for feature in facet.get('features', []):
                if feature['$type'] == 'app.bsky.richtext.facet#link':
                    print(f"With link to: {feature['uri']}")
                else:
                    print("With unknown feature:")
                    pp.pprint(feature)
        if 'embed' in action:
            # It comes with a file or something.
            embed = action['embed']
            if embed['$type'] == 'app.bsky.embed.images':
                print("With images:")
                for image in embed['images']:
                    print(blob_link(db, actor_did, image['image'], f"View Image: \"{image.get('alt', '')}\""))
            elif embed['$type'] == 'app.bsky.embed.record' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet of: {embed['record']['uri']}")
            elif embed['$type'] == 'app.bsky.embed.recordWithMedia' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet with media of: {embed['record']['uri']}") 
            else:
                print("With unknown embed:")
                pp.pprint(embed)
    elif schema == 'app.bsky.feed.repost':
        print(f"Reskeeted: {action['subject'].get('uri')}")
    elif schema == 'app.bsky.graph.block':
        print(f"Blocked: {action['subject']}")
    elif schema == 'app.bsky.graph.follow':
        print(f"Followed: {action['subject']}")
    else:
        print(f'Unknown action: {schema}')
        pp.pprint(action)
                
def dump_repo(db: Datastore, actor_did: str, root_cid: CID):
    """
    Given a repo with its actor and root, traverse it.
    """
    
    pp = pprint.PrettyPrinter(indent=4)
    
    root = db.get_block(actor_did, root_cid)
    if root is None:
        logger.error("Missing root commit")
        return
    
    # Whose profile is this again?
    assert actor_did == root['did']
    
    data_cid = root['data']
    data = db.get_block(actor_did, data_cid)
    if data is None:
        logger.error("Missing tree root")
        return
        
    # Now we decode the Merkle Search Tree (MST).
    # See https://atproto.com/specs/atp#repo-data-layout
    mst = MerkleSearchTree(db, actor_did, data_cid)
    
    print("")
    print("Timeline:")
    
    action_count = 0
    unknown_count = 0
    
    for k, v in mst.items():
        if k.startswith(b'app.bsky') and isinstance(v, CID):
            # Looks like a bsky action or whatever they call it.
            dump_action(db, actor_did, v)
            action_count += 1
        else:
            print(f"Unknown key: {repr(k)} with value {repr(v)}")
            unknown_count += 1
    
    logger.info(f"Decoded {action_count} actions; failed to decode {unknown_count}")
            
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
        help="Handle ('somebody.bsky.social'), DID ('did:plc:xxxxx'), or .car filename to fetch feed from"
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
    logger.info(f"Dumping feed rooted at {head_root} from repo for {actor_did}") 
    dump_repo(data_store, actor_did, head_root)


try:
    main()
except HTTPError as e:
    # Print the response body
    print('Error: %s' % e.read())
    
    
    

