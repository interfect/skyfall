#!/usr/bin/env python3

import json
import re
import io
import os
import time
import sys
import base64
import pprint
import argparse
from typing import Any, Optional, Tuple, Iterator

try:
    import leb128
except ImportError:
    print("Error: install the leb128 module: pip install leb128")
    sys.exit(1)
    
try:
    import cbor2
except ImportError:
    print("Error: install the leb128 module: pip install leb128")
    sys.exit(1)

try:
    from chitose.agent import BskyAgent
except ImportError:
    print("Error: install the chitose module: pip install chitose")
    sys.exit(1)

from urllib.error import HTTPError

class CID(str):
    """
    Represents an IPLD CID, which is a hash-based key for identifying data.
    
    We store this as a special kind of string, where the string is the base-32
    lower-case unpadded "multibase" CID format.
    """
    
    def __repr__(self):
        return 'CID(' + str(self) + ')'
        
    @staticmethod
    def decode_bytes(cid_bytes: bytes) -> "CID":
        """
        Decode a CID represented as raw, non-0-prefixed bytes. 
        """
        return CID('b' + base64.b32encode(cid_bytes).decode('utf-8').lower().rstrip('='))

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
        
def decode_dag_cbor(data: bytes):
    """
    Decode IPLD DAG-CBOR format to Python objects.
    IPLD links are decoded as CID objects containing the string CID linked to.
    """
    
    return cbor2.decoder.loads(data, tag_hook=CID.tag_hook)
    
def decode_car_of_dag_cbor(stream) -> dict:
    """
    Decode an IPLD CAR file from a stream of bytes.
    
    Returns a dict with a 'header' key, and additionally CID keys pointing to
    their stored values. Values are all decoded as DAC-CBOR objects. All IPLD
    links will be CID strings.
    """
    
    print("Decoding CAR archive...")
    
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
    
class MerkleSearchTree:
    """
    Class to allow querying in a Merkle Search Tree.
    
    Keys are all bytes.
    """
    
    def __init__(self, db: dict, root_cid: CID):
        """
        Make a new Merkel Search Tree rooted at the given CID. It will look up
        CIDs in the given database of CIDs to values.
        """
        
        self.db = db
        self.root_cid = root_cid
        
    def items(self) -> Iterator[Tuple[bytes, Any]]:
        """
        Yield pairs of all keys and values in the tree.
        """
        
        # Do an in-order traversal
        def traverse(node_cid: CID) -> Iterator[Tuple[bytes, Any]]:
            # Get node object
            node_object = self.db[node_cid]
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
        
# What extensions should we use when saving embeds?        
MIME_TO_EXT = {
    'image/jpeg': 'jpg',
    'image/png': 'png'
}

def dump_blob(agent: BskyAgent, poster_did: str, blob_object: dict, hint: Optional[str] = None, out_dir: Optional[str] = None, blob_delay: float = 0.0) -> str:
    """
    Dump a blob to a file. Return the file name.
    
    Takes a blob object with '$type' set to 'blob', a 'ref' CID, and maybe a 'mimeType'.
    """
    
    blob_cid = blob_object.get('ref')
    if blob_object.get('mimeType') not in MIME_TO_EXT:
        print(f"Unknown MIME type: {blob_object.get('mimeType')}")
    blob_ext = MIME_TO_EXT.get(blob_object.get('mimeType'), 'dat')
    
    # Work out where to save it
    name = hint
    if name is None:
        name = 'blob'
    # Make the name filename-safe and reasonably short
    name = re.sub("[^A-Za-z0-9._-]", "", name.replace(' ', '_'))[:40]
    
    # Decide where to put it
    if out_dir is None:
        out_dir = '.'
    os.makedirs(out_dir, exist_ok=True)
    
    # Add extension and directory
    filename = os.path.join(out_dir, f'{name}-{blob_cid}.{blob_ext}')
    
    if os.path.exists(filename):
        # Already downloaded
        return filename
    
    try:
        # Fetch it to memory
        result_bytes = agent.com.atproto.sync.get_blob(poster_did, blob_cid)
    except HTTPError as e:
        print(f'Error downloading blob {blob_cid} from poster {poster_did}: %s' % e.read())
        return None
    
    # Save it
    open(filename, 'wb').write(result_bytes)
    
    # Wait the delay after a successful download
    time.sleep(blob_delay)
    
    return filename
    
def linkify(filename: str) -> str:
    """
    Make an OSC-8 link of a filename.
    """
    
    return f"\033]8;;file://localhost{os.path.realpath(filename)}\033\\{filename}\033]8;;\033\\"
    
        
def dump_action(db: dict, actor_did: str, cid: CID, agent: Optional[BskyAgent] = None, out_dir: Optional[str] = None, blob_delay: float = 0.0):
    """
    Dump a Bluesky social action (post, like, profile, etc.).
    
    Can use a BskyAgent to fetch blobs. Saves blobs to the given out_dir. After
    downloading a blob, waits for blob_delay seconds.
    """
    
    pp = pprint.PrettyPrinter(indent=4)
    
    action = db[cid]
    if '$type' not in action:
        print("Not an action")
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
        if action.get('avatar') and agent:
            # We can fetch an avatar
            filename = dump_blob(agent, actor_did, action['avatar'], "avatar", out_dir, blob_delay)
            if filename:
                print(f"Saved avatar to {linkify(filename)}")
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
                    filename = dump_blob(agent, actor_did, image['image'], image.get('alt') or "image", out_dir, blob_delay)
                    if filename:
                        print(f"Saved image to {linkify(filename)}")
            elif embed['$type'] == 'app.bsky.embed.record' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet of: {embed['record']['uri']}")
            elif embed['$type'] == 'app.bsky.embed.recordWithMedia' and 'record' in embed and 'uri' in embed['record']:
                print(f"As a quote-skeet with media of: {embed['record']['uri']}") 
            else:
                print("With unknown embed:")
                pp.pprint(embed)
        
    elif schema == 'app.bsky.graph.block':
        print(f"Blocked: {action['subject']}")
    elif schema == 'app.bsky.graph.follow':
        print(f"Followed: {action['subject']}")
    else:
        print(f'Unknown action: {schema}')
        pp.pprint(action)
                
def dump_repo(db: dict, root_cid: CID, agent: Optional[BskyAgent] = None, out_dir: Optional[str] = None, blob_delay: float = 0.0):
    """
    Given a repo with its root in the header, traverse it.
    
    Can use a BskyAgent to fetch blobs.
    """
    
    pp = pprint.PrettyPrinter(indent=4)
    
    root = db[root_cid]
    print('Repo HEAD root:')
    pp.pprint(root)
    
    # Whose profile is this again?
    actor_did = root['did']
    
    data_cid = root['data']
    data = db[data_cid]
    
    # Now we decode the Merkle Search Tree (MST).
    # See https://atproto.com/specs/atp#repo-data-layout
    mst = MerkleSearchTree(db, data_cid)
    
    print("")
    print("Timeline:")
    
    for k, v in mst.items():
        if k.startswith(b'app.bsky') and isinstance(v, CID):
            # Looks like a bsky action or whatever they call it.
            dump_action(db, actor_did, v, agent, out_dir, blob_delay)
        else:
            print(f"Unknown key: {k}")
            
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
        default='.',
        help="Directory to save output to. Default: %(default)s)"
    )
    parser.add_argument(
        '--server',
        default='https://bsky.social',
        help="AT Protocol Personal Data Server, as an HTTP URL. Default: %(default)s"
    )
    parser.add_argument(
        '--blob_delay',
        type=float,
        default=0.0,
        help='Wait this long after downloading a blob to avoid annoying the server.'
    )

    options = parser.parse_args()
    
    agent = BskyAgent(service=options.server)
    
    if os.path.exists(options.target):
        print(f"Interpreting {options.target} as a local file.")
        car_filename = options.target
        # Will need to guess the root
        head_root = None
    else:
        if options.target.startswith('did:'):
            print(f"Interpreting {options.target} as a DID.")
            did = options.target
        else:
            print(f"Interpreting {options.target} as a handle, because it does not exist as a file and does not start with 'did:'.")
            repo = options.target
            did_response = decode_json(agent.com.atproto.identity.resolve_handle(handle=repo))
            did = did_response['did']
            print(f"Resolved {repo} to {did}")
            
        print("Get HEAD of repo")
        head_response = decode_json(agent.com.atproto.sync.get_head(did=did))
        head_root = CID(head_response['root'])
        print(f"Repo is rooted at {head_root}")
        
        print("Get CAR file for repo")
        # TODO: This is probably big; the library should maybe hand back a stream
        # here?
        car_bytes = agent.com.atproto.sync.get_repo(did=did)
        # Save the CAR. Overwrite because it may have updated.
        # TODO: Real differential sync somehow.
        os.makedirs(options.out_dir, exist_ok=True)
        car_filename = os.path.join(options.out_dir, 'feed-data.car')
        open(car_filename, 'wb').write(car_bytes)
        # Drop from memory
        del car_bytes
        print(f"Saved feed data to {car_filename}")
        # Now car_filename exists and can be used later.
    
    print(f"Decoding {car_filename} to CID database")
    # This maps from CID to decoded structure
    data_store = {}
    # This one gets an IPLD CAR file
    data_store.update(decode_car_of_dag_cbor(open(car_filename, 'rb')))
    
    if head_root is None:
        print("Autodetecting root from CAR")
        head_root = data_store['header']['roots'][0]
    
    print(f"Dumping feed rooted at {head_root} from repo") 
    dump_repo(data_store, head_root, agent=agent, out_dir=options.out_dir, blob_delay=options.blob_delay)


try:
    main()
except HTTPError as e:
    # Print the response body
    print('Error: %s' % e.read())
    
    
    

