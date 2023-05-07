# Skyfall: Browse Bluesky (and other AT Protocol servers) without an account

## Quickstart

```
python3.9 -m virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
./skyfall.py whoever.bsky.social
```

## About

Are all your friends [skeeting in hellthread](https://knowyourmeme.com/memes/events/hellthread-hellrope-bluesky) without you? Does Jack Dorsey not think you're cool, leaving you stuck paying homage to other, lesser billionaires? Well, worry no more! With **Skyfall**, you can **see what's going on on Bluesky** and other compatible services **without needing an invite code, or even an account!**.

Simply clone the repo, install the dependencies, and point Skyfall at someone's handle or Decentralized Identifier (DID), and bask in the glory of their skeets, delivered straight to your standard output device!

Consider, for example, this fine skeet by jesopo-test.bsky.social: 

```
=== At: 2023-04-18T23:37:27.810Z ===
Skeeted:

test post please ignore

```

Enjoy(?) the future of social media today!

## Hot Tips and Known Issues

* You may want to send the output to a file.
* If you want to talk to a server other than Jack Dorsey's™ Bluesky™, use the `--server` option with an HTTP URL.
* Profile CAR archives, block data, and image blobs will be dumped in './store' by default, organized by profile DID, type, and hash prefix. To put them somewhere else, use the `--out_dir` option.
* Sync is terrible but it *is* now an attempt at a sync; use the same `--out_dir` repeatedly to re-use existing data.
* You can re-load a CAR file by passing it to the script again, without re-downloading it.
* Use your powers for good, not evil. Bluesky as a community remains invite-only; things people posted there are possibly not yet intended to be widely distributed on the open Internet. This tool dumps whole repos because I was too lazy to write a UI, not so you can steal them and put them up for Google. Be respectful.
* When trying to fetch blobs, you may see something like: `{"error":"InvalidRequest","message":"Temporarily disabled: com.atproto.sync.getBlob"}`. It looks like Bluesky turned off their blob-serving API shortly after I implemented it. Perhaps it will come back soon.
* Information comes out in internal storage order: profile, likes, posts, blocks, follows. This is because I only barely got the Merkle Search Tree iterator working and did not want to implement the RocksDB-style range search on keys that you are really supposed to use.
* `at://` URIs are not supported as arguments! Use just a handle or DID, and then hope you can find the particular thing being linked to in there somewhere.

## How does this work?

Skyfall implements a trivial version of the not-really-explained but also fairly straightforward [cross-server sync portion](https://atproto.com/lexicons/com-atproto-sync) of the Authenticated Transfer (AT) Protocol, as used by Bluesky. While Bluesky's web frontend and its social-media-level API require authentication, the server-facing AT Protocol sync API is meant to be public, so that other AT Protocol based instances can federate with Bluesky. Skyfall syncs the AT Protocol repo containing whatever you want to look at to a local datastore, and then decodes the file to display the content.

Skyfall uses [Chitose](https://github.com/mnogu/chitose) to make API requests, and handles parsing the [Interplanetary Linked Data (IPLD)](https://ipld.io)-defined [Content-Addressable aRchive](https://ipld.io/specs/transport/car/carv1/) files and the [Merkle Search Trees](https://atproto.com/specs/atp#repo-data-layout) they contain, which in turn contain actual "skeets" (Bluesky Tweets, AKA posts). It also downloads media for skeets individually.
