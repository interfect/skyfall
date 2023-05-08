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

Consider, for example, this fine skeet by @jesopo-test.bsky.social: 

```
=== At: 2023-04-18T23:37:27.810Z ===
Skeeted:

test post please ignore

```

Skyfall is also compatible with other AT Protocol deployments, such as [stems.social](https://stems.social), which is also not currently accepting new users (and which uses non-IANA domains for handles for some reason). You can do, for example:
```
./skyfall.py --server https://stems.social browse.records
```
This gets you fine skeets from someone alleging to be @browse.records, such as:
```
=== At: 2023-04-30T14:34:02.628Z ===
Skeeted:

Durand Jones & the Indications - Is It Any Wonder?

https://www.youtube.com/watch?v=hIHxDxTcuDk

With link to: https://www.youtube.com/watch?v=hIHxDxTcuDk
With images:
View Image: "" (local)
```

Although you can't see it on Github, Skyfall's output is enhanced with [the finest in terminal hyperlink technology](https://github.com/Alhadis/OSC8-Adoption/), allowing you to click on a link in your terminal and be *literally transported* to its destination in mere milliseconds!

Enjoy(?) the future of social media today!

## URI Support

You can resolve `at://` URIs with Skyfall!

For example:

```
./skyfall.py at://did:plc:mf5dzzqkp7fnmby6blfeljwj/app.bsky.feed.post/3jufymasfaw23
```

This will print out a single skeet, after downloading several tens of thousands of blocks from the poster's profile, and writing them all to files on your disk. This is useful for following chains of replies, reskeets, and quote-skeets. Truly, we are achieving new frontiers in technological progress.

## Hot Tips and Known Issues

* You may want to send the output to a file.
* If you want to talk to a server other than Jack Dorsey's™ Bluesky™, use the `--server` option with an HTTP URL.
* Profile CAR archives, block data, and image blobs will be dumped in './store' by default, organized by profile DID, type, and hash prefix. To put them somewhere else, use the `--out_dir` option.
* The datastore is terrible and stores every block as a file. Seemingly normal profiles have tens of thousands of blocks for a few thousand posts for no apparent reason. Try not to run out of inodes.
* Sync is terrible but it *is* now an attempt at a sync; use the same `--out_dir` repeatedly to re-use existing data.
* You can re-load a CAR file by passing it to the script again, without re-downloading it.
* Use your powers for good, not evil. Bluesky as a community remains invite-only; things people posted there are possibly not yet intended to be widely distributed on the open Internet. This tool dumps whole repos because I was too lazy to write a UI, not so you can steal them and put them up for Google. Be respectful.
* When trying to fetch blobs, you may see something like: `{"error":"InvalidRequest","message":"Temporarily disabled: com.atproto.sync.getBlob"}`. It looks like Bluesky turned off their blob-serving API shortly after I implemented it. Perhaps it will come back soon. Other AT Protocol instances work fine.
* Information comes out organized by action type (so the profile, then all the skeets, then all the reskeets, etc.). This required implementing really annoying Merkle Search Tree reverse range queries.

## How does this work?

Skyfall implements a trivial version of the not-really-explained but also fairly straightforward [cross-server sync portion](https://atproto.com/lexicons/com-atproto-sync) of the Authenticated Transfer (AT) Protocol, as used by Bluesky. While Bluesky's web frontend and its social-media-level API require authentication, the server-facing AT Protocol sync API is meant to be public, so that other AT Protocol based instances can federate with Bluesky. Skyfall syncs the AT Protocol repo containing whatever you want to look at to a local datastore, and then decodes the file to display the content.

Skyfall uses [Chitose](https://github.com/mnogu/chitose) to make API requests, and handles parsing the [Interplanetary Linked Data (IPLD)](https://ipld.io)-defined [Content-Addressable aRchive](https://ipld.io/specs/transport/car/carv1/) files and the [Merkle Search Trees](https://atproto.com/specs/atp#repo-data-layout) they contain, which in turn contain actual "skeets" (Bluesky Tweets, AKA posts). It also downloads media for skeets individually.
