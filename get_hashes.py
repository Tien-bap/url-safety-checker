import requests, hashlib, json

FEEDS = [
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "type": "text"
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "text"
    },
    {
        "name": "Abuse.ch SSLBL",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "text"
    },
    {
        "name": "Botvrij",
        "url": "https://www.botvrij.eu/data/ioclist.url.raw",
        "type": "text"
    },
]

def fetch_text_feed(url):
    res = requests.get(url, timeout=10)
    lines = res.text.strip().split("\n")
    # bỏ comment
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]

def hash_url(url):
    return hashlib.sha256(url.encode()).hexdigest()

hash_map = {}
total = 0

for feed in FEEDS:
    try:
        urls = fetch_text_feed(feed["url"])
        for url in urls:
            h = hash_url(url)
            prefix = h[:8]
            if prefix not in hash_map:
                hash_map[prefix] = []
            if h not in hash_map[prefix]:
                hash_map[prefix].append(h)
        print(f"{feed['name']}: {len(urls)} URLs")
        total += len(urls)
    except Exception as e:
        print(f"{feed['name']} failed: {e}")

print(f"Total: {total} URLs → {len(hash_map)} prefixes")

with open("hashes.json", "w") as f:
    json.dump(hash_map, f)