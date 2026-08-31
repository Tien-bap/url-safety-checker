import requests, hashlib, json


data = requests.get("https://openphish.com/feed.txt").text
urls = data.split("\n")

hash_map = {}

for url in urls:
    hash = hashlib.sha256(url.encode()).hexdigest()
    hash_8 = hash[:8]
    if hash_8 not in hash_map:
        hash_map[hash_8] = []
    hash_map[hash_8].append(hash)

with open("./hashes.json", "w") as f:
    json.dump(hash_map, f)