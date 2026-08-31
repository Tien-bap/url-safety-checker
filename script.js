function sha256(text) {
    return CryptoJS.SHA256(text).toString(); 
}

hash_map = null
onload = async function() {
    const result = await fetch('hashes.json');
    const data = await result.json();
    hash_map = data;
    console.log("Loaded", Object.keys(hash_map).length, "hashes");
}

function handleURLInput() {
    const url = document.getElementById('urlInput').value;
    const result = checkURL(url);
    document.getElementById('result').innerText = result;
}


function checkURL(url) {
    const hash_url = sha256(url);
    const hash_url_8 = hash_url.slice(0, 8);
    
    if(hash_map.hasOwnProperty(hash_url_8)) {
        const fullHashes = hash_map[hash_url_8];
        if(fullHashes.includes(hash_url)) {
            return "The URL is unsafe (found in the database).";
        } else {
            return "The URL is safe (not found in the database).";
        }
    } else {
        return "The URL is safe (not found in the database).";
    }

}