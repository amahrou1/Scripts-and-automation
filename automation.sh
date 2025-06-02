#!/bin/bash

# Subdomain Enumeration

# Prompt the user for the target domain
read -p "Enter the target domain: " target

# Run the dig command and count the results
result_count=$(dig @1.1.1.1 A,CNAME {test321123,testingforwildcard,plsdontgimmearesult}.$target +short | wc -l)

# Check if the result count is 0
if [ $result_count -eq 0 ]; then
  echo "No results found. Running subdomain enumeration tools..."

  # Create hosts-wordlist.txt from subdomains-top1million-20000.txt
  sed "s/$/.$target/" /root/myLists/subdomains.txt  >> hosts-wordlist.txt

  # Run massdns
  massdns -r /root/myLists/resolvers.txt  -t A -o S -w massdns.out hosts-wordlist.txt

  # Extract subdomains and IPs
  cat massdns.out | awk '{print $1}' | sed 's/.$//' | sort -u > subs.txt
  cat massdns.out | awk '{print $3}' | sort -u | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ips-online.txt

  # Use httpx to check for live subdomains
  cat subs.txt | httpx | tee -a wordlist-subs.txt

  # Cleanup
  rm hosts-wordlist.txt massdns.out subs.txt

  # Run other subdomain enumeration tools
  echo "Running amass command..."
  amass enum -passive -norecursive -noalts -d $target >> subs1.txt
  echo "Running subfinder command..."
  subfinder -d $target  >> subs1.txt
  echo "Running assetfinder command..."
  assetfinder -subs-only $target >> subs1.txt
  echo "Running findomain command..."
  findomain -t $target --quiet >> subs1.txt
  echo "Running cat and sort commands..."
  cat subs1.txt | sort -u > subs2.txt
  echo "Running httpx command..."
  cat subs2.txt | httpx > subs3.txt
  echo "Running grep command..."
  grep -vf subs3.txt wordlist-subs.txt > bruteforce-subs.txt
  cat subs3.txt wordlist-subs.txt | sort -u > subdomains.txt
  rm wordlist-subs.txt subs1.txt subs2.txt subs3.txt
else
  echo "Results found. Running subdomain enumeration tools..."

  # Run subdomain enumeration tools when results are found
  echo "Running amass command..."
  amass enum -passive -norecursive -noalts -d "$target" >> subs1.txt
  echo "Running subfinder command..."
  subfinder -d "$target" -all >> subs1.txt
  echo "Running assetfinder command..."
  assetfinder -subs-only "$target" >> subs1.txt
  echo "Running findomain command..."
  findomain -t "$target" --quiet >> subs1.txt
  echo "Running cat and sort commands..."
  cat subs1.txt | sort -u > subs2.txt
  echo "Running httpx command..."
  cat subs2.txt | httpx > subdomains.txt
  # Cleanup
  echo "Cleaning up..."
  rm subs1.txt subs2.txt
fi

# Nuclei Test
nuclei -l subdomains.txt -t /root/test123/ | tee -a nuclei.txt

# Port Scan
for sub in $(cat subdomains.txt); do
    sub_without_protocol=$(echo "$sub" | sed -e 's~^https\?://~~')
    echo "Modified URL: $sub_without_protocol"

    # Perform a nmap scan
    nmap -p- "$sub_without_protocol" | tee -a nmap.txt
    echo -e "\e[32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m"
done

#url crawling
cat subdomains.txt | waybackurls | tee -a gau.txt && katana  -list subdomains.txt -duc -silent -nc -jc -kf -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg | tee -a katana.txt && katana -list subdomains.txt -fs fqdn -f qurl -jc -d 6 | tee -a params-katana.txt && cat gau.txt params-katana.txt katana.txt | sort -u > url.txt && cat url.txt | uro | tee -a unique-urls.txt && cat unique-urls.txt | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | httpx  | tee -a params.txt && cat unique-urls.txt | egrep "\.js" > js.txt && cat js.txt | httpx -mc 200 | tee -a live-js.txt && rm params-katana.txt gau.txt url.txt katana.txt js.txt && nuclei -l params.txt -t /root/fuzz/ | tee -a fuzzing-nuclei-result.txt && nuclei -l live-js.txt -t /root/nuclei-templates/http/exposures/ | tee -a js-nuclei-result.txt

# login panels
nuclei -l subdomains.txt -t /root/nuclei-templates/http/exposed-panels/ | tee -a login-panals.txt

# robots  txt

nuclei -l subdomains.txt -t /root/nucleiMy/ | tee -a robtos.txt
