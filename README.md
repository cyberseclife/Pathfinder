# Pathfinder
Advanced Subdomain and Directory Fuzzer in GoLang

***DO NOT use on goverment sites or perform unauthorized scans. 
The user assumes all responsibility and the creator is not liable.
I know people don't listen but I have to put it anyways!***

Installation:
git clone https://github.com/cyberseclife/Pathfinder.git
cd Pathfinder
chmod +x pathfinder
./pathfinder dir or sub
To use globally:
sudo cp /path/to/pathfinder /home/<username>/go/bin/pathfinder
or
sudo mv /path/to/pathfinder /home/<username>/go/bin/pathfinder

***GOPATH must be set in either ~/.zshrc or ~/.bashrc***

cyberseclife@debian-vm ~/Projects/pathfinder $ ./pathfinder sub -h
```
  _____      _   _     __ _           _           
 |  __ \    | | | |   / _(_)         | |          
 | |__) |_ _| |_| |__| |_ _ _ __   __| | ___ _ __ 
 |  ___/ _` | __| '_ \  _| | '_ \ / _` |/ _ \ '__|
 | |  | (_| | |_| | | | | | | | | | (_| |  __/ |   
 |_|   \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|   

Usage of sub:
  -o string
    	Output file to save results
  -rl int
    	Rate limit (requests per second) (default 10)
  -t int
    	Number of concurrent threads (default 50)
  -u string
    	Target URL/Domain with markers (e.g. https://WL1.example.com)
  -v	Enable verbose output
  -w value
    	Path to wordlist file (format: /path:MARKER or just /path for WL1)

----------------------------------------------------------------------------------

cyberseclife@debian-vm ~/Projects/pathfinder $ ./pathfinder dir -h

  _____      _   _     __ _           _           
 |  __ \    | | | |   / _(_)         | |          
 | |__) |_ _| |_| |__| |_ _ _ __   __| | ___ _ __ 
 |  ___/ _` | __| '_ \  _| | '_ \ / _` |/ _ \ '__|
 | |  | (_| | |_| | | | | | | | | | (_| |  __/ |   
 |_|   \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|   

Usage of dir:
  -f string
    	File extensions to search (comma-separated, e.g., 'php,html')
  -fc string
    	Filter status codes (comma-separated)
  -fs string
    	Filter response sizes (comma-separated)
  -mc string
    	Match status codes (comma-separated) (default "200,204,301,302,307,401,403")
  -o string
    	Output file to save results
  -rl int
    	Rate limit (requests per second) (default 10)
  -t int
    	Number of concurrent threads (default 50)
  -u string
    	Target URL with markers (e.g. https://example.com/WL1)
  -v	Enable verbose output
  -w value
    	Path to wordlist file
