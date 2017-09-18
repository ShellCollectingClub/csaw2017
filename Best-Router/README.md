Pretty straightfoward. We were provided a large img file, along with a website asking for a username and password. 

First, the file system had to be mounted. The provided image had 2 partions. The larger of the two was mounted using the commands found [here](https://askubuntu.com/questions/69363/mount-single-partition-from-image-of-entire-disk-device). Seeing as the other part of the challenge was a web page asking for login, I looked for its source, which included login creds. Using those to login gave the flag.
