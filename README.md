# lockdown.sh

Lockdown.sh is a single file zero config shell script to be run to lockdown a newly installed linux os. Lockdown.sh aims to set a sensible baseline which can be built upon for specific needs.

- Zero Config
- Zero Install
- Single file POSIX shell script

## WARNING
This script changes the ssh port to `141`.

## Usage
Download and run the script as root, if prompted for anything select `y`. 
```bash
wget https://raw.githubusercontent.com/x08d/lockdown.sh/master/lockdown.sh
chmod +x ./lockdown.sh
./lockdown.sh
```

## Supported OS
- Debian 10
- Debian 8
- (Should work with most debian and debian based OS's)

## Contributing
Please open pull requests and issues on github for anything you find.

## References
- https://github.com/CISOfy/lynis 
- https://github.com/Jsitech/JShielder

