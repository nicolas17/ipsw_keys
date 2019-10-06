# How to use this
1. Download the script to the same folder as ipwndfu
2. Boot the device in DFU mode and run checkm8 exploit
3. Run the script using the arguments listed below

## Usage
```
Usage: ipsw_key.py <-i <input>|-d <identifier>> [-ajpw] [-v version] [options] -o <output>
Extracts iOS encryption keys from an IPSW using a physical device's AES engine.

Required arguments:
    -d, --device <identifier>    Device identifier to download IPSW for
    -i, --input <input>          Local IPSW file to read from
    -o, --output <output>        Location to store output keys
    
Optional arguments:
    -a, --auto-name              Automatically name output based on version and device, and save in folder at <output>
    -h, --help                   Show this help prompt
    -j, --json                   Store output as JSON file
    -p, --plist                  Store output as property list file
    -v, --version <version>      Version of iOS to download (without this, downloads all versions and implies -a)
    -w, --wiki                   Format output for iPhone Wiki upload
```

### Examples
`./ipsw_keys.py -d iPad4,5 -v 12.4.2 -o . --auto-name`  
`./ipsw_keys.py -i iPhone10,3,iPhone10,6_12.4.1_16G102_Restore.ipsw -o iPhoneXKeys_12.4.1.plist --plist`

### Notes
* Only IMG4 files are supported at the moment. This means only A7+ IPSWs can be used until I add IMG3 support.
* If you specify `-d` without `-v`, all iOS versions will be downloaded. **THIS WILL TAKE A LONG TIME!**
* The output JSON and plist files will be in a format similar to this:
```json
{
    "BatteryLow0": {
        "Path": "Firmware/all_flash/batterylow0@2x~ipad.im4p",
        "Encrypted": false
    },
    [...]
    "iBSS": {
        "Path": "Firmware/dfu/iBSS.ipad4b.RELEASE.im4p",
        "Encrypted": true,
        "IV": "00112233445566778899aabbccddeeff",
        "Key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    }
}
```