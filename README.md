This script was originally written by @MCJack123,
posted on this Gist:
https://gist.github.com/MCJack123/b7ded5a4b2a221e13dd3492f2971ae34

# How to use this
1. Download the script to the same folder as ipwndfu
2. Boot the device in DFU mode and run checkm8 exploit
3. Run the script using the arguments listed below

## Usage
```
Usage: ipsw_key.py <-i <input>|-d <identifier>> [-ajpw] [-v <version>] [-b <bdid>] [options] [-a] [-o <output>]
Extracts iOS encryption keys from an IPSW using a physical device's AES engine.

Required arguments:
    -d, --device <identifier>    Device identifier to download IPSW for
    -i, --input <input>          Local IPSW file to read from
    -o, --output <output>        Location to store output keys
    
Optional arguments:
    -a, --auto-name              Automatically name output based on version and device, and save in folder at <output> if specified
    -b, --bdid <bdid>            Use a custom board ID instead of the current device's BDID
    -h, --help                   Show this help prompt
    -j, --json                   Store output as JSON file
    -p, --plist                  Store output as property list file
    -v, --version <version>      Version of iOS to download (without this, downloads all versions and implies -a)
    -w, --wiki                   Format output for iPhone Wiki upload
```

### Examples
* `./ipsw_keys.py -d iPad4,5 -v 12.4.2 --auto-name` - Downloads the keys for iOS 12.4.2 for iPad4,5 to `iPad4,5_12.4.2_16G114_Keys.json`
* `./ipsw_keys.py -d iPhone5,1 -o iPhone5Keys -w` - Downloads the keys for all versions for iPhone5,1 to `iPhone5Keys/iPhone5,1_<version>_<build>_Keys.wiki`
* `./ipsw_keys.py -i iPhone10,3,iPhone10,6_12.4.1_16G102_Restore.ipsw -o iPhoneXKeys_12.4.1.plist --plist` - Extracts keys from `iPhone10,3,iPhone10,6_12.4.1_16G102_Restore.ipsw` to `iPhoneXKeys_12.4.1.plist`

### Notes
* If you specify `-d` without `-v`, all iOS versions will be downloaded, and `-a` is implied. **THIS WILL TAKE A LONG TIME!**
* If you specify `-a`, the `-o` option will instead be used for the output folder. In this case, you can skip `-o` to save in the current directory.
* This will not get the keys for the RootFS before 10.0 since it was stored in a different non-IMG4 format that I can't parse. These keys are mostly available on the iPhone Wiki anyway, so it shouldn't matter too much; plus, iOS 10 and later don't encrypt the RootFS at all.
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
