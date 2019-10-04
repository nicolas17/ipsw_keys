# How to use this
1. `pip install asn1`
2. Download the script to the same folder as ipwndfu
3. Boot the device in DFU mode and run checkm8 exploit
4. Run the script with the device identifier, iOS version, and output JSON file

Example:
`./ipsw_keys.py iPad4,5 12.4.2 iPad4,5_12.4.2_Keys.json`

If you add anything after the output file, the script will skip downloading and will instead look inside `firmware.ipsw` in the current directory.

The outputted JSON file will have this basic format:
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