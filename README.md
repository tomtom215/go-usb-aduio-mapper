# USB Soundcard Mapper

A production-grade utility for creating persistent udev mappings for USB audio devices on Linux systems.

## Overview

USB Soundcard Mapper solves a common problem for audio professionals and enthusiasts working with USB audio interfaces on Linux: ensuring consistent device naming across disconnects, reconnects, and system reboots.

When you connect multiple USB audio devices to a Linux system, they are assigned arbitrary card numbers (e.g., `card0`, `card1`) based on the order they are detected. These card numbers can change when devices are reconnected or when the system reboots, which causes issues with audio applications that reference specific device names.

This utility creates persistent udev rules that assign consistent, meaningful names to your USB audio devices, ensuring they remain stable regardless of connection order or system reboots.

### Key Features

- Automatic detection of USB audio devices with detailed information extraction
- Interactive terminal UI for device selection and naming
- Non-interactive mode for scripting and automation
- Robust error handling and recovery mechanisms
- Comprehensive logging with configurable verbosity
- Automatic validation and verification of applied rules
- Support for virtual audio devices (with safety prompts)
- Backup creation of existing rules

## System Requirements

- Linux system with udev (most modern distributions)
- Required commands: `lsusb`, `aplay`, `udevadm`
- Root privileges (for writing udev rules)
- Go 1.17+ (for building from source)

## Installation

### From Binary Releases

Download the latest release from the GitHub releases page:

```bash
# Download the latest release (replace X.Y.Z with the version number)
curl -LO https://github.com/tomtom215/usb-soundcard-mapper/releases/download/vX.Y.Z/usb-soundcard-mapper

# Make it executable
chmod +x usb-soundcard-mapper

# Move to a directory in your PATH (requires root)
sudo mv usb-soundcard-mapper /usr/local/bin/
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/tomtom215/usb-soundcard-mapper.git
cd usb-soundcard-mapper

# Build the binary
go build -o usb-soundcard-mapper

# Optionally install it to your system (requires root)
sudo mv usb-soundcard-mapper /usr/local/bin/
```

## Usage

### Interactive Mode

The easiest way to use the utility is in interactive mode:

```bash
# Must be run with root privileges
sudo usb-soundcard-mapper
```

This will:
1. Detect all USB sound cards connected to your system
2. Present an interactive terminal UI for selecting a device
3. Allow you to customize the device name or use the suggested one
4. Create and apply the udev rule
5. Verify the rule has been successfully applied

### Non-Interactive Mode

For automation and scripting, use the non-interactive mode:

```bash
sudo usb-soundcard-mapper --non-interactive --vendor-id 1234 --product-id 5678 --name my_audio_interface
```

### List Mode

To view all connected USB audio devices without making changes:

```bash
usb-soundcard-mapper --list
```

### Dry Run Mode

To see what changes would be made without actually applying them:

```bash
sudo usb-soundcard-mapper --dry-run
```

### Command Line Options

```
Usage: usb-soundcard-mapper [options]

Creates persistent device mappings for USB sound cards.

Options:
  --rules-path string       Path to udev rules directory (default "/etc/udev/rules.d")
  --list                    List USB sound cards and exit
  --non-interactive         Non-interactive mode
  --name string             Custom name for the device (non-interactive mode)
  --vendor-id string        Vendor ID (non-interactive mode)
  --product-id string       Product ID (non-interactive mode)
  --skip-reload             Skip reloading udev rules after creating them
  --dry-run                 Show what would be done without making changes
  --force                   Force overwrite existing rules and accept virtual devices
  --ignore-virtual          Ignore virtual audio devices
  --log-level string        Log level (debug, info, warn, error) (default "info")
  --command-timeout int     Command execution timeout in seconds (default 5)
  --retries int             Maximum number of retries for commands (default 3)
```

## How It Works

1. The utility detects all USB audio devices connected to your system
2. For each device, it extracts:
   - Vendor and product IDs
   - Serial number (if available)
   - Physical port information
   - Bus and device information
   - Vendor and product names
3. It creates a udev rule that:
   - Applies a consistent name to the device based on its unique attributes
   - Creates symbolic links for easier application access
   - Handles different udev event types (add, change) for robustness
4. The rule is installed in `/etc/udev/rules.d/`
5. Udev rules are reloaded and triggered to apply the changes

## Best Practices

### Device Naming

When naming your devices, consider:

- Use descriptive names that identify the function or model
- Avoid spaces or special characters
- Keep names short but meaningful
- Use prefixes for different types of interfaces (e.g., `mic_`, `mixer_`)

Example: `focusrite_2i2` for a Focusrite Scarlett 2i2 interface

### For Audio Production Systems

- Create mappings for all your devices before setting up your audio software
- Verify each mapping by disconnecting and reconnecting the device
- Consider creating a backup of your working udev rules configuration
- Test with your audio software to ensure it correctly identifies the devices

## Troubleshooting

### Common Issues

#### Device Not Detected

- Ensure the device is properly connected and powered on
- Check if the device appears in `lsusb` output
- Check if the device appears in `aplay -l` output
- Try a different USB port or cable

#### Name Not Applied After Rule Creation

- Disconnect and reconnect the device
- Run `sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound`
- Check system logs: `journalctl -u systemd-udevd`
- Verify the rule file exists: `ls -l /etc/udev/rules.d/89-usb-soundcard-*.rules`

#### Permission Denied Errors

- Ensure you're running the utility with `sudo`
- Check permissions on the udev rules directory: `ls -la /etc/udev/rules.d/`
- Verify your user has sudo privileges

#### Conflicts with Existing Rules

- Use `--force` to overwrite existing rules
- Manually check for conflicting rules: `grep -r "ATTRS{idVendor}" /etc/udev/rules.d/`
- Use `--backup-rules` to create backups before modification

### Debugging Techniques

For more in-depth troubleshooting:

```bash
# Enable debug logging
sudo usb-soundcard-mapper --log-level debug

# Test udev rule manual application
sudo udevadm test $(udevadm info --query=path --name=/dev/snd/cardX)

# View detailed device information
sudo udevadm info --attribute-walk --name=/dev/snd/cardX

# Monitor udev events
sudo udevadm monitor --environment --udev
```

## Uninstallation

### Remove Created Rules

To remove specific rules created by the utility:

```bash
# List all rules created by the utility
ls /etc/udev/rules.d/89-usb-soundcard-*.rules

# Remove a specific rule
sudo rm /etc/udev/rules.d/89-usb-soundcard-XXXX-YYYY.rules

# Reload udev rules
sudo udevadm control --reload-rules
```

### Complete Uninstallation

```bash
# Remove all created rules
sudo rm /etc/udev/rules.d/89-usb-soundcard-*.rules

# Remove modprobe configurations (if created)
sudo rm /etc/modprobe.d/99-soundcard-*.conf

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Remove the binary (if installed)
sudo rm /usr/local/bin/usb-soundcard-mapper
```

## Advanced Usage

### Integration with Audio Software Setup Scripts

Add to your setup scripts:

```bash
# Map all connected USB audio devices with default names
for device in $(usb-soundcard-mapper --list | grep VID:PID | awk '{print $3}'); do
  vid=$(echo $device | cut -d: -f1)
  pid=$(echo $device | cut -d: -f2)
  sudo usb-soundcard-mapper --non-interactive --vendor-id $vid --product-id $pid
done
```

### Custom Rules Directory

For testing or custom installations:

```bash
sudo usb-soundcard-mapper --rules-path /path/to/custom/rules/dir
```

### Handling Virtual Devices

By default, the utility will warn about virtual audio devices. You can:

```bash
# Skip virtual devices entirely
sudo usb-soundcard-mapper --ignore-virtual

# Force mapping of virtual devices
sudo usb-soundcard-mapper --force
```

## License

[MIT License](LICENSE) - See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
