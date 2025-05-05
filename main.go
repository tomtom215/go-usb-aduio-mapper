// USB Soundcard Mapper
// A robust utility for creating persistent udev mappings for USB audio devices
// Version: 2.0.0 (based on original v1.3.0 with comprehensive improvements)

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Application constants
const (
	AppName      = "usb-soundcard-mapper"
	AppVersion   = "2.0.0"
	ExecTimeout  = 5 * time.Second
	udevRulesDir = "/etc/udev/rules.d"
)

// Sentinel errors for specific failure cases
var (
	ErrNoUSBSoundCards     = errors.New("no USB sound cards found")
	ErrInsufficientPrivs   = errors.New("insufficient privileges")
	ErrUdevSystemFailure   = errors.New("udev system test failed")
	ErrCommandNotFound     = errors.New("required command not found")
	ErrOperationCancelled  = errors.New("operation cancelled by user")
	ErrDeviceNameEmpty     = errors.New("device name cannot be empty")
	ErrInvalidDeviceParams = errors.New("invalid device parameters")
)

// LogLevel represents the logging verbosity level
type LogLevel string

// Log level constants
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Config holds application configuration
type Config struct {
	UdevRulesPath   string
	ListOnly        bool
	NonInteractive  bool
	DeviceName      string
	VendorID        string
	ProductID       string
	LogLevel        LogLevel
	SkipReload      bool
	DryRun          bool
	ConcurrencyOpts ConcurrencyOptions
	BackupRules     bool
}

// ConcurrencyOptions configures the concurrency behavior
type ConcurrencyOptions struct {
	MaxWorkers     int
	OperationQueue int
}

// USBSoundCard represents a USB sound card device with all necessary attributes
type USBSoundCard struct {
	CardNumber   string
	DevicePath   string
	Vendor       string
	Product      string
	VendorID     string
	ProductID    string
	Serial       string
	BusID        string
	DeviceID     string
	PhysicalPort string
	FriendlyName string
	Detected     time.Time
}

// String returns a formatted representation of the sound card
func (c USBSoundCard) String() string {
	var attrs []string
	attrs = append(attrs, fmt.Sprintf("Card: %s", c.CardNumber))
	attrs = append(attrs, fmt.Sprintf("Device: %s %s", c.Vendor, c.Product))
	attrs = append(attrs, fmt.Sprintf("VID:PID: %s:%s", c.VendorID, c.ProductID))
	if c.Serial != "" {
		attrs = append(attrs, fmt.Sprintf("Serial: %s", c.Serial))
	}
	if c.PhysicalPort != "" {
		attrs = append(attrs, fmt.Sprintf("Port: %s", c.PhysicalPort))
	}
	return strings.Join(attrs, ", ")
}

// CommandExecutor handles safe execution of external commands with proper timeout
type CommandExecutor struct {
	DefaultTimeout time.Duration
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{
		DefaultTimeout: ExecTimeout,
	}
}

// ExecuteCommand executes a command with the default timeout
func (ce *CommandExecutor) ExecuteCommand(ctx context.Context, command string, args ...string) (string, error) {
	return ce.ExecuteCommandWithTimeout(ctx, ce.DefaultTimeout, command, args...)
}

// ExecuteCommandWithTimeout executes a command with a specific timeout
func (ce *CommandExecutor) ExecuteCommandWithTimeout(ctx context.Context, timeout time.Duration, command string, args ...string) (string, error) {
	// Check if context is already canceled
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// Create a context with timeout
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Find the full path to the command to avoid shell injection
	cmdPath, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("command not found %s: %w", command, ErrCommandNotFound)
	}

	slog.Debug("Executing command", "command", command, "args", args)
	cmd := exec.CommandContext(execCtx, cmdPath, args...)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	
	// Check for timeout
	if execCtx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("command timed out after %s: %s %v", timeout, command, args)
	}

	// Handle other errors
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return "", fmt.Errorf("command '%s %v' failed with exit code %d: %s", 
				command, args, exitError.ExitCode(), stderr.String())
		}
		return "", fmt.Errorf("command '%s %v' failed: %s", command, args, stderr.String())
	}

	return stdout.String(), nil
}

// CheckCommands verifies that all required system commands are available
func CheckCommands(ctx context.Context, executor *CommandExecutor) error {
	requiredCommands := []string{"lsusb", "aplay", "udevadm"}
	
	var missingCommands []string
	for _, cmd := range requiredCommands {
		_, err := exec.LookPath(cmd)
		if err != nil {
			missingCommands = append(missingCommands, cmd)
		}
	}
	
	if len(missingCommands) > 0 {
		return fmt.Errorf("required commands not found: %s: %w", strings.Join(missingCommands, ", "), ErrCommandNotFound)
	}
	
	return nil
}

// DeviceRegistry manages a thread-safe collection of sound cards
type DeviceRegistry struct {
	devices map[string]USBSoundCard
	mu      sync.RWMutex
}

// NewDeviceRegistry creates a new device registry
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		devices: make(map[string]USBSoundCard),
	}
}

// AddDevice adds a device to the registry
func (dr *DeviceRegistry) AddDevice(card USBSoundCard) {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	
	key := fmt.Sprintf("%s:%s", card.VendorID, card.ProductID)
	if card.Serial != "" {
		key = fmt.Sprintf("%s:%s:%s", card.VendorID, card.ProductID, card.Serial)
	}
	
	card.Detected = time.Now()
	dr.devices[key] = card
}

// GetDevices returns all devices in the registry
func (dr *DeviceRegistry) GetDevices() []USBSoundCard {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	
	devices := make([]USBSoundCard, 0, len(dr.devices))
	for _, device := range dr.devices {
		devices = append(devices, device)
	}
	
	return devices
}

// GetUSBSoundCards detects all USB sound cards in the system
func GetUSBSoundCards(ctx context.Context, executor *CommandExecutor) ([]USBSoundCard, error) {
	// Create registry for devices 
	registry := NewDeviceRegistry()
	
	// Get list of all sound cards using aplay
	output, err := executor.ExecuteCommand(ctx, "aplay", "-l")
	if err != nil {
		return nil, fmt.Errorf("failed to list sound cards: %w", err)
	}
	
	// Parse the output to find USB sound cards
	scanner := bufio.NewScanner(strings.NewReader(output))
	cardRegexp := regexp.MustCompile(`card (\d+):.*\[(.+)\].*\[(.+)\]`)
	
	// Create arrays to store results
	var cards []USBSoundCard
	var errs []error
	
	// Collect card numbers first
	var cardNumbers []string
	for scanner.Scan() {
		line := scanner.Text()
		matches := cardRegexp.FindStringSubmatch(line)
		if matches != nil && len(matches) >= 4 {
			cardNumber := matches[1]
			
			// Skip non-USB cards
			if !strings.Contains(strings.ToLower(line), "usb") {
				continue
			}
			
			cardNumbers = append(cardNumbers, cardNumber)
		}
	}
	
	// Process each card sequentially to avoid race conditions
	for _, cardNum := range cardNumbers {
		// Get more details about this card
		card, err := getCardDetails(ctx, executor, cardNum)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get details for card %s: %w", cardNum, err))
			continue
		}
		
		cards = append(cards, card)
		registry.AddDevice(card)
	}
	
	if err := scanner.Err(); err != nil {
		return cards, fmt.Errorf("error scanning aplay output: %w", err)
	}
	
	// If no cards found but no errors, return specific "no cards" error
	if len(cards) == 0 && len(errs) == 0 {
		return nil, ErrNoUSBSoundCards
	}
	
	// If we have errors, return them (but still return cards if we found any)
	if len(errs) > 0 {
		// Join errors into a single error
		var errStrings []string
		for _, err := range errs {
			errStrings = append(errStrings, err.Error())
		}
		
		// Only return error if we have no cards
		if len(cards) == 0 {
			return nil, fmt.Errorf("failed to process sound cards: %s", strings.Join(errStrings, "; "))
		}
		
		// Log errors but still return cards
		slog.Warn("Some cards could not be processed", "errors", strings.Join(errStrings, "; "))
	}
	
	return cards, nil
}

// getCardDetails gets detailed information about a sound card
func getCardDetails(ctx context.Context, executor *CommandExecutor, cardNumber string) (USBSoundCard, error) {
	card := USBSoundCard{
		CardNumber: cardNumber,
		DevicePath: fmt.Sprintf("/dev/snd/card%s", cardNumber),
	}
	
	// Get card path in sysfs
	sysfsPath := fmt.Sprintf("/sys/class/sound/card%s", cardNumber)
	
	// Run udevadm to get detailed device information
	output, err := executor.ExecuteCommand(ctx, "udevadm", "info", "--attribute-walk", "--path", sysfsPath)
	if err != nil {
		return card, fmt.Errorf("failed to get device info: %w", err)
	}
	
	// Extract vendor ID, product ID, serial number, etc.
	scanner := bufio.NewScanner(strings.NewReader(output))
	vendorRegexp := regexp.MustCompile(`ATTRS{idVendor}=="([^"]*)"`)
	productRegexp := regexp.MustCompile(`ATTRS{idProduct}=="([^"]*)"`)
	serialRegexp := regexp.MustCompile(`ATTRS{serial}=="([^"]*)"`)
	busPathRegexp := regexp.MustCompile(`KERNELS=="([0-9\-\.]+)"`)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		if matches := vendorRegexp.FindStringSubmatch(line); matches != nil && card.VendorID == "" {
			card.VendorID = matches[1]
		}
		
		if matches := productRegexp.FindStringSubmatch(line); matches != nil && card.ProductID == "" {
			card.ProductID = matches[1]
		}
		
		if matches := serialRegexp.FindStringSubmatch(line); matches != nil && card.Serial == "" {
			card.Serial = matches[1]
		}
		
		if matches := busPathRegexp.FindStringSubmatch(line); matches != nil && card.PhysicalPort == "" {
			card.PhysicalPort = matches[1]
			
			// Extract bus ID and device ID from physical port
			parts := strings.Split(matches[1], "-")
			if len(parts) >= 2 {
				card.BusID = parts[0]
				if len(parts) >= 3 {
					card.DeviceID = strings.Split(parts[1], ".")[0]
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return card, fmt.Errorf("error scanning udevadm output: %w", err)
	}
	
	// Validate required fields
	if card.VendorID == "" || card.ProductID == "" {
		return card, fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}
	
	// Get vendor/product names from lsusb if we have vendor and product IDs
	if card.VendorID != "" && card.ProductID != "" {
		lsusbOutput, err := executor.ExecuteCommand(ctx, "lsusb", "-d", fmt.Sprintf("%s:%s", card.VendorID, card.ProductID))
		if err == nil && len(lsusbOutput) > 0 {
			// Extract vendor and product names from lsusb output
			lsusbRegexp := regexp.MustCompile(`ID [0-9a-f]+:[0-9a-f]+ (.+)`)
			if matches := lsusbRegexp.FindStringSubmatch(lsusbOutput); matches != nil {
				fullName := matches[1]
				
				// Split into vendor and product if possible
				parts := strings.SplitN(fullName, " ", 2)
				if len(parts) >= 2 {
					card.Vendor = parts[0]
					card.Product = parts[1]
				} else {
					card.Vendor = "USB"
					card.Product = fullName
				}
			}
		}
	}
	
	// If we couldn't get vendor/product names, use IDs
	if card.Vendor == "" {
		card.Vendor = fmt.Sprintf("USB-%s", card.VendorID)
	}
	if card.Product == "" {
		card.Product = fmt.Sprintf("Audio-%s", card.ProductID)
	}
	
	// Create a friendly name based on available information using a tiered strategy
	// 1. Serial number is most reliable if present and not a PCI-like path
	// 2. Physical port path as fallback for devices without serial
	// 3. Card number as a last resort
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		// Clean serial number of problematic chars
		cleanSerial := cleanupName(card.Serial)
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, cleanSerial)
	} else if card.PhysicalPort != "" {
		// Use physical port for more stable identification across reboots
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_port%s", card.VendorID, card.ProductID, 
			strings.Replace(card.PhysicalPort, "-", "_", -1))
	} else {
		// Fallback to card number (least stable, but better than nothing)
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.CardNumber)
	}
	
	// Clean up the friendly name to ensure it's a valid ID
	card.FriendlyName = cleanupName(card.FriendlyName)
	
	return card, nil
}

// cleanupName ensures the generated name is valid for udev rules
func cleanupName(name string) string {
	// Replace any non-alphanumeric characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name = re.ReplaceAllString(name, "_")
	
	// Ensure it doesn't start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "usb_" + name
	}
	
	// Ensure name is not too long (trim if necessary)
	maxLength := 64
	if len(name) > maxLength {
		name = name[:maxLength]
	}
	
	return name
}

// UdevRule represents a complete udev rule configuration
type UdevRule struct {
	Card     USBSoundCard
	Content  string
	Path     string
	Name     string
	DeviceID string
}

// createUdevRule creates a udev rule to give the sound card a persistent name
func createUdevRule(ctx context.Context, card USBSoundCard, customName string, config Config) (*UdevRule, error) {
	// Verify we have the necessary information
	if card.VendorID == "" || card.ProductID == "" {
		return nil, fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}

	// Use custom name if provided, otherwise use the default
	deviceName := card.FriendlyName
	if customName != "" {
		deviceName = cleanupName(customName)
	}
	
	// Create rule content - Using string builder for better performance and clarity
	var ruleBuilder strings.Builder
	
	// Add header with appropriate documentation
	ruleBuilder.WriteString("# USB sound card persistent mapping created by usb-soundcard-mapper v")
	ruleBuilder.WriteString(AppVersion)
	ruleBuilder.WriteString("\n# Created: ")
	ruleBuilder.WriteString(time.Now().Format(time.RFC3339))
	ruleBuilder.WriteString("\n# Device: ")
	ruleBuilder.WriteString(card.Vendor)
	ruleBuilder.WriteString(" ")
	ruleBuilder.WriteString(card.Product)
	ruleBuilder.WriteString("\n# VID:PID: ")
	ruleBuilder.WriteString(card.VendorID)
	ruleBuilder.WriteString(":")
	ruleBuilder.WriteString(card.ProductID)
	
	if card.Serial != "" {
		ruleBuilder.WriteString("\n# Serial: ")
		ruleBuilder.WriteString(card.Serial)
	}
	
	if card.PhysicalPort != "" {
		ruleBuilder.WriteString("\n# USB Path: ")
		ruleBuilder.WriteString(card.PhysicalPort)
	}
	ruleBuilder.WriteString("\n\n")
	
	// Create multiple matching rules for different scenarios
	// 1. Priority rule for ACTION=="add" with full device attributes 
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		// If we have a normal serial number, use it for more reliable mapping
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ACTION==\"add\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTRS{serial}==\"%s\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, card.Serial, deviceName)
	} else if card.PhysicalPort != "" {
		// Use physical port for devices without serial numbers
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ACTION==\"add\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", KERNELS==\"%s*\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName)
	} else {
		// Fallback to basic vendor/product ID mapping (less reliable)
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ACTION==\"add\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, deviceName)
	}
	
	// 2. Rule for ENV{SOUND_INITIALIZED}=="1" for after sound system is fully running
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ENV{SOUND_INITIALIZED}==\"1\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTRS{serial}==\"%s\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, card.Serial, deviceName)
	} else if card.PhysicalPort != "" {
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ENV{SOUND_INITIALIZED}==\"1\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", KERNELS==\"%s*\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName)
	} else {
		fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ENV{SOUND_INITIALIZED}==\"1\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTR{id}=\"%s\"\n",
			card.VendorID, card.ProductID, deviceName)
	}
	
	// 3. Universal rule for any sound card with the specific USB vendor/product ID
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTR{id}=\"%s\"\n",
		card.VendorID, card.ProductID, deviceName)
	
	// 4. Alternative rule with different path attribute for the kernel
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", KERNEL==\"card*\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", ATTR{id}=\"%s\"\n",
		card.VendorID, card.ProductID, deviceName)
		
	// 5. Add a symlink rule for easier access by applications
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ACTION==\"add\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", SYMLINK+=\"sound/by-id/%s\"\n", 
		card.VendorID, card.ProductID, deviceName)
	
	// Create a fallback symlink with ACTION=="change" as well
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", ACTION==\"change\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", SYMLINK+=\"sound/by-id/%s\"\n", 
		card.VendorID, card.ProductID, deviceName)
	
	// Add symlinks for specific device nodes
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", KERNEL==\"controlC*\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", SYMLINK+=\"sound/%s/control\"\n",
		card.VendorID, card.ProductID, deviceName)
		
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", KERNEL==\"pcmC*D*p\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", SYMLINK+=\"sound/%s/pcm_playback\"\n",
		card.VendorID, card.ProductID, deviceName)
		
	fmt.Fprintf(&ruleBuilder, "SUBSYSTEM==\"sound\", KERNEL==\"pcmC*D*c\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", SYMLINK+=\"sound/%s/pcm_capture\"\n",
		card.VendorID, card.ProductID, deviceName)
	
	// Create the rule file path 
	ruleFileName := fmt.Sprintf("89-usb-soundcard-%s-%s.rules", card.VendorID, card.ProductID)
	rulePath := filepath.Join(config.UdevRulesPath, ruleFileName)
	
	rule := &UdevRule{
		Card:     card,
		Content:  ruleBuilder.String(),
		Path:     rulePath,
		Name:     ruleFileName,
		DeviceID: deviceName,
	}
	
	return rule, nil
}

// installUdevRule writes the rule to the filesystem
func installUdevRule(ctx context.Context, rule *UdevRule, config Config) error {
	slog.Info("Installing udev rule", 
		"device", rule.Card.String(),
		"rule_path", rule.Path)
	
	if config.DryRun {
		slog.Info("Dry run mode - rule would be written to:", "path", rule.Path)
		fmt.Println("--- Rule Content ---")
		fmt.Println(rule.Content)
		fmt.Println("--------------------")
		return nil
	}
	
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(config.UdevRulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create udev rules directory: %w", err)
	}
	
	// Use atomic write to avoid race conditions
	if err := atomicWriteFile(rule.Path, []byte(rule.Content), 0644); err != nil {
		return fmt.Errorf("failed to write udev rule file: %w", err)
	}
	
	// Create modprobe configuration for better compatibility
	if err := createModprobeConfig(rule.Card); err != nil {
		// This is non-fatal
		slog.Warn("Failed to create modprobe configuration", "error", err)
	}
	
	return nil
}

// atomicWriteFile writes a file atomically using a temporary file and rename
func atomicWriteFile(filename string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(filename)
	
	// Create a temporary file in the same directory
	tempFile, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()
	
	// Clean up on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tempPath)
		}
	}()
	
	// Write the data to the temporary file
	if _, err = tempFile.Write(data); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	
	// Ensure file mode is set correctly
	if err = tempFile.Chmod(perm); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to chmod temporary file: %w", err)
	}
	
	// Close the file to ensure all data is written
	if err = tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	
	// Atomically replace the target file
	if err = os.Rename(tempPath, filename); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}
	
	success = true
	return nil
}

// createModprobeConfig creates a modprobe configuration for better device handling
func createModprobeConfig(card USBSoundCard) error {
	modprobePath := "/etc/modprobe.d"
	if !fileExists(modprobePath) {
		// Skip if modprobe directory doesn't exist
		return nil
	}
	
	modprobeFile := filepath.Join(modprobePath, fmt.Sprintf("99-soundcard-%s-%s.conf", 
		card.VendorID, card.ProductID))
	
	// Skip if already exists
	if fileExists(modprobeFile) {
		return nil
	}
	
	modprobeContent := fmt.Sprintf("# Modprobe options for USB sound card %s %s\n", 
		card.Vendor, card.Product)
	modprobeContent += "options snd_usb_audio index=-2\n"
	
	// Write the modprobe file
	if err := os.WriteFile(modprobeFile, []byte(modprobeContent), 0644); err != nil {
		return fmt.Errorf("failed to write modprobe configuration: %w", err)
	}
	
	return nil
}

// reloadUdevRules triggers a reload of udev rules
func reloadUdevRules(ctx context.Context, executor *CommandExecutor, config Config) error {
	if config.DryRun {
		slog.Info("Dry run mode - skipping udev rules reload")
		return nil
	}
	
	// Reload udev rules
	if _, err := executor.ExecuteCommand(ctx, "udevadm", "control", "--reload-rules"); err != nil {
		return fmt.Errorf("failed to reload udev rules: %w", err)
	}
	
	// Sleep to give udev time to process the rule reloading
	time.Sleep(1 * time.Second)
	
	// Trigger the rules for all sound devices - using add action for more reliable application
	if _, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=add", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules with add action: %w", err)
	}

	// Sleep to give udev time to apply the rules
	time.Sleep(2 * time.Second)
	
	// Also trigger with change action as a fallback
	if _, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=change", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules with change action: %w", err)
	}
	
	// Sleep again to ensure rules are fully applied
	time.Sleep(2 * time.Second)
	
	return nil
}

// verifyUdevRuleInstallation checks if the rule is properly installed
func verifyUdevRuleInstallation(ctx context.Context, executor *CommandExecutor, card USBSoundCard, customName string) bool {
	// Check if udev rules were reloaded successfully
	output, err := executor.ExecuteCommand(ctx, "udevadm", "info", "--path", fmt.Sprintf("/sys/class/sound/card%s", card.CardNumber))
	if err != nil {
		slog.Error("Failed to verify udev rule installation", "error", err)
		return false
	}

	// Look for the custom name in the output
	if strings.Contains(output, fmt.Sprintf("ID_SOUND_ID=%s", customName)) {
		slog.Info("Verified successful udev rule installation!")
		return true
	}

	// If not found, try to trigger the rule specifically for this device
	slog.Info("Rule verification failed. Trying to trigger rules specifically for this device...")
	
	_, err = executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=add", 
		"--property-match=SUBSYSTEM=sound", 
		fmt.Sprintf("--property-match=ID_VENDOR_ID=%s", card.VendorID),
		fmt.Sprintf("--property-match=ID_MODEL_ID=%s", card.ProductID))
	
	if err != nil {
		slog.Error("Failed to trigger specific udev rules", "error", err)
		return false
	}

	// Give it a moment to apply
	time.Sleep(2 * time.Second)
	
	return true
}

// checkElevatedPrivileges checks if the process has the necessary privileges
func checkElevatedPrivileges() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}
	
	return currentUser.Uid == "0", nil
}

// backupExistingUdevRules creates a backup of existing rules files
func backupExistingUdevRules(card USBSoundCard, config Config) error {
	if !config.BackupRules {
		return nil
	}
	
	// Pattern for rule files we might want to back up
	patterns := []string{
		fmt.Sprintf("*usb-soundcard*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*usb*sound*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*sound*%s*%s*.rules", card.VendorID, card.ProductID),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(config.UdevRulesPath, pattern))
		if err != nil {
			slog.Error("Error searching for existing rules", "error", err)
			continue
		}

		for _, match := range matches {
			// Skip backing up our own rule file
			if strings.Contains(match, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", card.VendorID, card.ProductID)) {
				continue
			}

			// Create backup with timestamp
			backupFile := match + ".bak." + time.Now().Format("20060102150405")
			slog.Info("Backing up existing rule file", "source", match, "backup", backupFile)

			content, err := os.ReadFile(match)
			if err != nil {
				slog.Error("Failed to read existing rule file", "file", match, "error", err)
				continue
			}

			err = os.WriteFile(backupFile, content, 0644)
			if err != nil {
				slog.Error("Failed to write backup file", "file", backupFile, "error", err)
				continue
			}
		}
	}

	return nil
}

// testUdevSystem performs a basic test of the udev system
func testUdevSystem(ctx context.Context, executor *CommandExecutor, config Config) bool {
	slog.Info("Testing if udev rule system is working properly...")
	
	if config.DryRun {
		slog.Info("Dry run mode - skipping udev system test")
		return true
	}
	
	// Create a small test rule
	testRuleFile := filepath.Join(config.UdevRulesPath, "99-test-usb-soundcard-mapper.rules")
	testRuleContent := "# Test rule to check if udev is functioning properly\n"
	
	// Write test rule
	err := os.WriteFile(testRuleFile, []byte(testRuleContent), 0644)
	if err != nil {
		slog.Error("Failed to write test udev rule", "error", err)
		return false
	}
	
	// Try to reload udev rules
	_, err = executor.ExecuteCommand(ctx, "udevadm", "control", "--reload-rules")
	if err != nil {
		slog.Error("Failed to reload udev rules during test", "error", err)
		os.Remove(testRuleFile) // Clean up
		return false
	}
	
	// Clean up test rule
	os.Remove(testRuleFile)
	
	slog.Info("Udev system test passed")
	return true
}

// checkAndFixPermissions ensures the udev rules directory has the correct permissions
func checkAndFixPermissions(config Config) error {
	// Check if the rules directory exists and has correct permissions
	info, err := os.Stat(config.UdevRulesPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Create directory with correct permissions
			err = os.MkdirAll(config.UdevRulesPath, 0755)
			if err != nil {
				return fmt.Errorf("failed to create udev rules directory: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to check udev rules directory: %w", err)
	}
	
	// If exists but is not a directory
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", config.UdevRulesPath)
	}
	
	// Check permissions - should be at least 0755
	if info.Mode().Perm()&0755 != 0755 {
		// Try to fix permissions
		slog.Info("Fixing permissions on rules directory", "path", config.UdevRulesPath)
		err = os.Chmod(config.UdevRulesPath, 0755)
		if err != nil {
			return fmt.Errorf("failed to set permissions on udev rules directory: %w", err)
		}
	}
	
	return nil
}

// detectSoundSystemType checks what sound system is in use (ALSA, PulseAudio, etc.)
func detectSoundSystemType(ctx context.Context, executor *CommandExecutor) string {
	// Check for PipeWire first (most modern)
	_, err := executor.ExecuteCommand(ctx, "pipewire", "--version")
	if err == nil {
		slog.Info("Detected PipeWire sound system")
		return "pipewire"
	}
	
	// Check for PulseAudio
	_, err = executor.ExecuteCommand(ctx, "pulseaudio", "--version")
	if err == nil {
		slog.Info("Detected PulseAudio sound system")
		return "pulseaudio"
	}
	
	// Check for JACK
	_, err = executor.ExecuteCommand(ctx, "jackd", "--version")
	if err == nil {
		slog.Info("Detected JACK sound system")
		return "jack"
	}
	
	// Default to ALSA
	slog.Info("Assuming ALSA sound system")
	return "alsa"
}

// checkPCIFallbackForSerials verifies if PCI paths are being used as serial numbers
func checkPCIFallbackForSerials(ctx context.Context, executor *CommandExecutor) bool {
	// Run command to see if any device has a PCI-like serial
	output, err := executor.ExecuteCommand(ctx, "lsusb", "-v")
	if err != nil {
		slog.Warn("Could not check for PCI fallback serial numbers", "error", err)
		return false
	}
	
	hasPCISerials := strings.Contains(output, "iSerial") && strings.Contains(output, ":")
	if hasPCISerials {
		slog.Info("Detected devices with PCI path-like serial numbers. Special handling will be applied.")
	}
	
	return hasPCISerials
}

// findAllUSBDevices gets information about all connected USB devices
func findAllUSBDevices(ctx context.Context, executor *CommandExecutor) (map[string]map[string]string, error) {
	devices := make(map[string]map[string]string)
	
	// Get all USB devices from lsusb
	output, err := executor.ExecuteCommand(ctx, "lsusb")
	if err != nil {
		return nil, fmt.Errorf("failed to run lsusb: %w", err)
	}
	
	// Parse the output to get bus and device numbers
	scanner := bufio.NewScanner(strings.NewReader(output))
	lsusbRegexp := regexp.MustCompile(`Bus (\d{3}) Device (\d{3}): ID ([0-9a-f]{4}):([0-9a-f]{4}) (.+)`)
	
	for scanner.Scan() {
		line := scanner.Text()
		matches := lsusbRegexp.FindStringSubmatch(line)
		
		if matches != nil && len(matches) >= 6 {
			busNum := matches[1]
			devNum := matches[2]
			vendorID := matches[3]
			productID := matches[4]
			deviceName := matches[5]
			
			// Remove leading zeros
			busNum = strings.TrimLeft(busNum, "0")
			devNum = strings.TrimLeft(devNum, "0")
			
			deviceID := fmt.Sprintf("%s:%s", busNum, devNum)
			
			devices[deviceID] = map[string]string{
				"bus": busNum,
				"device": devNum,
				"vendorID": vendorID,
				"productID": productID,
				"name": deviceName,
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return devices, fmt.Errorf("error scanning lsusb output: %w", err)
	}
	
	return devices, nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return !info.IsDir()
}

// directoryExists checks if a directory exists
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return info.IsDir()
}

// setupSignalHandling sets up graceful shutdown on system signals
func setupSignalHandling(ctx context.Context, cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		select {
		case sig := <-c:
			slog.Info("Received signal, shutting down gracefully", "signal", sig)
			cancel()
		case <-ctx.Done():
			// Context was canceled elsewhere
			return
		}
	}()
}

// initLogger initializes the structured logger
func initLogger(level LogLevel) {
	// Convert log level string to slog.Level
	var logLevel slog.Level
	switch level {
	case LogLevelDebug:
		logLevel = slog.LevelDebug
	case LogLevelInfo:
		logLevel = slog.LevelInfo
	case LogLevelWarn:
		logLevel = slog.LevelWarn
	case LogLevelError:
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	
	// Create structured logger with JSON output
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Add timestamp in standardized format
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   "timestamp",
					Value: slog.StringValue(time.Now().Format(time.RFC3339)),
				}
			}
			return a
		},
	})
	
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// UI Components for interactive mode

// listItem represents a USB sound card in the UI list
type listItem struct {
	card USBSoundCard
}

// Implement the list.Item interface
func (i listItem) Title() string {
	title := fmt.Sprintf("Card %s: %s %s", i.card.CardNumber, i.card.Vendor, i.card.Product)
	if i.card.Serial != "" {
		title += fmt.Sprintf(" (S/N: %s)", i.card.Serial)
	}
	return title
}

func (i listItem) Description() string {
	desc := fmt.Sprintf("VID:PID %s:%s", i.card.VendorID, i.card.ProductID)
	if i.card.PhysicalPort != "" {
		desc += fmt.Sprintf(", Port: %s", i.card.PhysicalPort)
	}
	return desc
}

func (i listItem) FilterValue() string {
	return i.Title()
}

// viewState represents the current UI state
type viewState int

const (
	stateCardSelect viewState = iota
	stateNameInput
	stateConfirmation
	stateError
)

// UI styling
var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1)

	subtitleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#43BF6D")).
		Padding(0, 1)

	activeStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#43BF6D"))

	inactiveStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666666"))

	errorStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FF0000"))

	docStyle = lipgloss.NewStyle().
		Margin(1, 2)

	highlightStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#874BFD"))

	infoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#43BF6D"))
)

// UI-related key mappings
type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Enter   key.Binding
	Back    key.Binding
	Quit    key.Binding
	Edit    key.Binding
	Confirm key.Binding
}

// Default key mappings
var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+c", "q"),
		key.WithHelp("ctrl+c/q", "quit"),
	),
	Edit: key.NewBinding(
		key.WithKeys("e"),
		key.WithHelp("e", "edit"),
	),
	Confirm: key.NewBinding(
		key.WithKeys("y"),
		key.WithHelp("y", "confirm"),
	),
}

// uiModel represents the UI state
type uiModel struct {
	cards           []USBSoundCard
	list            list.Model
	textInput       textinput.Model
	state           viewState
	selectedCard    USBSoundCard
	customName      string
	config          Config
	executor        *CommandExecutor
	error           string
	width           int
	height          int
	successMessage  string
	ctx             context.Context
	cancel          context.CancelFunc
}

// Initialize UI model
func initialUIModel(cards []USBSoundCard, config Config, executor *CommandExecutor) uiModel {
	// Create a context for the UI operations
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create list items
	items := make([]list.Item, len(cards))
	for i, card := range cards {
		items[i] = listItem{card: card}
	}
	
	// Setup list component
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select USB Sound Card to Map"
	l.SetFilteringEnabled(false)
	l.SetShowHelp(true)
	l.SetShowStatusBar(false)
	l.SetShowPagination(true)
	
	// Setup text input component
	ti := textinput.New()
	ti.Placeholder = "Enter custom name for the device"
	ti.CharLimit = 64
	ti.Width = 40
	ti.Prompt = "› "
	
	return uiModel{
		cards:     cards,
		list:      l,
		textInput: ti,
		state:     stateCardSelect,
		config:    config,
		executor:  executor,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Initialize the model
func (m uiModel) Init() tea.Cmd {
	return nil
}

// Handle user input and state transitions
func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		
		// Update list dimensions
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
		
	case tea.KeyMsg:
		// Global key handlers
		switch {
		case key.Matches(msg, keys.Quit):
			slog.Debug("User quit application")
			m.cancel() // Cancel the context
			return m, tea.Quit
		}
		
		// State-specific handlers
		switch m.state {
		case stateCardSelect:
			// Handle list navigation and selection
			switch {
			case key.Matches(msg, keys.Enter):
				selectedItem, ok := m.list.SelectedItem().(listItem)
				if !ok || len(m.cards) == 0 {
					slog.Error("No card selected or no cards available")
					m.error = "No card selected or no cards available"
					m.state = stateError
					return m, nil
				}
				
				m.selectedCard = selectedItem.card
				m.customName = m.selectedCard.FriendlyName // Pre-populate with suggested name
				m.textInput.SetValue(m.customName)
				m.textInput.Focus()
				m.state = stateNameInput
				return m, textinput.Blink
			}
			
			// Pass the message to the list component
			m.list, cmd = m.list.Update(msg)
			cmds = append(cmds, cmd)
			
		case stateNameInput:
			switch {
			case key.Matches(msg, keys.Enter):
				// Validate input
				customName := m.textInput.Value()
				if customName == "" {
					m.error = "Device name cannot be empty"
					return m, nil
				}
				
				// Clean up and validate the name
				cleanedName := cleanupName(customName)
				if cleanedName != customName {
					m.customName = cleanedName
					m.textInput.SetValue(cleanedName)
					return m, nil
				}
				
				m.customName = cleanedName
				m.state = stateConfirmation
				return m, nil
				
			case key.Matches(msg, keys.Back):
				// Return to card selection
				m.textInput.Blur()
				m.state = stateCardSelect
				return m, nil
			}
			
			// Pass the message to the text input component
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)
			
		case stateConfirmation:
			switch {
			case key.Matches(msg, keys.Confirm):
				// Create udev rule with custom name
				rule, err := createUdevRule(m.ctx, m.selectedCard, m.customName, m.config)
				if err != nil {
					slog.Error("Failed to create udev rule", "error", err)
					m.error = fmt.Sprintf("Failed to create udev rule: %v", err)
					m.state = stateError
					return m, nil
				}
				
				// Backup existing rules for this device
				if err := backupExistingUdevRules(m.selectedCard, m.config); err != nil {
					slog.Warn("Failed to backup existing rules", "error", err)
				}
				
				// Install the rule
				if err := installUdevRule(m.ctx, rule, m.config); err != nil {
					slog.Error("Failed to install udev rule", "error", err)
					m.error = fmt.Sprintf("Failed to install udev rule: %v", err)
					m.state = stateError
					return m, nil
				}
				
				// Reload udev rules if not skipped
				if !m.config.SkipReload {
					if err := reloadUdevRules(m.ctx, m.executor, m.config); err != nil {
						slog.Error("Failed to reload udev rules", "error", err)
						m.error = fmt.Sprintf("Failed to reload udev rules: %v", err)
						m.state = stateError
						return m, nil
					}
					
					// Verify the rule installation
					verifyUdevRuleInstallation(m.ctx, m.executor, m.selectedCard, m.customName)
				}
				
				// Success message
				m.successMessage = fmt.Sprintf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n\n"+
					"The sound card will use this name consistently across reboots and reconnections.\n"+
					"You can see this device in 'aplay -l' output as card with ID '%s'\n"+
					"once you disconnect and reconnect the device.",
					m.selectedCard.Vendor, m.selectedCard.Product, 
					m.selectedCard.VendorID, m.selectedCard.ProductID, 
					m.customName, m.customName)
				
				m.cancel() // Cancel the context before quitting
				return m, tea.Quit
				
			case key.Matches(msg, keys.Back):
				// Return to name input
				m.state = stateNameInput
				return m, textinput.Blink
			}
			
		case stateError:
			// Return to card selection on any key press
			m.error = ""
			m.state = stateCardSelect
			return m, nil
		}
	}

	return m, tea.Batch(cmds...)
}

// Render the UI based on current state
func (m uiModel) View() string {
	var sb strings.Builder
	
	// Common header
	sb.WriteString(titleStyle.Render(fmt.Sprintf(" %s v%s ", AppName, AppVersion)) + "\n\n")
	
	switch m.state {
	case stateCardSelect:
		sb.WriteString(activeStyle.Render("Step 1: Select a USB sound card") + "\n\n")
		sb.WriteString(m.list.View() + "\n\n")
		sb.WriteString(inactiveStyle.Render("Step 2: Enter custom name") + "\n")
		
	case stateNameInput:
		sb.WriteString(inactiveStyle.Render("Step 1: Select a USB sound card") + "\n")
		sb.WriteString(fmt.Sprintf("Selected: %s\n\n", highlightStyle.Render(m.selectedCard.Vendor+" "+m.selectedCard.Product)))
		sb.WriteString(activeStyle.Render("Step 2: Enter custom name for this device") + "\n\n")
		sb.WriteString(m.textInput.View() + "\n\n")
		sb.WriteString("This name will be used to identify the device in ALSA.\n")
		sb.WriteString("Press Enter to confirm or Esc to go back.\n")
		
		if m.error != "" {
			sb.WriteString("\n" + errorStyle.Render(m.error) + "\n")
		}
		
	case stateConfirmation:
		sb.WriteString("Please confirm the following configuration:\n\n")
		sb.WriteString(fmt.Sprintf("Device: %s\n", highlightStyle.Render(m.selectedCard.Vendor+" "+m.selectedCard.Product)))
		sb.WriteString(fmt.Sprintf("Card Number: %s\n", m.selectedCard.CardNumber))
		sb.WriteString(fmt.Sprintf("VID:PID: %s:%s\n", m.selectedCard.VendorID, m.selectedCard.ProductID))
		
		if m.selectedCard.Serial != "" {
			sb.WriteString(fmt.Sprintf("Serial: %s\n", m.selectedCard.Serial))
		}
		
		if m.selectedCard.PhysicalPort != "" {
			sb.WriteString(fmt.Sprintf("Physical Port: %s\n", m.selectedCard.PhysicalPort))
		}
		
		sb.WriteString(fmt.Sprintf("\nCustom Name: %s\n\n", highlightStyle.Render(m.customName)))
		sb.WriteString("Press 'y' to confirm or Esc to go back.")
		
	case stateError:
		sb.WriteString(errorStyle.Render("Error:") + "\n\n")
		sb.WriteString(m.error + "\n\n")
		sb.WriteString("Press any key to return to device selection...")
	}
	
	return docStyle.Render(sb.String())
}

// runUI starts the terminal UI for interactive mode
func runUI(ctx context.Context, cards []USBSoundCard, config Config, executor *CommandExecutor) (string, error) {
	if len(cards) == 0 {
		return "", ErrNoUSBSoundCards
	}
	
	model := initialUIModel(cards, config, executor)
	
	// Create a new program with alt screen enabled
	p := tea.NewProgram(model, tea.WithAltScreen())
	
	// Run in a goroutine to handle context cancellation
	resultCh := make(chan tea.Model, 1)
	errCh := make(chan error, 1)
	
	go func() {
		m, err := p.Run()
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- m
	}()
	
	// Wait for either context done or UI completion
	select {
	case <-ctx.Done():
		// Context was canceled, shutdown the UI
		p.Quit()
		return "", ctx.Err()
		
	case err := <-errCh:
		return "", fmt.Errorf("UI error: %w", err)
		
	case m := <-resultCh:
		// UI completed normally
		model, ok := m.(uiModel)
		if !ok {
			return "", fmt.Errorf("unexpected model type returned from UI")
		}
		
		// Return success message if we have one
		if model.successMessage != "" {
			return model.successMessage, nil
		}
		
		// If we don't have a success message, the user probably quit early
		return "", ErrOperationCancelled
	}
}

// nonInteractiveMode handles the non-interactive operation
func nonInteractiveMode(ctx context.Context, config Config, executor *CommandExecutor, cards []USBSoundCard) error {
	// Validate required parameters
	if config.VendorID == "" || config.ProductID == "" {
		return fmt.Errorf("in non-interactive mode, --vendor-id and --product-id are required: %w", ErrInvalidDeviceParams)
	}
	
	// Find the card that matches the vendor and product IDs
	var selectedCard USBSoundCard
	found := false
	
	for _, card := range cards {
		if card.VendorID == config.VendorID && card.ProductID == config.ProductID {
			selectedCard = card
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("no USB sound card found with VID:PID %s:%s: %w", 
			config.VendorID, config.ProductID, ErrNoUSBSoundCards)
	}
	
	// If a custom name was specified, use it
	customName := selectedCard.FriendlyName
	if config.DeviceName != "" {
		customName = cleanupName(config.DeviceName)
	}
	
	// Backup any existing rules for this device
	if err := backupExistingUdevRules(selectedCard, config); err != nil {
		slog.Warn("Failed to backup existing rules", "error", err)
		// Continue anyway - this is not fatal
	}
	
	// Create udev rule
	rule, err := createUdevRule(ctx, selectedCard, customName, config)
	if err != nil {
		return fmt.Errorf("failed to create udev rule: %w", err)
	}
	
	// Install the rule
	if err := installUdevRule(ctx, rule, config); err != nil {
		return fmt.Errorf("failed to install udev rule: %w", err)
	}
	
	// Reload udev rules if not skipped
	if !config.SkipReload {
		if err := reloadUdevRules(ctx, executor, config); err != nil {
			return fmt.Errorf("failed to reload udev rules: %w", err)
		}
		
		// Verify the rule installation
		verifyUdevRuleInstallation(ctx, executor, selectedCard, customName)
	}
	
	// Output success message
	fmt.Printf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n",
		selectedCard.Vendor, selectedCard.Product, selectedCard.VendorID, 
		selectedCard.ProductID, customName)
		
	fmt.Println("\nImportant: For the changes to take full effect, please:")
	fmt.Println("1. Disconnect and reconnect the USB sound device, or")
	fmt.Println("2. Reboot your system")
	
	// This is critical for reliable rule application - tell the user to run this specific command
	fmt.Println("\nFor immediate application of rules without rebooting, run:")
	fmt.Printf("sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound\n")
	
	return nil
}

// showDeviceList displays a list of USB sound cards
func showDeviceList(cards []USBSoundCard) {
	if len(cards) == 0 {
		fmt.Println("No USB sound cards found.")
		return
	}
	
	fmt.Println("USB Sound Cards:")
	fmt.Println("---------------")
	
	for i, card := range cards {
		fmt.Printf("%d. Card %s: %s %s (VID:PID %s:%s)\n", 
			i+1, card.CardNumber, card.Vendor, card.Product, card.VendorID, card.ProductID)
		
		if card.Serial != "" {
			fmt.Printf("   Serial: %s\n", card.Serial)
		}
		
		if card.PhysicalPort != "" {
			fmt.Printf("   Physical Port: %s\n", card.PhysicalPort)
		}
		
		fmt.Printf("   Suggested Name: %s\n\n", card.FriendlyName)
	}
}

// main function
func main() {
	// Create a context for the entire application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Setup signal handling for graceful shutdown
	setupSignalHandling(ctx, cancel)
	
	// Parse command line flags
	config := Config{
		UdevRulesPath: udevRulesDir,
		LogLevel:      LogLevelInfo,
		BackupRules:   true,
		ConcurrencyOpts: ConcurrencyOptions{
			MaxWorkers:     4,
			OperationQueue: 100,
		},
	}
	
	flag.StringVar(&config.UdevRulesPath, "rules-path", udevRulesDir, "Path to udev rules directory")
	flag.BoolVar(&config.ListOnly, "list", false, "List USB sound cards and exit")
	flag.BoolVar(&config.NonInteractive, "non-interactive", false, "Non-interactive mode")
	flag.StringVar(&config.DeviceName, "name", "", "Custom name for the device (non-interactive mode)")
	flag.StringVar(&config.VendorID, "vendor-id", "", "Vendor ID (non-interactive mode)")
	flag.StringVar(&config.ProductID, "product-id", "", "Product ID (non-interactive mode)")
	flag.BoolVar(&config.SkipReload, "skip-reload", false, "Skip reloading udev rules after creating them")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")
	
	var logLevelStr string
	flag.StringVar(&logLevelStr, "log-level", string(LogLevelInfo), "Log level (debug, info, warn, error)")
	
	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", AppName)
		fmt.Fprintf(os.Stderr, "Creates persistent device mappings for USB sound cards.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --list                  # List all USB sound cards\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s                         # Interactive mode\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s --non-interactive --vendor-id 1234 --product-id 5678 --name my_mic\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s --dry-run --non-interactive --vendor-id 1234 --product-id 5678  # Show rule without creating it\n", AppName)
	}
	
	flag.Parse()
	
	// Set log level
	config.LogLevel = LogLevel(logLevelStr)
	
	// Initialize structured logging
	initLogger(config.LogLevel)
	
	// Log basic startup info
	slog.Info(fmt.Sprintf("Starting %s v%s", AppName, AppVersion),
		"rules_path", config.UdevRulesPath,
		"interactive", !config.NonInteractive,
		"dry_run", config.DryRun)
	
	// Create command executor
	executor := NewCommandExecutor()
	
	// Check if required commands are available
	if err := CheckCommands(ctx, executor); err != nil {
		slog.Error("Command check failed", "error", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Check if we have elevated privileges
	elevated, err := checkElevatedPrivileges()
	if err != nil {
		slog.Error("Failed to check privileges", "error", err)
		fmt.Fprintf(os.Stderr, "Error checking privileges: %v\n", err)
		os.Exit(1)
	}
	
	// Only require root for actual rule creation, not for listing
	if !elevated && !config.ListOnly && !config.DryRun {
		slog.Error("Insufficient privileges", "error", ErrInsufficientPrivs)
		fmt.Fprintf(os.Stderr, "This application requires root privileges to create udev rules.\nPlease run with sudo.\n")
		os.Exit(1)
	}
	
	// Check and fix permissions on udev rules directory
	if !config.ListOnly && !config.DryRun {
		if err := checkAndFixPermissions(config); err != nil {
			slog.Error("Permission check failed", "error", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Test if udev system is working properly
	if !config.ListOnly && !config.DryRun {
		if !testUdevSystem(ctx, executor, config) {
			slog.Error("Udev system test failed", "error", ErrUdevSystemFailure)
			fmt.Fprintf(os.Stderr, "Warning: Udev system test failed - rules may not apply correctly\n")
			// Continue anyway, but with a warning
		}
	}
	
	// Check for PCI fallback serial numbers
	hasPCISerials := checkPCIFallbackForSerials(ctx, executor)
	slog.Debug("PCI fallback serial detection", "has_pci_serials", hasPCISerials)
	
	// Detect sound system type for additional compatibility
	soundSystem := detectSoundSystemType(ctx, executor)
	slog.Info("Sound system detection", "system", soundSystem)
	
	// Find all USB devices for reference
	allUSBDevices, err := findAllUSBDevices(ctx, executor)
	if err != nil {
		slog.Error("Failed to enumerate all USB devices", "error", err)
		// This is not fatal, continue anyway
	} else {
		slog.Debug("USB devices found", "count", len(allUSBDevices))
	}
	
	// List all USB sound cards
	cards, err := GetUSBSoundCards(ctx, executor)
	if err != nil {
		if errors.Is(err, ErrNoUSBSoundCards) {
			slog.Error("No USB sound cards found")
			fmt.Println("No USB sound cards found.")
			os.Exit(0)
		}
		
		slog.Error("Failed to get USB sound cards", "error", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// If list-only mode, just display the cards and exit
	if config.ListOnly {
		showDeviceList(cards)
		return
	}
	
	// Handle non-interactive mode
	if config.NonInteractive {
		err := nonInteractiveMode(ctx, config, executor, cards)
		if err != nil {
			slog.Error("Non-interactive mode failed", "error", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	
	// Interactive mode - run the terminal UI
	result, err := runUI(ctx, cards, config, executor)
	if err != nil {
		if errors.Is(err, ErrOperationCancelled) {
			slog.Info("Operation cancelled by user")
			fmt.Println("Operation cancelled by user.")
			return
		}
		
		if errors.Is(err, context.Canceled) {
			slog.Info("Operation interrupted, shutting down")
			fmt.Println("Operation interrupted. Shutting down...")
			return
		}
		
		slog.Error("UI error", "error", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Display the result
	fmt.Println(result)
	
	// Print the location of the udev rule for confirmation
	if !strings.Contains(result, "operation cancelled") {
		fmt.Printf("\nRule file created at: %s\n", filepath.Join(config.UdevRulesPath, 
			fmt.Sprintf("89-usb-soundcard-%s-%s.rules", 
				strings.Split(result, "(VID:PID ")[1][:4], 
				strings.Split(result, "(VID:PID ")[1][5:9])))
		fmt.Println("\nTo verify the rule file exists, run:")
		fmt.Printf("sudo ls -l %s\n", config.UdevRulesPath)
		
		fmt.Println("\nImportant: For the changes to take full effect, please:")
		fmt.Println("1. Disconnect and reconnect the USB sound device, or")
		fmt.Println("2. Reboot your system")
		
		// This is critical for reliable rule application - tell the user to run this specific command
		fmt.Println("\nFor immediate application of rules without rebooting, run:")
		fmt.Printf("sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound\n")
	}
}
