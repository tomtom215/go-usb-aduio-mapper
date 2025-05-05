package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
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

// Version information
const (
	AppName    = "usb-soundcard-mapper"
	AppVersion = "1.3.0"
)

// viewState represents the current UI state
type viewState int

const (
	stateCardSelect viewState = iota
	stateNameInput
	stateConfirmation
	stateError
)

// USBSoundCard represents a USB sound card device
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
}

// Configuration for the application
type Config struct {
	UdevRulesPath   string
	ListOnly        bool
	NonInteractive  bool
	DeviceName      string
	VendorID        string
	ProductID       string
	Debug           bool
	SkipReload      bool
}

// Logger provides structured logging with debug capability
type Logger struct {
	debug bool
	mu    sync.Mutex
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	return &Logger{
		debug: debug,
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[INFO] "+format, v...)
}

// Error logs error messages
func (l *Logger) Error(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[ERROR] "+format, v...)
}

// Debug logs debug messages only when debug mode is enabled
func (l *Logger) Debug(format string, v ...interface{}) {
	if !l.debug {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[DEBUG] "+format, v...)
}

// CommandExecutor wraps command execution with proper error handling
type CommandExecutor struct {
	// DefaultTimeout is the default timeout for command execution
	DefaultTimeout time.Duration
	logger         *Logger
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor(logger *Logger) *CommandExecutor {
	return &CommandExecutor{
		DefaultTimeout: 5 * time.Second,
		logger:         logger,
	}
}

// ExecuteCommand executes a command with proper timeout and error handling
func (ce *CommandExecutor) ExecuteCommand(command string, args ...string) (string, error) {
	return ce.ExecuteCommandWithTimeout(ce.DefaultTimeout, command, args...)
}

// ExecuteCommandWithTimeout executes a command with a specific timeout
func (ce *CommandExecutor) ExecuteCommandWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ce.logger.Debug("Executing command: %s %v", command, args)
	cmd := exec.CommandContext(ctx, command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("command timed out after %s", timeout)
	}

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
func CheckCommands(executor *CommandExecutor) error {
	requiredCommands := []string{"lsusb", "aplay", "udevadm"}
	
	for _, cmd := range requiredCommands {
		_, err := exec.LookPath(cmd)
		if err != nil {
			return fmt.Errorf("required command '%s' not found: %w", cmd, err)
		}
	}
	
	return nil
}

// CheckPCIFallbackForSerials verifies if PCI paths are being used as serial numbers
func CheckPCIFallbackForSerials(executor *CommandExecutor, logger *Logger) {
	// Run command to see if any device has a PCI-like serial
	output, _ := executor.ExecuteCommand("lsusb", "-v")
	if strings.Contains(output, "iSerial") && strings.Contains(output, ":") {
		logger.Info("Detected devices with PCI path-like serial numbers. Special handling will be applied.")
	}
}

// GetUSBSoundCards detects all USB sound cards in the system
func GetUSBSoundCards(executor *CommandExecutor) ([]USBSoundCard, error) {
	var cards []USBSoundCard
	
	// Get list of all sound cards using aplay
	output, err := executor.ExecuteCommand("aplay", "-l")
	if err != nil {
		return nil, fmt.Errorf("failed to list sound cards: %w", err)
	}
	
	// Parse the output to find USB sound cards
	scanner := bufio.NewScanner(strings.NewReader(output))
	cardRegexp := regexp.MustCompile(`card (\d+):.*\[(.+)\].*\[(.+)\]`)
	
	for scanner.Scan() {
		line := scanner.Text()
		matches := cardRegexp.FindStringSubmatch(line)
		if matches != nil && len(matches) >= 4 {
			cardNumber := matches[1]
			
			// Skip non-USB cards
			if !strings.Contains(strings.ToLower(line), "usb") {
				continue
			}
			
			// Get more details about this card
			card, err := getCardDetails(executor, cardNumber)
			if err != nil {
				executor.logger.Error("Failed to get details for card %s: %v", cardNumber, err)
				continue
			}
			
			cards = append(cards, card)
		}
	}

	if err := scanner.Err(); err != nil {
		return cards, fmt.Errorf("error scanning aplay output: %w", err)
	}
	
	return cards, nil
}

// getCardDetails gets detailed information about a sound card
func getCardDetails(executor *CommandExecutor, cardNumber string) (USBSoundCard, error) {
	card := USBSoundCard{
		CardNumber: cardNumber,
		DevicePath: fmt.Sprintf("/dev/snd/card%s", cardNumber),
	}
	
	// Get card path in sysfs
	sysfsPath := fmt.Sprintf("/sys/class/sound/card%s", cardNumber)
	
	// Run udevadm to get detailed device information
	output, err := executor.ExecuteCommand("udevadm", "info", "--attribute-walk", "--path", sysfsPath)
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
	
	// Get vendor/product names from lsusb if we have vendor and product IDs
	if card.VendorID != "" && card.ProductID != "" {
		lsusbOutput, err := executor.ExecuteCommand("lsusb", "-d", fmt.Sprintf("%s:%s", card.VendorID, card.ProductID))
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
	
	// Create a friendly name based on available information
	if card.Serial != "" {
		// Check for PCI-like serial numbers (which aren't really unique to the device but to the USB port)
		if strings.Contains(card.Serial, ":") {
			// For PCI-like serials, create a name based on product ID and port
			if card.PhysicalPort != "" {
				card.FriendlyName = fmt.Sprintf("usb_%s_%s_port%s", card.VendorID, card.ProductID, 
					strings.Replace(card.PhysicalPort, "-", "_", -1))
			} else {
				card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.CardNumber)
			}
		} else {
			// Normal serial number
			card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.Serial)
		}
	} else if card.PhysicalPort != "" {
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_port%s", card.VendorID, card.ProductID, 
			strings.Replace(card.PhysicalPort, "-", "_", -1))
	} else {
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.CardNumber)
	}
	
	// Clean up the friendly name to ensure it's a valid ID
	card.FriendlyName = cleanupName(card.FriendlyName)
	
	return card, nil
}

// cleanupName ensures the generated name is valid for udev
func cleanupName(name string) string {
	// Replace any non-alphanumeric characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name = re.ReplaceAllString(name, "_")
	
	// Ensure it doesn't start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "usb_" + name
	}
	
	return name
}

// createUdevRule creates a udev rule to give the sound card a persistent name
func createUdevRule(card USBSoundCard, customName string, config Config, logger *Logger) error {
	// Verify we have the necessary information
	if card.VendorID == "" || card.ProductID == "" {
		return fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}

	// Use custom name if provided, otherwise use the default
	deviceName := card.FriendlyName
	if customName != "" {
		deviceName = cleanupName(customName)
	}
	
	// Create rule content - Using string slice and Join to avoid escape issues
	var ruleLines []string
	
	// Add header
	ruleLines = append(ruleLines, "# USB sound card persistent mapping created by usb-soundcard-mapper")
	ruleLines = append(ruleLines, "# Device: "+card.Vendor+" "+card.Product)
	
	// Create multiple matching rules for different scenarios
	// Critical: Need at least 3 different matching approaches for reliability
	
	// 1. Priority rule for ACTION=="add" with full device attributes 
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		// If we have a normal serial number, use it for more reliable mapping
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTRS{serial}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.Serial, deviceName))
	} else if card.PhysicalPort != "" {
		// Use physical port for devices without serial numbers
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", KERNELS=="%s*", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName))
	} else {
		// Fallback to basic vendor/product ID mapping (less reliable)
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, deviceName))
	}
	
	// 2. Rule for ENV{SOUND_INITIALIZED}=="1" for after sound system is fully running
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTRS{serial}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.Serial, deviceName))
	} else if card.PhysicalPort != "" {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", KERNELS=="%s*", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName))
	} else {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, deviceName))
	}
	
	// 3. Universal rule for any sound card with the specific USB vendor/product ID
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
		card.VendorID, card.ProductID, deviceName))
	
	// 4. Alternative rule with different path attribute for the kernel
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", KERNEL=="card*", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
		card.VendorID, card.ProductID, deviceName))
		
	// 5. Add a symlink rule
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="sound/by-id/%s"`, 
		card.VendorID, card.ProductID, deviceName))
	
	// Create a fallback symlink with ACTION=="change" as well
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", ACTION=="change", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="sound/by-id/%s"`, 
		card.VendorID, card.ProductID, deviceName))
	
	// Join all lines with proper newlines
	ruleContent := strings.Join(ruleLines, "\n") + "\n"
	
	// Create the rule file path
	ruleFile := filepath.Join(config.UdevRulesPath, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", 
		card.VendorID, card.ProductID))
	
	// Log the exact file path being used
	logger.Info("Creating udev rule file at: %s", ruleFile)
	
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(config.UdevRulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create udev rules directory: %w", err)
	}
	
	// Write the rule directly to the file - no more using temporary files to avoid issues
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write udev rule file: %w", err)
	}
	
	// Set correct permissions
	if err := os.Chmod(ruleFile, 0644); err != nil {
		return fmt.Errorf("failed to set rule file permissions: %w", err)
	}
	
	// Verify the file was actually created with the correct content
	if contents, err := os.ReadFile(ruleFile); err != nil {
		return fmt.Errorf("error verifying udev rule file: %w", err)
	} else {
		// Log the actual content that was written
		logger.Debug("Rule file content: %s", string(contents))
		
		// Verify content was written properly
		if !strings.Contains(string(contents), deviceName) {
			return fmt.Errorf("rule file was created but does not contain the device name: %s", deviceName)
		}
		
		// Verify proper line breaks
		if !strings.Contains(string(contents), "\nSUBSYSTEM") {
			logger.Error("Rule file was created but may have formatting issues!")
		}
	}

	logger.Info("Created udev rule at %s", ruleFile)
	
	// For extra safety, also create a modprobe configuration to help with sound card loading
	modprobePath := "/etc/modprobe.d"
	if FileExists(modprobePath) {
		modprobeFile := filepath.Join(modprobePath, fmt.Sprintf("99-soundcard-%s-%s.conf", 
			card.VendorID, card.ProductID))
		
		modprobeContent := fmt.Sprintf("# Modprobe options for USB sound card %s %s\n", 
			card.Vendor, card.Product)
		modprobeContent += "options snd_usb_audio index=-2\n"
		
		// Write the modprobe file if it doesn't exist already
		if !FileExists(modprobeFile) {
			logger.Info("Creating modprobe configuration at %s", modprobeFile)
			if err := os.WriteFile(modprobeFile, []byte(modprobeContent), 0644); err != nil {
				logger.Error("Failed to write modprobe configuration: %v", err)
				// This is not fatal, continue anyway
			}
		}
	}
	
	return nil
}

// reloadUdevRules triggers a reload of udev rules
func reloadUdevRules(executor *CommandExecutor) error {
	// Reload udev rules
	if _, err := executor.ExecuteCommand("udevadm", "control", "--reload-rules"); err != nil {
		return fmt.Errorf("failed to reload udev rules: %w", err)
	}
	
	// Sleep to give udev time to process the rule reloading
	time.Sleep(1 * time.Second)
	
	// Trigger the rules for all sound devices - using add action for more reliable application
	if _, err := executor.ExecuteCommand("udevadm", "trigger", "--action=add", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules with add action: %w", err)
	}

	// Sleep to give udev time to apply the rules
	time.Sleep(2 * time.Second)
	
	// Also trigger with change action as a fallback
	if _, err := executor.ExecuteCommand("udevadm", "trigger", "--action=change", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules with change action: %w", err)
	}
	
	// Sleep again to ensure rules are fully applied
	time.Sleep(2 * time.Second)
	
	return nil
}

// checkElevatedPrivileges checks if the process has the necessary privileges
func checkElevatedPrivileges() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}
	
	return currentUser.Uid == "0", nil
}

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
	logger          *Logger
	error           string
	width           int
	height          int
	successMessage  string
}

// Initialize UI model
func initialUIModel(cards []USBSoundCard, config Config, executor *CommandExecutor, logger *Logger) uiModel {
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
		logger:    logger,
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
			m.logger.Debug("Quitting application")
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
					m.logger.Error("No card selected or no cards available")
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
				err := createUdevRule(m.selectedCard, m.customName, m.config, m.logger)
				if err != nil {
					m.logger.Error("Failed to create udev rule: %v", err)
					m.error = fmt.Sprintf("Failed to create udev rule: %v", err)
					m.state = stateError
					return m, nil
				}
				
				// Reload udev rules if not skipped
				if !m.config.SkipReload {
					err = reloadUdevRules(m.executor)
					if err != nil {
						m.logger.Error("Failed to reload udev rules: %v", err)
						m.error = fmt.Sprintf("Failed to reload udev rules: %v", err)
						m.state = stateError
						return m, nil
					}
				}
				
				// Success message
				m.successMessage = fmt.Sprintf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n\n"+
					"The sound card will use this name consistently across reboots and reconnections.\n"+
					"You can see this device in 'aplay -l' output as card with ID '%s'\n"+
					"once you disconnect and reconnect the device.",
					m.selectedCard.Vendor, m.selectedCard.Product, 
					m.selectedCard.VendorID, m.selectedCard.ProductID, 
					m.customName, m.customName)
				
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
func runUI(cards []USBSoundCard, config Config, executor *CommandExecutor, logger *Logger) (string, error) {
	if len(cards) == 0 {
		return "", fmt.Errorf("no USB sound cards found")
	}
	
	p := tea.NewProgram(initialUIModel(cards, config, executor, logger), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("error running UI: %w", err)
	}
	
	model, ok := m.(uiModel)
	if !ok {
		return "", fmt.Errorf("unexpected model type returned from UI")
	}
	
	// Return success message if we have one
	if model.successMessage != "" {
		return model.successMessage, nil
	}
	
	// If we don't have a success message, the user probably quit early
	return "", fmt.Errorf("operation cancelled by user")
}

// setupSignalHandling sets up graceful shutdown on system signals
func setupSignalHandling(logger *Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		logger.Info("Received interrupt signal, shutting down gracefully")
		os.Exit(0)
	}()
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return !info.IsDir()
}

// DirectoryExists checks if a directory exists
func DirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return info.IsDir()
}

// BackupExistingUdevRules creates a backup of existing rules files
func BackupExistingUdevRules(cardVendorID, cardProductID string, config Config, logger *Logger) error {
	// Pattern for rule files we might want to back up
	patterns := []string{
		fmt.Sprintf("*usb-soundcard*%s*%s*.rules", cardVendorID, cardProductID),
		fmt.Sprintf("*usb*sound*%s*%s*.rules", cardVendorID, cardProductID),
		fmt.Sprintf("*sound*%s*%s*.rules", cardVendorID, cardProductID),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(config.UdevRulesPath, pattern))
		if err != nil {
			logger.Error("Error searching for existing rules: %v", err)
			continue
		}

		for _, match := range matches {
			// Skip backing up our own rule file
			if strings.Contains(match, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", cardVendorID, cardProductID)) {
				continue
			}

			// Create backup with timestamp
			backupFile := match + ".bak." + time.Now().Format("20060102150405")
			logger.Info("Backing up existing rule file %s to %s", match, backupFile)

			content, err := os.ReadFile(match)
			if err != nil {
				logger.Error("Failed to read existing rule file %s: %v", match, err)
				continue
			}

			err = os.WriteFile(backupFile, content, 0644)
			if err != nil {
				logger.Error("Failed to write backup file %s: %v", backupFile, err)
				continue
			}

			// Don't delete the original - just leave it as a backup
		}
	}

	return nil
}

// verifyUdevRuleInstallation checks if the rule is properly installed
func verifyUdevRuleInstallation(card USBSoundCard, customName string, executor *CommandExecutor, logger *Logger) bool {
	// Check if udev rules were reloaded successfully
	output, err := executor.ExecuteCommand("udevadm", "info", "--path", fmt.Sprintf("/sys/class/sound/card%s", card.CardNumber))
	if err != nil {
		logger.Error("Failed to verify udev rule installation: %v", err)
		return false
	}

	// Look for the custom name in the output
	if strings.Contains(output, fmt.Sprintf("ID_SOUND_ID=%s", customName)) {
		logger.Info("Verified successful udev rule installation!")
		return true
	}

	// If not found, try to trigger the rule specifically for this device
	logger.Info("Rule verification failed. Trying to trigger rules specifically for this device...")
	
	_, err = executor.ExecuteCommand("udevadm", "trigger", "--action=add", 
		"--property-match=SUBSYSTEM=sound", 
		fmt.Sprintf("--property-match=ID_VENDOR_ID=%s", card.VendorID),
		fmt.Sprintf("--property-match=ID_MODEL_ID=%s", card.ProductID))
	
	if err != nil {
		logger.Error("Failed to trigger specific udev rules: %v", err)
		return false
	}

	// Give it a moment to apply
	time.Sleep(2 * time.Second)
	
	return true
}

// Write a test udev rule to verify udev is working properly
func testUdevSystem(executor *CommandExecutor, logger *Logger) bool {
	logger.Info("Testing if udev rule system is working properly...")
	
	// Create a small test rule
	testRuleFile := "/etc/udev/rules.d/99-test-usb-soundcard-mapper.rules"
	testRuleContent := "# Test rule to check if udev is functioning properly\n"
	
	// Write test rule
	err := os.WriteFile(testRuleFile, []byte(testRuleContent), 0644)
	if err != nil {
		logger.Error("Failed to write test udev rule: %v", err)
		return false
	}
	
	// Try to reload udev rules
	_, err = executor.ExecuteCommand("udevadm", "control", "--reload-rules")
	if err != nil {
		logger.Error("Failed to reload udev rules during test: %v", err)
		os.Remove(testRuleFile) // Clean up
		return false
	}
	
	// Clean up test rule
	os.Remove(testRuleFile)
	
	logger.Info("Udev system test passed")
	return true
}

// checkAndFixPermissions ensures the udev rules directory has the correct permissions
func checkAndFixPermissions(config Config, logger *Logger) error {
	// Check if the rules directory exists and has correct permissions
	info, err := os.Stat(config.UdevRulesPath)
	if err != nil {
		if os.IsNotExist(err) {
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
		logger.Info("Fixing permissions on %s", config.UdevRulesPath)
		err = os.Chmod(config.UdevRulesPath, 0755)
		if err != nil {
			return fmt.Errorf("failed to set permissions on udev rules directory: %w", err)
		}
	}
	
	return nil
}

// detectSoundSystemType checks what sound system is in use (ALSA, PulseAudio, etc.)
func detectSoundSystemType(executor *CommandExecutor, logger *Logger) string {
	// Check for PulseAudio
	_, err := executor.ExecuteCommand("pulseaudio", "--version")
	if err == nil {
		logger.Info("Detected PulseAudio sound system")
		return "pulseaudio"
	}
	
	// Check for PipeWire
	_, err = executor.ExecuteCommand("pipewire", "--version")
	if err == nil {
		logger.Info("Detected PipeWire sound system")
		return "pipewire"
	}
	
	// Default to ALSA
	logger.Info("Assuming ALSA sound system")
	return "alsa"
}

// createAudioSymlinkRules creates additional symlink rules for audio-specific paths
func createAudioSymlinkRules(card USBSoundCard, customName string, config Config, logger *Logger) error {
	// Create audio-specific symlink rule file
	ruleFile := filepath.Join(config.UdevRulesPath, fmt.Sprintf("90-audio-symlinks-%s-%s.rules", 
		card.VendorID, card.ProductID))
	
	var ruleLines []string
	
	// Add header
	ruleLines = append(ruleLines, "# Audio symlink rules for USB sound card created by usb-soundcard-mapper")
	ruleLines = append(ruleLines, "# Device: "+card.Vendor+" "+card.Product)
	
	// Create symlinks for audio control devices
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", KERNEL=="controlC*", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="audio/%s/control"`,
		card.VendorID, card.ProductID, customName))
	
	// Create symlinks for PCM devices
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", KERNEL=="pcmC*D*p", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="audio/%s/playback"`,
		card.VendorID, card.ProductID, customName))
	
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", KERNEL=="pcmC*D*c", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="audio/%s/capture"`,
		card.VendorID, card.ProductID, customName))
	
	// Join all lines with proper newlines
	ruleContent := strings.Join(ruleLines, "\n") + "\n"
	
	// Write the rule file
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		logger.Error("Failed to write audio symlink rules: %v", err)
		// This is not fatal, continue anyway
		return nil
	}
	
	logger.Info("Created audio symlink rules at %s", ruleFile)
	return nil
}

// findAllUSBDevices gets information about all connected USB devices
func findAllUSBDevices(executor *CommandExecutor) (map[string]map[string]string, error) {
	devices := make(map[string]map[string]string)
	
	// Get all USB devices from lsusb
	output, err := executor.ExecuteCommand("lsusb")
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

// main function
func main() {
	// Parse command line flags
	config := Config{}
	
	flag.StringVar(&config.UdevRulesPath, "rules-path", "/etc/udev/rules.d", "Path to udev rules directory")
	flag.BoolVar(&config.ListOnly, "list", false, "List USB sound cards and exit")
	flag.BoolVar(&config.NonInteractive, "non-interactive", false, "Non-interactive mode")
	flag.StringVar(&config.DeviceName, "name", "", "Custom name for the device (non-interactive mode)")
	flag.StringVar(&config.VendorID, "vendor-id", "", "Vendor ID (non-interactive mode)")
	flag.StringVar(&config.ProductID, "product-id", "", "Product ID (non-interactive mode)")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&config.SkipReload, "skip-reload", false, "Skip reloading udev rules after creating them")
	
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
	}
	
	flag.Parse()
	
	// Configure logging
	logger := NewLogger(config.Debug)
	logger.Info("Starting %s v%s", AppName, AppVersion)
	
	// Setup signal handling for graceful shutdown
	setupSignalHandling(logger)
	
	// Create command executor
	executor := NewCommandExecutor(logger)
	
	// Check if required commands are available
	if err := CheckCommands(executor); err != nil {
		logger.Error("Command check failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Check and fix permissions on udev rules directory
	if err := checkAndFixPermissions(config, logger); err != nil {
		logger.Error("Permission check failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Test if udev system is working properly
	if !testUdevSystem(executor, logger) {
		logger.Error("Udev system test failed - proceeding anyway but results may be unreliable")
		fmt.Fprintf(os.Stderr, "Warning: Udev system test failed - rules may not apply correctly\n")
	}
	
	// Check for PCI fallback serial numbers
	CheckPCIFallbackForSerials(executor, logger)
	
	// Detect sound system type for additional compatibility
	soundSystem := detectSoundSystemType(executor, logger)
	if soundSystem != "alsa" {
		logger.Info("Detected %s sound system - creating compatible rules", soundSystem)
	}
	
	// Find all USB devices for reference
	allUSBDevices, err := findAllUSBDevices(executor)
	if err != nil {
		logger.Error("Failed to enumerate all USB devices: %v", err)
		// This is not fatal, continue anyway
	} else {
		logger.Debug("Found %d USB devices in the system", len(allUSBDevices))
	}
	
	// List all USB sound cards
	cards, err := GetUSBSoundCards(executor)
	if err != nil {
		logger.Error("Failed to get USB sound cards: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// If list-only mode, just display the cards and exit
	if config.ListOnly {
		fmt.Println("USB Sound Cards:")
		fmt.Println("---------------")
		if len(cards) == 0 {
			fmt.Println("No USB sound cards found.")
			return
		}
		
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
		return
	}
	
	// Check privileges for creating udev rules
	elevated, err := checkElevatedPrivileges()
	if err != nil {
		logger.Error("Failed to check privileges: %v", err)
		fmt.Fprintf(os.Stderr, "Error checking privileges: %v\n", err)
		os.Exit(1)
	}
	
	if !elevated {
		logger.Error("Insufficient privileges")
		fmt.Fprintf(os.Stderr, "This application requires root privileges to create udev rules.\nPlease run with sudo.\n")
		os.Exit(1)
	}
	
	// Handle non-interactive mode
	if config.NonInteractive {
		if config.VendorID == "" || config.ProductID == "" {
			logger.Error("Missing required parameters for non-interactive mode")
			fmt.Fprintf(os.Stderr, "In non-interactive mode, --vendor-id and --product-id are required\n")
			os.Exit(1)
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
			logger.Error("No matching USB sound card found")
			fmt.Fprintf(os.Stderr, "No USB sound card found with VID:PID %s:%s\n", config.VendorID, config.ProductID)
			os.Exit(1)
		}
		
		// If a custom name was specified, use it
		customName := selectedCard.FriendlyName
		if config.DeviceName != "" {
			customName = cleanupName(config.DeviceName)
		}
		
		// Backup any existing rules for this device
		if err := BackupExistingUdevRules(selectedCard.VendorID, selectedCard.ProductID, config, logger); err != nil {
			logger.Error("Warning: Failed to backup existing rules: %v", err)
			// Continue anyway - this is not fatal
		}
		
		// Create udev rule
		if err := createUdevRule(selectedCard, customName, config, logger); err != nil {
			logger.Error("Failed to create udev rule: %v", err)
			fmt.Fprintf(os.Stderr, "Error creating udev rule: %v\n", err)
			os.Exit(1)
		}
		
		// Also create audio symlink rules for better compatibility
		createAudioSymlinkRules(selectedCard, customName, config, logger)
		
		// Reload udev rules
		if !config.SkipReload {
			if err := reloadUdevRules(executor); err != nil {
				logger.Error("Failed to reload udev rules: %v", err)
				fmt.Fprintf(os.Stderr, "Error reloading udev rules: %v\n", err)
				os.Exit(1)
			}
			
			// Verify the rule installation
			verifyUdevRuleInstallation(selectedCard, customName, executor, logger)
		}
		
		fmt.Printf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n",
			selectedCard.Vendor, selectedCard.Product, selectedCard.VendorID, 
			selectedCard.ProductID, customName)
			
		fmt.Println("\nImportant: For the changes to take full effect, please:")
		fmt.Println("1. Disconnect and reconnect the USB sound device, or")
		fmt.Println("2. Reboot your system")
		
		// This is critical for reliable rule application - tell the user to run this specific command
		fmt.Println("\nFor immediate application of rules without rebooting, run:")
		fmt.Printf("sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound\n")
		
		return
	}
	
	// Interactive mode - run the terminal UI
	if len(cards) == 0 {
		logger.Error("No USB sound cards found")
		fmt.Fprintf(os.Stderr, "No USB sound cards found.\n")
		os.Exit(1)
	}
	
	// Backup existing rules for found cards
	for _, card := range cards {
		if err := BackupExistingUdevRules(card.VendorID, card.ProductID, config, logger); err != nil {
			logger.Error("Warning: Failed to backup existing rules for card %s: %v", card.CardNumber, err)
			// Continue anyway - this is not fatal
		}
	}
	
	// Run the UI and get the result
	result, err := runUI(cards, config, executor, logger)
	if err != nil {
		logger.Error("UI error: %v", err)
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
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Version information
const (
	AppName    = "usb-soundcard-mapper"
	AppVersion = "1.3.0"
)

// viewState represents the current UI state
type viewState int

const (
	stateCardSelect viewState = iota
	stateNameInput
	stateConfirmation
	stateError
)

// USBSoundCard represents a USB sound card device
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
}

// Configuration for the application
type Config struct {
	UdevRulesPath   string
	ListOnly        bool
	NonInteractive  bool
	DeviceName      string
	VendorID        string
	ProductID       string
	Debug           bool
	SkipReload      bool
}

// Logger provides structured logging with debug capability
type Logger struct {
	debug bool
	mu    sync.Mutex
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	return &Logger{
		debug: debug,
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[INFO] "+format, v...)
}

// Error logs error messages
func (l *Logger) Error(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[ERROR] "+format, v...)
}

// Debug logs debug messages only when debug mode is enabled
func (l *Logger) Debug(format string, v ...interface{}) {
	if !l.debug {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf("[DEBUG] "+format, v...)
}

// CommandExecutor wraps command execution with proper error handling
type CommandExecutor struct {
	// DefaultTimeout is the default timeout for command execution
	DefaultTimeout time.Duration
	logger         *Logger
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor(logger *Logger) *CommandExecutor {
	return &CommandExecutor{
		DefaultTimeout: 5 * time.Second,
		logger:         logger,
	}
}

// ExecuteCommand executes a command with proper timeout and error handling
func (ce *CommandExecutor) ExecuteCommand(command string, args ...string) (string, error) {
	return ce.ExecuteCommandWithTimeout(ce.DefaultTimeout, command, args...)
}

// ExecuteCommandWithTimeout executes a command with a specific timeout
func (ce *CommandExecutor) ExecuteCommandWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ce.logger.Debug("Executing command: %s %v", command, args)
	cmd := exec.CommandContext(ctx, command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("command timed out after %s", timeout)
	}

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
func CheckCommands(executor *CommandExecutor) error {
	requiredCommands := []string{"lsusb", "aplay", "udevadm"}
	
	for _, cmd := range requiredCommands {
		_, err := exec.LookPath(cmd)
		if err != nil {
			return fmt.Errorf("required command '%s' not found: %w", cmd, err)
		}
	}
	
	return nil
}

// GetUSBSoundCards detects all USB sound cards in the system
func GetUSBSoundCards(executor *CommandExecutor) ([]USBSoundCard, error) {
	var cards []USBSoundCard
	
	// Get list of all sound cards using aplay
	output, err := executor.ExecuteCommand("aplay", "-l")
	if err != nil {
		return nil, fmt.Errorf("failed to list sound cards: %w", err)
	}
	
	// Parse the output to find USB sound cards
	scanner := bufio.NewScanner(strings.NewReader(output))
	cardRegexp := regexp.MustCompile(`card (\d+):.*\[(.+)\].*\[(.+)\]`)
	
	for scanner.Scan() {
		line := scanner.Text()
		matches := cardRegexp.FindStringSubmatch(line)
		if matches != nil && len(matches) >= 4 {
			cardNumber := matches[1]
			// We're storing this in a variable but not using it directly
			// The card details function will determine the card name
			_ = matches[2] // CardName is used within getCardDetails
			
			// Skip non-USB cards
			if !strings.Contains(strings.ToLower(line), "usb") {
				continue
			}
			
			// Get more details about this card
			card, err := getCardDetails(executor, cardNumber)
			if err != nil {
				executor.logger.Error("Failed to get details for card %s: %v", cardNumber, err)
				continue
			}
			
			cards = append(cards, card)
		}
	}

	if err := scanner.Err(); err != nil {
		return cards, fmt.Errorf("error scanning aplay output: %w", err)
	}
	
	return cards, nil
}

// getCardDetails gets detailed information about a sound card
func getCardDetails(executor *CommandExecutor, cardNumber string) (USBSoundCard, error) {
	card := USBSoundCard{
		CardNumber: cardNumber,
		DevicePath: fmt.Sprintf("/dev/snd/card%s", cardNumber),
	}
	
	// Get card path in sysfs
	sysfsPath := fmt.Sprintf("/sys/class/sound/card%s", cardNumber)
	
	// Run udevadm to get detailed device information
	output, err := executor.ExecuteCommand("udevadm", "info", "--attribute-walk", "--path", sysfsPath)
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
	
	// Get vendor/product names from lsusb if we have vendor and product IDs
	if card.VendorID != "" && card.ProductID != "" {
		lsusbOutput, err := executor.ExecuteCommand("lsusb", "-d", fmt.Sprintf("%s:%s", card.VendorID, card.ProductID))
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
	
	// Create a friendly name based on available information
	if card.Serial != "" {
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.Serial)
	} else if card.PhysicalPort != "" {
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_port%s", card.VendorID, card.ProductID, 
			strings.Replace(card.PhysicalPort, "-", "_", -1))
	} else {
		card.FriendlyName = fmt.Sprintf("usb_%s_%s_%s", card.VendorID, card.ProductID, card.CardNumber)
	}
	
	// Clean up the friendly name to ensure it's a valid ID
	card.FriendlyName = cleanupName(card.FriendlyName)
	
	return card, nil
}

// cleanupName ensures the generated name is valid for udev
func cleanupName(name string) string {
	// Replace any non-alphanumeric characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name = re.ReplaceAllString(name, "_")
	
	// Ensure it doesn't start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "usb_" + name
	}
	
	return name
}

// createUdevRule creates a udev rule to give the sound card a persistent name
func createUdevRule(card USBSoundCard, customName string, config Config, logger *Logger) error {
	// Verify we have the necessary information
	if card.VendorID == "" || card.ProductID == "" {
		return fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}

	// Use custom name if provided, otherwise use the default
	deviceName := card.FriendlyName
	if customName != "" {
		deviceName = cleanupName(customName)
	}
	
	// Create rule content - FIX: Using string slice and Join to avoid escape issues
	var ruleLines []string
	
	// Add header
	ruleLines = append(ruleLines, "# USB sound card persistent mapping created by usb-soundcard-mapper")
	ruleLines = append(ruleLines, "# Device: "+card.Vendor+" "+card.Product)
	
	// Create the mapping rule - ACTION=="add" critical for reliable application
	if card.Serial != "" {
		// If we have a serial number, use it for more reliable mapping
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTRS{serial}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.Serial, deviceName))
	} else if card.PhysicalPort != "" {
		// Use physical port for devices without serial numbers
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", KERNELS=="%s*", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName))
	} else {
		// Fallback to basic vendor/product ID mapping (less reliable)
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, deviceName))
	}
	
	// Add additional rule to ensure the name is also set after the system is running
	if card.Serial != "" {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTRS{serial}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.Serial, deviceName))
	} else if card.PhysicalPort != "" {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", KERNELS=="%s*", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, card.PhysicalPort, deviceName))
	} else {
		ruleLines = append(ruleLines, fmt.Sprintf(
			`SUBSYSTEM=="sound", ENV{SOUND_INITIALIZED}=="1", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"`,
			card.VendorID, card.ProductID, deviceName))
	}
	
	// Add a symlink rule - using separate rule for clarity
	ruleLines = append(ruleLines, fmt.Sprintf(
		`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", SYMLINK+="sound/by-id/%s"`, 
		card.VendorID, card.ProductID, deviceName))
	
	// Join all lines with proper newlines
	ruleContent := strings.Join(ruleLines, "\n") + "\n"
	
	// Create the rule file path
	ruleFile := filepath.Join(config.UdevRulesPath, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", 
		card.VendorID, card.ProductID))
	
	// Log the exact file path being used
	logger.Info("Creating udev rule file at: %s", ruleFile)
	
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(config.UdevRulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create udev rules directory: %w", err)
	}
	
	// Write the rule directly to the file - no more using temporary files to avoid issues
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write udev rule file: %w", err)
	}
	
	// Set correct permissions
	if err := os.Chmod(ruleFile, 0644); err != nil {
		return fmt.Errorf("failed to set rule file permissions: %w", err)
	}
	
	// Verify the file was actually created with the correct content
	if contents, err := os.ReadFile(ruleFile); err != nil {
		return fmt.Errorf("error verifying udev rule file: %w", err)
	} else {
		// Log the actual content that was written
		logger.Debug("Rule file content: %s", string(contents))
		
		// Verify content was written properly
		if !strings.Contains(string(contents), deviceName) {
			return fmt.Errorf("rule file was created but does not contain the device name: %s", deviceName)
		}
		
		// Verify proper line breaks
		if !strings.Contains(string(contents), "\nSUBSYSTEM") {
			logger.Error("Rule file was created but may have formatting issues!")
		}
	}

	logger.Info("Created udev rule at %s", ruleFile)
	
	return nil
}

// reloadUdevRules triggers a reload of udev rules
func reloadUdevRules(executor *CommandExecutor) error {
	// Reload udev rules
	if _, err := executor.ExecuteCommand("udevadm", "control", "--reload-rules"); err != nil {
		return fmt.Errorf("failed to reload udev rules: %w", err)
	}
	
	// Sleep to give udev time to process the rule reloading
	time.Sleep(1 * time.Second)
	
	// Trigger the rules for all sound devices - using add action for more reliable application
	if _, err := executor.ExecuteCommand("udevadm", "trigger", "--action=add", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules: %w", err)
	}

	// Sleep again to give udev time to apply the rules
	time.Sleep(2 * time.Second)
	
	return nil
}

// checkElevatedPrivileges checks if the process has the necessary privileges
func checkElevatedPrivileges() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}
	
	return currentUser.Uid == "0", nil
}

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
	logger          *Logger
	error           string
	width           int
	height          int
	successMessage  string
}

// Initialize UI model
func initialUIModel(cards []USBSoundCard, config Config, executor *CommandExecutor, logger *Logger) uiModel {
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
		logger:    logger,
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
			m.logger.Debug("Quitting application")
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
					m.logger.Error("No card selected or no cards available")
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
				err := createUdevRule(m.selectedCard, m.customName, m.config, m.logger)
				if err != nil {
					m.logger.Error("Failed to create udev rule: %v", err)
					m.error = fmt.Sprintf("Failed to create udev rule: %v", err)
					m.state = stateError
					return m, nil
				}
				
				// Reload udev rules if not skipped
				if !m.config.SkipReload {
					err = reloadUdevRules(m.executor)
					if err != nil {
						m.logger.Error("Failed to reload udev rules: %v", err)
						m.error = fmt.Sprintf("Failed to reload udev rules: %v", err)
						m.state = stateError
						return m, nil
					}
				}
				
				// Success message
				m.successMessage = fmt.Sprintf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n\n"+
					"The sound card will use this name consistently across reboots and reconnections.\n"+
					"You can see this device in 'aplay -l' output as card with ID '%s'\n"+
					"once you disconnect and reconnect the device.",
					m.selectedCard.Vendor, m.selectedCard.Product, 
					m.selectedCard.VendorID, m.selectedCard.ProductID, 
					m.customName, m.customName)
				
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
func runUI(cards []USBSoundCard, config Config, executor *CommandExecutor, logger *Logger) (string, error) {
	if len(cards) == 0 {
		return "", fmt.Errorf("no USB sound cards found")
	}
	
	p := tea.NewProgram(initialUIModel(cards, config, executor, logger), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("error running UI: %w", err)
	}
	
	model, ok := m.(uiModel)
	if !ok {
		return "", fmt.Errorf("unexpected model type returned from UI")
	}
	
	// Return success message if we have one
	if model.successMessage != "" {
		return model.successMessage, nil
	}
	
	// If we don't have a success message, the user probably quit early
	return "", fmt.Errorf("operation cancelled by user")
}

// setupSignalHandling sets up graceful shutdown on system signals
func setupSignalHandling(logger *Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		logger.Info("Received interrupt signal, shutting down gracefully")
		os.Exit(0)
	}()
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return !info.IsDir()
}

// BackupExistingUdevRules creates a backup of existing rules files
func BackupExistingUdevRules(cardVendorID, cardProductID string, config Config, logger *Logger) error {
	// Pattern for rule files we might want to back up
	patterns := []string{
		fmt.Sprintf("*usb-soundcard*%s*%s*.rules", cardVendorID, cardProductID),
		fmt.Sprintf("*usb*sound*%s*%s*.rules", cardVendorID, cardProductID),
		fmt.Sprintf("*sound*%s*%s*.rules", cardVendorID, cardProductID),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(config.UdevRulesPath, pattern))
		if err != nil {
			logger.Error("Error searching for existing rules: %v", err)
			continue
		}

		for _, match := range matches {
			// Skip backing up our own rule file
			if strings.Contains(match, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", cardVendorID, cardProductID)) {
				continue
			}

			// Create backup with timestamp
			backupFile := match + ".bak." + time.Now().Format("20060102150405")
			logger.Info("Backing up existing rule file %s to %s", match, backupFile)

			content, err := os.ReadFile(match)
			if err != nil {
				logger.Error("Failed to read existing rule file %s: %v", match, err)
				continue
			}

			err = os.WriteFile(backupFile, content, 0644)
			if err != nil {
				logger.Error("Failed to write backup file %s: %v", backupFile, err)
				continue
			}

			// Don't delete the original - just leave it as a backup
		}
	}

	return nil
}

// verifyUdevRuleInstallation checks if the rule is properly installed
func verifyUdevRuleInstallation(card USBSoundCard, customName string, executor *CommandExecutor, logger *Logger) bool {
	// Check if udev rules were reloaded successfully
	output, err := executor.ExecuteCommand("udevadm", "info", "--path", fmt.Sprintf("/sys/class/sound/card%s", card.CardNumber))
	if err != nil {
		logger.Error("Failed to verify udev rule installation: %v", err)
		return false
	}

	// Look for the custom name in the output
	if strings.Contains(output, fmt.Sprintf("ID_SOUND_ID=%s", customName)) {
		logger.Info("Verified successful udev rule installation!")
		return true
	}

	// If not found, try to trigger the rule specifically for this device
	logger.Info("Rule verification failed. Trying to trigger rules specifically for this device...")
	
	_, err = executor.ExecuteCommand("udevadm", "trigger", "--action=add", 
		"--property-match=SUBSYSTEM=sound", 
		fmt.Sprintf("--property-match=ID_VENDOR_ID=%s", card.VendorID),
		fmt.Sprintf("--property-match=ID_MODEL_ID=%s", card.ProductID))
	
	if err != nil {
		logger.Error("Failed to trigger specific udev rules: %v", err)
		return false
	}

	// Give it a moment to apply
	time.Sleep(2 * time.Second)
	
	return true
}

// Write a test udev rule to verify udev is working properly
func testUdevSystem(executor *CommandExecutor, logger *Logger) bool {
	logger.Info("Testing if udev rule system is working properly...")
	
	// Create a small test rule
	testRuleFile := "/etc/udev/rules.d/99-test-usb-soundcard-mapper.rules"
	testRuleContent := "# Test rule to check if udev is functioning properly\n"
	
	// Write test rule
	err := os.WriteFile(testRuleFile, []byte(testRuleContent), 0644)
	if err != nil {
		logger.Error("Failed to write test udev rule: %v", err)
		return false
	}
	
	// Try to reload udev rules
	_, err = executor.ExecuteCommand("udevadm", "control", "--reload-rules")
	if err != nil {
		logger.Error("Failed to reload udev rules during test: %v", err)
		os.Remove(testRuleFile) // Clean up
		return false
	}
	
	// Clean up test rule
	os.Remove(testRuleFile)
	
	logger.Info("Udev system test passed")
	return true
}

// checkAndFixPermissions ensures the udev rules directory has the correct permissions
func checkAndFixPermissions(config Config, logger *Logger) error {
	// Check if the rules directory exists and has correct permissions
	info, err := os.Stat(config.UdevRulesPath)
	if err != nil {
		if os.IsNotExist(err) {
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
		logger.Info("Fixing permissions on %s", config.UdevRulesPath)
		err = os.Chmod(config.UdevRulesPath, 0755)
		if err != nil {
			return fmt.Errorf("failed to set permissions on udev rules directory: %w", err)
		}
	}
	
	return nil
}

// main function
func main() {
	// Parse command line flags
	config := Config{}
	
	flag.StringVar(&config.UdevRulesPath, "rules-path", "/etc/udev/rules.d", "Path to udev rules directory")
	flag.BoolVar(&config.ListOnly, "list", false, "List USB sound cards and exit")
	flag.BoolVar(&config.NonInteractive, "non-interactive", false, "Non-interactive mode")
	flag.StringVar(&config.DeviceName, "name", "", "Custom name for the device (non-interactive mode)")
	flag.StringVar(&config.VendorID, "vendor-id", "", "Vendor ID (non-interactive mode)")
	flag.StringVar(&config.ProductID, "product-id", "", "Product ID (non-interactive mode)")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&config.SkipReload, "skip-reload", false, "Skip reloading udev rules after creating them")
	
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
	}
	
	flag.Parse()
	
	// Configure logging
	logger := NewLogger(config.Debug)
	logger.Info("Starting %s v%s", AppName, AppVersion)
	
	// Setup signal handling for graceful shutdown
	setupSignalHandling(logger)
	
	// Create command executor
	executor := NewCommandExecutor(logger)
	
	// Check if required commands are available
	if err := CheckCommands(executor); err != nil {
		logger.Error("Command check failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Check and fix permissions on udev rules directory
	if err := checkAndFixPermissions(config, logger); err != nil {
		logger.Error("Permission check failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Test if udev system is working properly
	if !testUdevSystem(executor, logger) {
		logger.Error("Udev system test failed - proceeding anyway but results may be unreliable")
		fmt.Fprintf(os.Stderr, "Warning: Udev system test failed - rules may not apply correctly\n")
	}
	
	// List all USB sound cards
	cards, err := GetUSBSoundCards(executor)
	if err != nil {
		logger.Error("Failed to get USB sound cards: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// If list-only mode, just display the cards and exit
	if config.ListOnly {
		fmt.Println("USB Sound Cards:")
		fmt.Println("---------------")
		if len(cards) == 0 {
			fmt.Println("No USB sound cards found.")
			return
		}
		
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
		return
	}
	
	// Check privileges for creating udev rules
	elevated, err := checkElevatedPrivileges()
	if err != nil {
		logger.Error("Failed to check privileges: %v", err)
		fmt.Fprintf(os.Stderr, "Error checking privileges: %v\n", err)
		os.Exit(1)
	}
	
	if !elevated {
		logger.Error("Insufficient privileges")
		fmt.Fprintf(os.Stderr, "This application requires root privileges to create udev rules.\nPlease run with sudo.\n")
		os.Exit(1)
	}
	
	// Handle non-interactive mode
	if config.NonInteractive {
		if config.VendorID == "" || config.ProductID == "" {
			logger.Error("Missing required parameters for non-interactive mode")
			fmt.Fprintf(os.Stderr, "In non-interactive mode, --vendor-id and --product-id are required\n")
			os.Exit(1)
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
			logger.Error("No matching USB sound card found")
			fmt.Fprintf(os.Stderr, "No USB sound card found with VID:PID %s:%s\n", config.VendorID, config.ProductID)
			os.Exit(1)
		}
		
		// If a custom name was specified, use it
		customName := selectedCard.FriendlyName
		if config.DeviceName != "" {
			customName = cleanupName(config.DeviceName)
		}
		
		// Backup any existing rules for this device
		if err := BackupExistingUdevRules(selectedCard.VendorID, selectedCard.ProductID, config, logger); err != nil {
			logger.Error("Warning: Failed to backup existing rules: %v", err)
			// Continue anyway - this is not fatal
		}
		
		// Create udev rule
		if err := createUdevRule(selectedCard, customName, config, logger); err != nil {
			logger.Error("Failed to create udev rule: %v", err)
			fmt.Fprintf(os.Stderr, "Error creating udev rule: %v\n", err)
			os.Exit(1)
		}
		
		// Reload udev rules
		if !config.SkipReload {
			if err := reloadUdevRules(executor); err != nil {
				logger.Error("Failed to reload udev rules: %v", err)
				fmt.Fprintf(os.Stderr, "Error reloading udev rules: %v\n", err)
				os.Exit(1)
			}
			
			// Verify the rule installation
			verifyUdevRuleInstallation(selectedCard, customName, executor, logger)
		}
		
		fmt.Printf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n",
			selectedCard.Vendor, selectedCard.Product, selectedCard.VendorID, 
			selectedCard.ProductID, customName)
			
		fmt.Println("\nImportant: For the changes to take full effect, please:")
		fmt.Println("1. Disconnect and reconnect the USB sound device, or")
		fmt.Println("2. Reboot your system")
		
		// This is critical for reliable rule application - tell the user to run this specific command
		fmt.Println("\nFor immediate application of rules without rebooting, run:")
		fmt.Printf("sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound\n")
		
		return
	}
	
	// Interactive mode - run the terminal UI
	if len(cards) == 0 {
		logger.Error("No USB sound cards found")
		fmt.Fprintf(os.Stderr, "No USB sound cards found.\n")
		os.Exit(1)
	}
	
	// Backup existing rules for found cards
	for _, card := range cards {
		if err := BackupExistingUdevRules(card.VendorID, card.ProductID, config, logger); err != nil {
			logger.Error("Warning: Failed to backup existing rules for card %s: %v", card.CardNumber, err)
			// Continue anyway - this is not fatal
		}
	}
	
	// Run the UI and get the result
	result, err := runUI(cards, config, executor, logger)
	if err != nil {
		logger.Error("UI error: %v", err)
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
