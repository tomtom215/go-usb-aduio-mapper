package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
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
}

// CommandExecutor wraps command execution with proper error handling
type CommandExecutor struct {
	// DefaultTimeout is the default timeout for command execution
	DefaultTimeout time.Duration
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{
		DefaultTimeout: 5 * time.Second,
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
				log.Printf("Warning: Failed to get details for card %s: %v", cardNumber, err)
				continue
			}
			
			cards = append(cards, card)
		}
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
func createUdevRule(card USBSoundCard, config Config) error {
	// Verify we have the necessary information
	if card.VendorID == "" || card.ProductID == "" {
		return fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}
	
	// Create rule content
	var ruleContent string
	
	// Add header
	ruleContent += "# USB sound card persistent mapping created by usb-soundcard-mapper\n"
	ruleContent += "# Device: " + card.Vendor + " " + card.Product + "\n"
	
	// Create the rule
	if card.Serial != "" {
		// If we have a serial number, use it for more reliable mapping
		ruleContent += fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTRS{serial}=="%s", ATTR{id}="%s"\n`,
			card.VendorID, card.ProductID, card.Serial, card.FriendlyName)
	} else if card.PhysicalPort != "" {
		// Use physical port for devices without serial numbers
		ruleContent += fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", KERNELS=="%s*", ATTR{id}="%s"\n`,
			card.VendorID, card.ProductID, card.PhysicalPort, card.FriendlyName)
	} else {
		// Fallback to basic vendor/product ID mapping (less reliable)
		ruleContent += fmt.Sprintf(
			`SUBSYSTEM=="sound", ACTION=="add", ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", ATTR{id}="%s"\n`,
			card.VendorID, card.ProductID, card.FriendlyName)
	}
	
	// Create the rule file path
	ruleFile := filepath.Join(config.UdevRulesPath, fmt.Sprintf("89-usb-soundcard-%s-%s.rules", 
		card.VendorID, card.ProductID))
	
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(config.UdevRulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create udev rules directory: %w", err)
	}
	
	// Write the rule to a temporary file first
	tmpFile, err := ioutil.TempFile("", "udev-rule-*.rules")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up in case of failure
	
	// Write the content to the temporary file
	if err := ioutil.WriteFile(tmpFile.Name(), []byte(ruleContent), 0644); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	
	// Move the temporary file to the final location
	if err := os.Rename(tmpFile.Name(), ruleFile); err != nil {
		return fmt.Errorf("failed to move rule file to destination: %w", err)
	}
	
	// Set correct permissions
	if err := os.Chmod(ruleFile, 0644); err != nil {
		return fmt.Errorf("failed to set rule file permissions: %w", err)
	}
	
	return nil
}

// reloadUdevRules triggers a reload of udev rules
func reloadUdevRules(executor *CommandExecutor) error {
	// Reload udev rules
	if _, err := executor.ExecuteCommand("udevadm", "control", "--reload-rules"); err != nil {
		return fmt.Errorf("failed to reload udev rules: %w", err)
	}
	
	// Trigger the rules for all sound devices
	if _, err := executor.ExecuteCommand("udevadm", "trigger", "--action=change", "--subsystem-match=sound"); err != nil {
		return fmt.Errorf("failed to trigger udev rules: %w", err)
	}
	
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

// cardSelectorModel holds the state for the device selection UI
type cardSelectorModel struct {
	list list.Model
	err  error
}

// Init initializes the model and returns initial command
func (m cardSelectorModel) Init() tea.Cmd {
	// No initial commands needed for this model
	return nil
}

// Initial model for the card selector
func initialCardSelectorModel(cards []USBSoundCard) cardSelectorModel {
	items := make([]list.Item, len(cards))
	for i, card := range cards {
		items[i] = listItem{card: card}
	}
	
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select USB Sound Card to Map"
	
	return cardSelectorModel{
		list: l,
	}
}

// Update the model based on messages
func (m cardSelectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
		
		if msg.String() == "enter" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}
	
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// Render the UI
func (m cardSelectorModel) View() string {
	return docStyle.Render(m.list.View())
}

// Style for the UI
var docStyle = lipgloss.NewStyle().Margin(1, 2)

// runCardSelector runs the terminal UI for card selection
func runCardSelector(cards []USBSoundCard) (USBSoundCard, error) {
	if len(cards) == 0 {
		return USBSoundCard{}, fmt.Errorf("no USB sound cards found")
	}
	
	p := tea.NewProgram(initialCardSelectorModel(cards))
	m, err := p.Run()
	if err != nil {
		return USBSoundCard{}, fmt.Errorf("error running UI: %w", err)
	}
	
	model, ok := m.(cardSelectorModel)
	if !ok {
		return USBSoundCard{}, fmt.Errorf("unexpected model type returned from UI")
	}
	
	// Get the selected card
	selectedItem, ok := model.list.SelectedItem().(listItem)
	if !ok {
		return USBSoundCard{}, fmt.Errorf("no card selected")
	}
	
	return selectedItem.card, nil
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
	
	flag.Parse()
	
	// Create command executor
	executor := NewCommandExecutor()
	
	// Check if required commands are available
	if err := CheckCommands(executor); err != nil {
		log.Fatalf("Error: %v", err)
	}
	
	// List all USB sound cards
	cards, err := GetUSBSoundCards(executor)
	if err != nil {
		log.Fatalf("Error: %v", err)
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
	
	// Check privileges
	elevated, err := checkElevatedPrivileges()
	if err != nil {
		log.Fatalf("Error checking privileges: %v", err)
	}
	
	if !elevated {
		log.Fatalf("This application requires root privileges to create udev rules.\nPlease run with sudo.")
	}
	
	// Handle non-interactive mode
	if config.NonInteractive {
		if config.VendorID == "" || config.ProductID == "" {
			log.Fatalf("In non-interactive mode, --vendor-id and --product-id are required")
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
			log.Fatalf("No USB sound card found with VID:PID %s:%s", config.VendorID, config.ProductID)
		}
		
		// If a custom name was specified, use it
		if config.DeviceName != "" {
			selectedCard.FriendlyName = cleanupName(config.DeviceName)
		}
		
		// Create udev rule
		if err := createUdevRule(selectedCard, config); err != nil {
			log.Fatalf("Error creating udev rule: %v", err)
		}
		
		// Reload udev rules
		if err := reloadUdevRules(executor); err != nil {
			log.Fatalf("Error reloading udev rules: %v", err)
		}
		
		fmt.Printf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n",
			selectedCard.Vendor, selectedCard.Product, selectedCard.VendorID, 
			selectedCard.ProductID, selectedCard.FriendlyName)
		return
	}
	
	// Interactive mode - run the terminal UI
	if len(cards) == 0 {
		log.Fatalf("No USB sound cards found.")
	}
	
	// Select a card
	selectedCard, err := runCardSelector(cards)
	if err != nil {
		log.Fatalf("Error selecting card: %v", err)
	}
	
	// Create udev rule
	if err := createUdevRule(selectedCard, config); err != nil {
		log.Fatalf("Error creating udev rule: %v", err)
	}
	
	// Reload udev rules
	if err := reloadUdevRules(executor); err != nil {
		log.Fatalf("Error reloading udev rules: %v", err)
	}
	
	fmt.Printf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n",
		selectedCard.Vendor, selectedCard.Product, selectedCard.VendorID, 
		selectedCard.ProductID, selectedCard.FriendlyName)
	
	fmt.Println("\nThe sound card will use this name consistently across reboots and reconnections.")
	fmt.Println("You can see this device in 'aplay -l' output as card with ID '" + selectedCard.FriendlyName + "'")
	fmt.Println("once you disconnect and reconnect the device.")
}
