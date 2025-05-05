// USB Soundcard Mapper
// A robust utility for creating persistent udev mappings for USB audio devices
// Version: 2.0.2 (production hardening release)

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
	"github.com/gofrs/flock" // Added for file locking
)

// Application constants
const (
	AppName         = "usb-soundcard-mapper"
	AppVersion      = "2.0.2"
	ExecTimeout     = 5 * time.Second
	udevRulesDir    = "/etc/udev/rules.d"
	maxBackupCount  = 10  // Maximum number of backups to keep per device
	maxQueueSize    = 100 // Maximum size of operation queues
	maxFileSize     = 1024 * 1024 // 1MB maximum file size for safety
	gracefulTimeout = 5 * time.Second // Timeout for graceful shutdown
)

// Pre-compiled regular expressions for improved performance and safety
var (
	vendorIDRegex  = regexp.MustCompile(`^[0-9a-fA-F]{4}$`)
	productIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}$`)
	serialRegex    = regexp.MustCompile(`^[^<>|&;()$\r\n\t\0]+$`)
	fileNameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	pathSafeRegex  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/]+$`)
)

// ConfigurableTimeouts holds configurable timeout values
type ConfigurableTimeouts struct {
	CommandExecution  time.Duration
	RuleReloadWait    time.Duration
	TriggerActionWait time.Duration
	RetryInterval     time.Duration
	GracefulShutdown  time.Duration
	LockAcquisition   time.Duration
}

// DefaultTimeouts provides default values for timeouts
var DefaultTimeouts = ConfigurableTimeouts{
	CommandExecution:  5 * time.Second,
	RuleReloadWait:    1 * time.Second,
	TriggerActionWait: 2 * time.Second,
	RetryInterval:     500 * time.Millisecond,
	GracefulShutdown:  5 * time.Second,
	LockAcquisition:   2 * time.Second,
}

// Sentinel errors for specific failure cases
var (
	ErrNoUSBSoundCards      = errors.New("no USB sound cards found")
	ErrInsufficientPrivs    = errors.New("insufficient privileges")
	ErrUdevSystemFailure    = errors.New("udev system test failed")
	ErrCommandNotFound      = errors.New("required command not found")
	ErrOperationCancelled   = errors.New("operation cancelled by user")
	ErrDeviceNameEmpty      = errors.New("device name cannot be empty")
	ErrInvalidDeviceParams  = errors.New("invalid device parameters")
	ErrDeviceDisconnected   = errors.New("device disconnected during operation")
	ErrFileLockFailed       = errors.New("failed to acquire file lock")
	ErrRuleVerificationFail = errors.New("rule verification failed")
	ErrVirtualDevice        = errors.New("virtual audio device detected")
	ErrResourceExhausted    = errors.New("resource limits exhausted")
	ErrInvalidPath          = errors.New("invalid path provided")
	ErrTransactionFailed    = errors.New("transaction failed, rollback completed")
	ErrUnsafeArgument       = errors.New("unsafe command argument detected")
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
	Timeouts        ConfigurableTimeouts
	MaxRetries      int
	ForceOverwrite  bool
	IgnoreVirtual   bool
	MaxBackupCount  int
	ResourceLimits  ResourceLimits
}

// ResourceLimits defines limits to prevent resource exhaustion
type ResourceLimits struct {
	MaxConcurrentOps   int
	MaxQueueSize       int
	MaxFileSize        int64
	MaxBackupsPerDevice int
}

// ConcurrencyOptions configures the concurrency behavior
type ConcurrencyOptions struct {
	MaxWorkers     int
	OperationQueue int
}

// DeviceStatus represents current device status
type DeviceStatus int

const (
	DeviceStatusConnected DeviceStatus = iota
	DeviceStatusDisconnected
	DeviceStatusUnknown
)

// USBSoundCard represents a USB sound card device with all necessary attributes
type USBSoundCard struct {
	CardNumber    string
	DevicePath    string
	Vendor        string
	Product       string
	VendorID      string
	ProductID     string
	Serial        string
	BusID         string
	DeviceID      string
	PhysicalPort  string
	FriendlyName  string
	Detected      time.Time
	Status        DeviceStatus
	IsVirtual     bool
	ValidationErr error
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
	if c.IsVirtual {
		attrs = append(attrs, "Type: Virtual")
	}
	return strings.Join(attrs, ", ")
}

// Validate validates the sound card attributes
func (c *USBSoundCard) Validate() error {
	if c.CardNumber == "" {
		return errors.New("missing card number")
	}
	
	if c.VendorID == "" {
		return errors.New("missing vendor ID")
	}
	
	if c.ProductID == "" {
		return errors.New("missing product ID")
	}
	
	// Validate VendorID and ProductID format (should be 4 hex digits)
	if !vendorIDRegex.MatchString(c.VendorID) {
		return fmt.Errorf("invalid vendor ID format: %s", c.VendorID)
	}
	
	if !productIDRegex.MatchString(c.ProductID) {
		return fmt.Errorf("invalid product ID format: %s", c.ProductID)
	}
	
	// Validate Serial if present (should not contain control characters or shell special chars)
	if c.Serial != "" {
		if !serialRegex.MatchString(c.Serial) {
			return fmt.Errorf("invalid serial number format: %s", c.Serial)
		}
	}
	
	return nil
}

// ResourceTracker tracks and manages resources to ensure proper cleanup
type ResourceTracker struct {
	resources map[string]func() error
	mu        sync.Mutex
	wg        sync.WaitGroup
}

// NewResourceTracker creates a new resource tracker
func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{
		resources: make(map[string]func() error),
	}
}

// AddResource adds a resource with cleanup function
func (rt *ResourceTracker) AddResource(id string, cleanup func() error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	rt.resources[id] = cleanup
}

// ReleaseResource releases a specific resource
func (rt *ResourceTracker) ReleaseResource(id string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	if cleanup, exists := rt.resources[id]; exists {
		err := cleanup()
		delete(rt.resources, id)
		return err
	}
	
	return nil
}

// CleanupAll releases all tracked resources
func (rt *ResourceTracker) CleanupAll() []error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	var errors []error
	for id, cleanup := range rt.resources {
		if err := cleanup(); err != nil {
			errors = append(errors, fmt.Errorf("failed to clean up resource %s: %w", id, err))
		}
		delete(rt.resources, id)
	}
	
	return errors
}

// WaitForCompletion waits for all background tasks to complete
func (rt *ResourceTracker) WaitForCompletion(timeout time.Duration) error {
	done := make(chan struct{})
	
	go func() {
		rt.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for resource cleanup")
	}
}

// WithCommandExecutor runs a system command safely with retries
type CommandExecutor struct {
	DefaultTimeout time.Duration
	MaxRetries     int
	RetryInterval  time.Duration
	ResourceTracker *ResourceTracker
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor(config Config, resourceTracker *ResourceTracker) *CommandExecutor {
	return &CommandExecutor{
		DefaultTimeout:  config.Timeouts.CommandExecution,
		MaxRetries:      config.MaxRetries,
		RetryInterval:   config.Timeouts.RetryInterval,
		ResourceTracker: resourceTracker,
	}
}

// ExecuteCommand executes a command with the default timeout and retries
func (ce *CommandExecutor) ExecuteCommand(ctx context.Context, command string, args ...string) (string, error) {
	// Validate command and arguments for safety
	if err := validateCommandArgs(command, args...); err != nil {
		return "", err
	}
	
	return ce.ExecuteCommandWithTimeoutAndRetry(ctx, ce.DefaultTimeout, ce.MaxRetries, command, args...)
}

// validateCommandArgs checks command and arguments for safety
func validateCommandArgs(command string, args ...string) error {
	// Check command
	if !fileNameRegex.MatchString(command) {
		return fmt.Errorf("unsafe command name: %s: %w", command, ErrUnsafeArgument)
	}
	
	// Check each argument
	for i, arg := range args {
		// For path arguments, use a more restrictive check
		if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
			if !pathSafeRegex.MatchString(arg) {
				return fmt.Errorf("unsafe path argument at position %d: %s: %w", i, arg, ErrUnsafeArgument)
			}
		} else if strings.Contains(arg, "&&") || strings.Contains(arg, "||") || 
			strings.Contains(arg, ";") || strings.Contains(arg, "`") {
			return fmt.Errorf("potentially unsafe argument at position %d: %s: %w", i, arg, ErrUnsafeArgument)
		}
	}
	
	return nil
}

// ExecuteCommandWithTimeoutAndRetry executes a command with specific timeout and retries
func (ce *CommandExecutor) ExecuteCommandWithTimeoutAndRetry(
	ctx context.Context, 
	timeout time.Duration, 
	maxRetries int,
	command string, 
	args ...string,
) (string, error) {
	var (
		output string
		err    error
		retryCount int
	)
	
	// Generate a unique ID for tracking this command execution
	cmdID := fmt.Sprintf("cmd_%s_%d", command, time.Now().UnixNano())
	
	for retryCount = 0; retryCount <= maxRetries; retryCount++ {
		// Check if context is already canceled
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		
		// Execute the command
		output, err = ce.executeCommandOnce(ctx, timeout, cmdID, command, args...)
		
		// If successful or not retryable error, return immediately
		if err == nil || 
		   errors.Is(err, ErrCommandNotFound) || 
		   errors.Is(err, context.DeadlineExceeded) ||
		   errors.Is(err, ErrUnsafeArgument) {
			return output, err
		}
		
		// Log retry attempt
		if retryCount < maxRetries {
			slog.Debug("Command failed, retrying", 
				"command", command, 
				"args", args, 
				"error", err, 
				"retry", retryCount+1)
			
			// Wait before retrying
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(ce.RetryInterval):
				// Continue to retry
			}
		}
	}
	
	// If we got here, all retries failed
	return output, fmt.Errorf("command failed after %d retries: %w", retryCount-1, err)
}

// executeCommandOnce executes a command once with timeout
func (ce *CommandExecutor) executeCommandOnce(
	ctx context.Context, 
	timeout time.Duration, 
	cmdID string,
	command string, 
	args ...string,
) (string, error) {
	// Check if context is already canceled
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// Create a context with timeout
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	
	// Register cleanup in ResourceTracker
	ce.ResourceTracker.AddResource(cmdID, func() error {
		cancel()
		return nil
	})
	
	// Find the full path to the command to avoid shell injection
	cmdPath, err := exec.LookPath(command)
	if err != nil {
		// Clean up the context
		ce.ResourceTracker.ReleaseResource(cmdID)
		return "", fmt.Errorf("command not found %s: %w", command, ErrCommandNotFound)
	}

	slog.Debug("Executing command", "command", command, "args", args)
	cmd := exec.CommandContext(execCtx, cmdPath, args...)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Register process cleanup
	processID := fmt.Sprintf("process_%s_%d", command, time.Now().UnixNano())
	ce.ResourceTracker.AddResource(processID, func() error {
		// If the process is still running, terminate it
		if cmd.Process != nil {
			err := cmd.Process.Kill()
			if err != nil && !strings.Contains(err.Error(), "process already finished") {
				return fmt.Errorf("failed to kill process: %w", err)
			}
		}
		return nil
	})

	err = cmd.Run()
	
	// Clean up resources
	ce.ResourceTracker.ReleaseResource(cmdID)
	ce.ResourceTracker.ReleaseResource(processID)
	
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

// Transaction represents an atomic operation with rollback capability
type Transaction struct {
	operations []func() error
	rollbacks  []func() error
	committed  bool
	mu         sync.Mutex
}

// NewTransaction creates a new transaction
func NewTransaction() *Transaction {
	return &Transaction{
		operations: make([]func() error, 0),
		rollbacks:  make([]func() error, 0),
		committed:  false,
	}
}

// AddOperation adds an operation and its rollback function to the transaction
func (t *Transaction) AddOperation(operation, rollback func() error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	t.operations = append(t.operations, operation)
	t.rollbacks = append(t.rollbacks, rollback)
}

// Execute executes all operations in the transaction
func (t *Transaction) Execute() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	// Execute each operation
	for i, operation := range t.operations {
		if err := operation(); err != nil {
			// If an operation fails, roll back all previous operations
			slog.Error("Transaction operation failed, rolling back", "error", err, "operation", i)
			
			// Execute rollbacks in reverse order
			for j := i - 1; j >= 0; j-- {
				if rollbackErr := t.rollbacks[j](); rollbackErr != nil {
					slog.Error("Rollback failed", "error", rollbackErr, "operation", j)
				}
			}
			
			return fmt.Errorf("transaction failed at operation %d: %w", i, err)
		}
	}
	
	t.committed = true
	return nil
}

// Commit marks the transaction as committed
func (t *Transaction) Commit() {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	t.committed = true
}

// Rollback executes all rollback functions in reverse order
func (t *Transaction) Rollback() []error {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if t.committed {
		return nil
	}
	
	var errors []error
	
	// Execute rollbacks in reverse order
	for i := len(t.rollbacks) - 1; i >= 0; i-- {
		if err := t.rollbacks[i](); err != nil {
			errors = append(errors, fmt.Errorf("rollback %d failed: %w", i, err))
		}
	}
	
	return errors
}

// SafeFileAccess ensures thread-safe file operations
type SafeFileAccess struct {
	lockMap map[string]*flock.Flock
	mu      sync.Mutex
	tracker *ResourceTracker
}

// NewSafeFileAccess creates a new file access manager
func NewSafeFileAccess(tracker *ResourceTracker) *SafeFileAccess {
	return &SafeFileAccess{
		lockMap: make(map[string]*flock.Flock),
		tracker: tracker,
	}
}

// LockFile acquires a lock on a file with timeout
func (sfa *SafeFileAccess) LockFile(filePath string, timeout time.Duration) (*flock.Flock, error) {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(filePath) {
		return nil, fmt.Errorf("unsafe file path: %s: %w", filePath, ErrInvalidPath)
	}
	
	sfa.mu.Lock()
	defer sfa.mu.Unlock()
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	lock, exists := sfa.lockMap[absPath]
	if !exists {
		lock = flock.New(absPath)
		sfa.lockMap[absPath] = lock
	}
	
	// Try to acquire the lock with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	// Create resource ID for tracking
	lockID := fmt.Sprintf("filelock_%s", absPath)
	
	// Register with resource tracker
	sfa.tracker.AddResource(lockID, func() error {
		// Release the lock if we have it
		if lock.Locked() {
			return lock.Unlock()
		}
		return nil
	})
	
	success, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		sfa.tracker.ReleaseResource(lockID)
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	
	if !success {
		sfa.tracker.ReleaseResource(lockID)
		return nil, ErrFileLockFailed
	}
	
	return lock, nil
}

// UnlockFile releases a lock on a file
func (sfa *SafeFileAccess) UnlockFile(filePath string) error {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(filePath) {
		return fmt.Errorf("unsafe file path: %s: %w", filePath, ErrInvalidPath)
	}
	
	sfa.mu.Lock()
	defer sfa.mu.Unlock()
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	lock, exists := sfa.lockMap[absPath]
	if !exists {
		return nil // already unlocked
	}
	
	err = lock.Unlock()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	
	delete(sfa.lockMap, absPath)
	
	// Release from resource tracker
	lockID := fmt.Sprintf("filelock_%s", absPath)
	sfa.tracker.ReleaseResource(lockID)
	
	return nil
}

// CleanupAllLocks releases all locks
func (sfa *SafeFileAccess) CleanupAllLocks() {
	sfa.mu.Lock()
	defer sfa.mu.Unlock()
	
	for path, lock := range sfa.lockMap {
		if lock.Locked() {
			err := lock.Unlock()
			if err != nil {
				slog.Error("Failed to release lock during cleanup", 
					"path", path, "error", err)
			}
			
			// Release from resource tracker
			lockID := fmt.Sprintf("filelock_%s", path)
			sfa.tracker.ReleaseResource(lockID)
		}
	}
	
	// Clear the map
	sfa.lockMap = make(map[string]*flock.Flock)
}

// DeviceRegistry manages a thread-safe collection of sound cards
type DeviceRegistry struct {
	devices      map[string]USBSoundCard
	deviceKeys   map[USBSoundCard]string // Reverse mapping for consistent key generation
	mu           sync.RWMutex
}

// NewDeviceRegistry creates a new device registry
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		devices:    make(map[string]USBSoundCard),
		deviceKeys: make(map[USBSoundCard]string),
	}
}

// AddDevice adds a device to the registry
func (dr *DeviceRegistry) AddDevice(card USBSoundCard) {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	
	key := dr.generateDeviceKey(card)
	card.Detected = time.Now()
	dr.devices[key] = card
	dr.deviceKeys[card] = key
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

// GetDevice retrieves a specific device by card
func (dr *DeviceRegistry) GetDevice(card USBSoundCard) (USBSoundCard, bool) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	
	key, exists := dr.deviceKeys[card]
	if !exists {
		// Fall back to generated key if not found in the cache
		key = dr.generateDeviceKey(card)
	}
	
	device, exists := dr.devices[key]
	return device, exists
}

// UpdateDeviceStatus updates the status of a device
func (dr *DeviceRegistry) UpdateDeviceStatus(card USBSoundCard, status DeviceStatus) {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	
	key, exists := dr.deviceKeys[card]
	if !exists {
		// Fall back to generated key if not found in the cache
		key = dr.generateDeviceKey(card)
	}
	
	if device, exists := dr.devices[key]; exists {
		device.Status = status
		dr.devices[key] = device
	}
}

// generateDeviceKey creates a unique key for a device
func (dr *DeviceRegistry) generateDeviceKey(card USBSoundCard) string {
	if card.Serial != "" && !strings.Contains(card.Serial, ":") {
		return fmt.Sprintf("%s:%s:%s", card.VendorID, card.ProductID, card.Serial)
	} else if card.PhysicalPort != "" {
		return fmt.Sprintf("%s:%s:%s", card.VendorID, card.ProductID, card.PhysicalPort)
	}
	
	// Add card number as fallback to reduce collision risk
	return fmt.Sprintf("%s:%s:%s", card.VendorID, card.ProductID, card.CardNumber)
}

// GetUSBSoundCards detects all USB sound cards in the system
func GetUSBSoundCards(ctx context.Context, executor *CommandExecutor, config Config) ([]USBSoundCard, error) {
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
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning aplay output: %w", err)
	}
	
	// Process each card sequentially to avoid race conditions
	for _, cardNum := range cardNumbers {
		// Check if context is canceled
		if ctx.Err() != nil {
			return cards, ctx.Err()
		}
		
		// Get more details about this card
		card, err := getCardDetails(ctx, executor, cardNum, config)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get details for card %s: %w", cardNum, err))
			continue
		}
		
		// Skip virtual devices if configured
		if card.IsVirtual && config.IgnoreVirtual {
			slog.Info("Skipping virtual device", "card", card.String())
			continue
		}
		
		// Validate the card
		if err := card.Validate(); err != nil {
			card.ValidationErr = err
			slog.Warn("Card validation failed", "card", card.CardNumber, "error", err)
		}
		
		cards = append(cards, card)
		registry.AddDevice(card)
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
func getCardDetails(ctx context.Context, executor *CommandExecutor, cardNumber string, config Config) (USBSoundCard, error) {
	card := USBSoundCard{
		CardNumber: cardNumber,
		DevicePath: fmt.Sprintf("/dev/snd/card%s", cardNumber),
		Status:     DeviceStatusConnected,
	}
	
	// Get card path in sysfs
	sysfsPath := fmt.Sprintf("/sys/class/sound/card%s", cardNumber)
	
	// Check if the card still exists (might have been disconnected)
	if ok, err := pathExists(sysfsPath); !ok {
		if err != nil {
			return card, fmt.Errorf("error checking card path: %w", err)
		}
		return card, ErrDeviceDisconnected
	}
	
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
	driverRegexp := regexp.MustCompile(`DRIVERS=="([^"]*)"`)
	
	// Check if it's a virtual device
	isVirtualDevice := false
	
	for scanner.Scan() {
		line := scanner.Text()
		
		if matches := vendorRegexp.FindStringSubmatch(line); matches != nil && card.VendorID == "" {
			card.VendorID = matches[1]
		}
		
		if matches := productRegexp.FindStringSubmatch(line); matches != nil && card.ProductID == "" {
			card.ProductID = matches[1]
		}
		
		if matches := serialRegexp.FindStringSubmatch(line); matches != nil && card.Serial == "" {
			card.Serial = sanitizeSerial(matches[1])
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
		
		// Check for virtual sound device drivers
		if matches := driverRegexp.FindStringSubmatch(line); matches != nil {
			driverName := matches[1]
			if isVirtualDriver(driverName) {
				isVirtualDevice = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return card, fmt.Errorf("error scanning udevadm output: %w", err)
	}
	
	// Set the virtual device flag
	card.IsVirtual = isVirtualDevice
	
	// Handle virtual devices
	if card.IsVirtual && !config.IgnoreVirtual {
		slog.Warn("Virtual audio device detected", "card", cardNumber)
	}
	
	// Validate required fields
	if card.VendorID == "" || card.ProductID == "" {
		return card, fmt.Errorf("insufficient device information for card %s", card.CardNumber)
	}
	
	// Get vendor/product names from lsusb if we have vendor and product IDs
	if card.VendorID != "" && card.ProductID != "" && ctx.Err() == nil {
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

// sanitizeSerial sanitizes a serial number to prevent security issues
func sanitizeSerial(serial string) string {
	// Remove any control characters or shell special chars
	return serialRegex.ReplaceAllString(serial, "_")
}

// isVirtualDriver checks if a driver name indicates a virtual audio device
func isVirtualDriver(driver string) bool {
	virtualDrivers := []string{
		"snd_dummy", "snd_aloop", "snd_virmidi", "snd_pcm_oss",
		"snd_mixer_oss", "snd_seq", "snd_seq_dummy", "snd_seq_oss",
	}
	
	for _, vd := range virtualDrivers {
		if driver == vd {
			return true
		}
	}
	
	return false
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
	// Check if context is canceled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
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
	
	if card.IsVirtual {
		ruleBuilder.WriteString("\n# Note: This appears to be a virtual audio device")
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

// installUdevRule writes the rule to the filesystem using transactions
func installUdevRule(ctx context.Context, rule *UdevRule, config Config, fileAccess *SafeFileAccess) error {
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
	
	// Create a transaction for the entire installation process
	transaction := NewTransaction()
	
	// Add directory creation to transaction
	transaction.AddOperation(
		// Create directory operation
		func() error {
			return os.MkdirAll(config.UdevRulesPath, 0755)
		},
		// Rollback is not needed - directory creation is idempotent
		func() error { return nil },
	)
	
	// Check if file exists and backup is needed
	exists, err := fileExists(rule.Path)
	if err != nil {
		return fmt.Errorf("error checking if rule file exists: %w", err)
	}
	
	var backupPath string
	if exists && config.BackupRules {
		backupPath = rule.Path + ".bak." + time.Now().Format("20060102150405")
		
		// Add backup operation to transaction
		transaction.AddOperation(
			// Backup operation
			func() error {
				content, err := os.ReadFile(rule.Path)
				if err != nil {
					return fmt.Errorf("failed to read existing rule file: %w", err)
				}
				
				// Use atomic write for backup
				return atomicWriteFile(backupPath, content, 0644, fileAccess, config.Timeouts.LockAcquisition)
			},
			// Rollback - remove the backup if needed
			func() error {
				if backupPath != "" {
					if exists, _ := fileExists(backupPath); exists {
						return os.Remove(backupPath)
					}
				}
				return nil
			},
		)
	}
	
	// Only write if content is different or force overwrite is enabled
	shouldWrite := true
	if exists && !config.ForceOverwrite {
		content, err := os.ReadFile(rule.Path)
		if err == nil && string(content) == rule.Content {
			shouldWrite = false
			slog.Info("Rule file already exists with identical content, skipping write", "path", rule.Path)
		}
	}
	
	// Add rule writing to transaction
	if shouldWrite {
		transaction.AddOperation(
			// Write rule operation
			func() error {
				// Use atomic write to avoid race conditions
				return atomicWriteFile(rule.Path, []byte(rule.Content), 0644, fileAccess, config.Timeouts.LockAcquisition)
			},
			// Rollback - restore from backup or remove if new
			func() error {
				if backupPath != "" && exists {
					// Restore from backup
					content, err := os.ReadFile(backupPath)
					if err != nil {
						return fmt.Errorf("failed to read backup for rollback: %w", err)
					}
					
					return atomicWriteFile(rule.Path, content, 0644, fileAccess, config.Timeouts.LockAcquisition)
				} else if !exists {
					// Remove the newly created file
					return os.Remove(rule.Path)
				}
				return nil
			},
		)
	}
	
	// Add modprobe configuration creation to transaction
	transaction.AddOperation(
		// Create modprobe config operation
		func() error {
			return createModprobeConfig(rule.Card, config, fileAccess)
		},
		// Rollback not needed for modprobe config - it's non-critical
		func() error { return nil },
	)
	
	// Execute the transaction
	if err := transaction.Execute(); err != nil {
		slog.Error("Installation transaction failed", "error", err)
		return fmt.Errorf("installation failed: %w", ErrTransactionFailed)
	}
	
	// Commit the transaction
	transaction.Commit()
	return nil
}

// atomicWriteFile writes a file atomically using a temporary file and rename
func atomicWriteFile(filename string, data []byte, perm fs.FileMode, fileAccess *SafeFileAccess, lockTimeout time.Duration) error {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(filename) {
		return fmt.Errorf("unsafe file path: %s: %w", filename, ErrInvalidPath)
	}
	
	// Check file size limits
	if int64(len(data)) > maxFileSize {
		return fmt.Errorf("file size exceeds maximum allowed size (%d bytes): %w", 
			maxFileSize, ErrResourceExhausted)
	}
	
	dir := filepath.Dir(filename)
	
	// Acquire a lock on the target file
	_, err := fileAccess.LockFile(filename, lockTimeout)
	if err != nil {
		return fmt.Errorf("failed to acquire lock on file: %w", err)
	}
	
	// Ensure we release the lock when done - this is critical
	defer fileAccess.UnlockFile(filename)
	
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
			err := os.Remove(tempPath)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Error("Failed to remove temporary file during cleanup", 
					"path", tempPath, "error", err)
			}
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
	
	// Ensure file is synced to disk
	if err = tempFile.Sync(); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to sync temporary file: %w", err)
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
func createModprobeConfig(card USBSoundCard, config Config, fileAccess *SafeFileAccess) error {
	modprobePath := "/etc/modprobe.d"
	exists, err := directoryExists(modprobePath)
	if err != nil {
		return fmt.Errorf("error checking modprobe directory: %w", err)
	}
	
	if !exists {
		// Skip if modprobe directory doesn't exist
		return nil
	}
	
	modprobeFile := filepath.Join(modprobePath, fmt.Sprintf("99-soundcard-%s-%s.conf", 
		card.VendorID, card.ProductID))
	
	// Skip if already exists and not forcing overwrite
	exists, err = fileExists(modprobeFile)
	if err != nil {
		return fmt.Errorf("error checking modprobe file: %w", err)
	}
	
	if exists && !config.ForceOverwrite {
		return nil
	}
	
	if config.DryRun {
		slog.Info("Dry run mode - would create modprobe configuration", "path", modprobeFile)
		return nil
	}
	
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf("# Modprobe options for USB sound card %s %s\n", 
		card.Vendor, card.Product))
	contentBuilder.WriteString("options snd_usb_audio index=-2\n")
	
	// Write the modprobe file atomically
	if err := atomicWriteFile(modprobeFile, []byte(contentBuilder.String()), 0644, fileAccess, config.Timeouts.LockAcquisition); err != nil {
		return fmt.Errorf("failed to write modprobe configuration: %w", err)
	}
	
	return nil
}

// reloadUdevRules triggers a reload of udev rules with transaction support
func reloadUdevRules(ctx context.Context, executor *CommandExecutor, config Config) error {
	if config.DryRun {
		slog.Info("Dry run mode - skipping udev rules reload")
		return nil
	}
	
	// Create a transaction for rule reloading
	transaction := NewTransaction()
	
	// Add rule reload to transaction
	transaction.AddOperation(
		// Reload operation
		func() error {
			_, err := executor.ExecuteCommand(ctx, "udevadm", "control", "--reload-rules")
			if err != nil {
				return fmt.Errorf("failed to reload udev rules: %w", err)
			}
			
			// Sleep to give udev time to process the rule reloading
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(config.Timeouts.RuleReloadWait):
				// Continue
			}
			
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Add trigger with add action to transaction
	transaction.AddOperation(
		// Trigger operation
		func() error {
			_, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=add", "--subsystem-match=sound")
			if err != nil {
				return fmt.Errorf("failed to trigger udev rules with add action: %w", err)
			}
			
			// Sleep to give udev time to apply the rules
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(config.Timeouts.TriggerActionWait):
				// Continue
			}
			
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Add trigger with change action to transaction
	transaction.AddOperation(
		// Trigger operation
		func() error {
			_, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=change", "--subsystem-match=sound")
			if err != nil {
				return fmt.Errorf("failed to trigger udev rules with change action: %w", err)
			}
			
			// Sleep to give udev time to apply the rules
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(config.Timeouts.TriggerActionWait):
				// Continue
			}
			
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Execute the transaction
	if err := transaction.Execute(); err != nil {
		return err
	}
	
	return nil
}

// verifyUdevRuleInstallation checks if the rule is properly installed
func verifyUdevRuleInstallation(ctx context.Context, executor *CommandExecutor, card USBSoundCard, customName string, config Config) (bool, error) {
	// Skip verification in dry run mode
	if config.DryRun {
		slog.Info("Dry run mode - skipping rule verification")
		return true, nil
	}
	
	// Check if card still exists
	cardPath := fmt.Sprintf("/sys/class/sound/card%s", card.CardNumber)
	exists, err := pathExists(cardPath)
	if err != nil {
		return false, fmt.Errorf("error checking card path: %w", err)
	}
	
	if !exists {
		return false, ErrDeviceDisconnected
	}
	
	// Try multiple verification methods to be thorough
	var verificationMethods = []struct {
		name     string
		function func() (bool, error)
	}{
		{
			name: "udevadm info",
			function: func() (bool, error) {
				output, err := executor.ExecuteCommand(ctx, "udevadm", "info", "--path", cardPath)
				if err != nil {
					return false, fmt.Errorf("failed to get udevadm info: %w", err)
				}
				
				return strings.Contains(output, fmt.Sprintf("ID_SOUND_ID=%s", customName)), nil
			},
		},
		{
			name: "symlink check",
			function: func() (bool, error) {
				symlinkPath := fmt.Sprintf("/dev/sound/by-id/%s", customName)
				exists, err := fileExists(symlinkPath)
				if err != nil {
					return false, fmt.Errorf("error checking symlink existence: %w", err)
				}
				return exists, nil
			},
		},
		{
			name: "udevadm trigger",
			function: func() (bool, error) {
				_, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=add", 
					"--property-match=SUBSYSTEM=sound", 
					fmt.Sprintf("--property-match=ID_VENDOR_ID=%s", card.VendorID),
					fmt.Sprintf("--property-match=ID_MODEL_ID=%s", card.ProductID))
				
				if err != nil {
					return false, fmt.Errorf("failed to trigger specific udev rules: %w", err)
				}
				
				// Give it a moment to apply
				select {
				case <-ctx.Done():
					return false, ctx.Err()
				case <-time.After(config.Timeouts.TriggerActionWait):
					// Continue
				}
				
				// Check again for the symlink
				symlinkPath := fmt.Sprintf("/dev/sound/by-id/%s", customName)
				exists, err := fileExists(symlinkPath)
				if err != nil {
					return false, fmt.Errorf("error checking symlink existence: %w", err)
				}
				return exists, nil
			},
		},
		{
			name: "aplay output",
			function: func() (bool, error) {
				aplayOutput, err := executor.ExecuteCommand(ctx, "aplay", "-L")
				if err != nil {
					return false, fmt.Errorf("failed to check aplay -L output: %w", err)
				}
				return strings.Contains(aplayOutput, customName), nil
			},
		},
	}
	
	// Try each verification method
	for _, method := range verificationMethods {
		// Check if context is canceled
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		
		success, err := method.function()
		if err != nil {
			slog.Warn(fmt.Sprintf("Verification method %s failed", method.name), "error", err)
			continue
		}
		
		if success {
			slog.Info(fmt.Sprintf("Verified successful udev rule installation via %s!", method.name))
			return true, nil
		}
	}
	
	// If all verification methods failed
	return false, ErrRuleVerificationFail
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
func backupExistingUdevRules(card USBSoundCard, config Config, fileAccess *SafeFileAccess) error {
	if !config.BackupRules || config.DryRun {
		return nil
	}
	
	// Check if we've exceeded the backup limit
	backupDir := filepath.Join(config.UdevRulesPath, "backups")
	
	// Create backup directory if needed
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		slog.Warn("Failed to create backup directory", "error", err)
		// Continue anyway - we'll use the main rules directory
	}
	
	// Pattern for rule files we might want to back up
	patterns := []string{
		fmt.Sprintf("*usb*soundcard*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*usb*sound*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*sound*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*card*%s*%s*.rules", card.VendorID, card.ProductID),
		fmt.Sprintf("*audio*%s*%s*.rules", card.VendorID, card.ProductID),
	}

	// Count existing backups to enforce limits
	existingBackups := 0
	backupPrefix := fmt.Sprintf("backup_%s_%s_", card.VendorID, card.ProductID)
	
	entries, err := os.ReadDir(backupDir)
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), backupPrefix) {
				existingBackups++
			}
		}
	}
	
	// Check if we've hit the backup limit
	if existingBackups >= config.MaxBackupCount {
		slog.Warn("Backup limit reached, skipping additional backups", 
			"limit", config.MaxBackupCount, 
			"existing", existingBackups)
		return nil
	}

	backupCount := 0
	for _, pattern := range patterns {
		// Check context cancellation
		if backupCount >= config.MaxBackupCount {
			slog.Info("Reached maximum backup count", "max", config.MaxBackupCount)
			break
		}
		
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
			timestamp := time.Now().Format("20060102150405")
			backupFile := filepath.Join(backupDir, fmt.Sprintf("%s%s_%s", 
				backupPrefix, filepath.Base(match), timestamp))
				
			slog.Info("Backing up existing rule file", "source", match, "backup", backupFile)

			// Create a transaction for the backup
			transaction := NewTransaction()
			
			// Add file reading to transaction
			var content []byte
			transaction.AddOperation(
				func() error {
					// Acquire a lock on the source file
					_, err := fileAccess.LockFile(match, config.Timeouts.LockAcquisition)
					if err != nil {
						return fmt.Errorf("failed to acquire lock on file during backup: %w", err)
					}
					defer fileAccess.UnlockFile(match)
					
					// Read the file
					c, err := os.ReadFile(match)
					if err != nil {
						return fmt.Errorf("failed to read file: %w", err)
					}
					
					content = c
					return nil
				},
				// No rollback needed for reading
				func() error { return nil },
			)
			
			// Add file writing to transaction
			transaction.AddOperation(
				func() error {
					// Use atomic write for backup
					return atomicWriteFile(backupFile, content, 0644, fileAccess, config.Timeouts.LockAcquisition)
				},
				// Rollback - delete the backup file
				func() error {
					if exists, _ := fileExists(backupFile); exists {
						return os.Remove(backupFile)
					}
					return nil
				},
			)
			
			// Execute the transaction
			if err := transaction.Execute(); err != nil {
				slog.Error("Failed to back up rule file", "source", match, "error", err)
				continue
			}
			
			backupCount++
			if backupCount >= config.MaxBackupCount {
				slog.Info("Reached maximum backup count", "max", config.MaxBackupCount)
				break
			}
		}
	}

	if backupCount > 0 {
		slog.Info("Created backups of existing rule files", "count", backupCount)
	}
	return nil
}

// testUdevSystem performs a basic test of the udev system
func testUdevSystem(ctx context.Context, executor *CommandExecutor, config Config, fileAccess *SafeFileAccess) (bool, error) {
	slog.Info("Testing if udev rule system is working properly...")
	
	if config.DryRun {
		slog.Info("Dry run mode - skipping udev system test")
		return true, nil
	}
	
	// Create a transaction for testing
	transaction := NewTransaction()
	
	// Create a small test rule
	testRuleFile := filepath.Join(config.UdevRulesPath, "99-test-usb-soundcard-mapper.rules")
	testRuleContent := "# Test rule to check if udev is functioning properly\n"
	
	// Add rule writing to transaction
	transaction.AddOperation(
		// Write test rule
		func() error {
			// Acquire a lock on the test rule file
			_, err := fileAccess.LockFile(testRuleFile, config.Timeouts.LockAcquisition)
			if err != nil {
				return fmt.Errorf("failed to acquire lock on test rule file: %w", err)
			}
			defer fileAccess.UnlockFile(testRuleFile)
			
			return os.WriteFile(testRuleFile, []byte(testRuleContent), 0644)
		},
		// Rollback - remove the test rule
		func() error {
			removeErr := os.Remove(testRuleFile)
			if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				slog.Error("Failed to remove test udev rule", "error", removeErr)
			}
			return nil
		},
	)
	
	// Add rule reloading to transaction
	transaction.AddOperation(
		// Reload rules
		func() error {
			_, err := executor.ExecuteCommand(ctx, "udevadm", "control", "--reload-rules")
			if err != nil {
				return fmt.Errorf("failed to reload udev rules during test: %w", err)
			}
			
			// Wait briefly to ensure reload completes
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(config.Timeouts.RuleReloadWait):
				// Continue
			}
			
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Add rule triggering to transaction
	transaction.AddOperation(
		// Trigger rules
		func() error {
			_, err := executor.ExecuteCommand(ctx, "udevadm", "trigger", "--action=add", "--subsystem-match=usb")
			if err != nil {
				return fmt.Errorf("failed to trigger udev rules during test: %w", err)
			}
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Add cleanup to transaction
	transaction.AddOperation(
		// Remove test rule
		func() error {
			removeErr := os.Remove(testRuleFile)
			if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				slog.Error("Failed to remove test udev rule", "error", removeErr)
				return fmt.Errorf("failed to remove test rule: %w", removeErr)
			}
			return nil
		},
		// No rollback needed
		func() error { return nil },
	)
	
	// Execute the transaction
	if err := transaction.Execute(); err != nil {
		return false, fmt.Errorf("udev system test failed: %w", err)
	}
	
	transaction.Commit()
	slog.Info("Udev system test passed")
	return true, nil
}

// checkAndFixPermissions ensures the udev rules directory has the correct permissions
func checkAndFixPermissions(config Config) error {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(config.UdevRulesPath) {
		return fmt.Errorf("unsafe udev rules path: %s: %w", config.UdevRulesPath, ErrInvalidPath)
	}
	
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
func detectSoundSystemType(ctx context.Context, executor *CommandExecutor) (string, error) {
	// Check for PipeWire first (most modern)
	_, err := executor.ExecuteCommand(ctx, "pipewire", "--version")
	if err == nil {
		slog.Info("Detected PipeWire sound system")
		return "pipewire", nil
	}
	
	// Check for PulseAudio
	_, err = executor.ExecuteCommand(ctx, "pulseaudio", "--version")
	if err == nil {
		slog.Info("Detected PulseAudio sound system")
		return "pulseaudio", nil
	}
	
	// Check for JACK
	_, err = executor.ExecuteCommand(ctx, "jackd", "--version")
	if err == nil {
		slog.Info("Detected JACK sound system")
		return "jack", nil
	}
	
	// Default to ALSA
	slog.Info("Assuming ALSA sound system")
	return "alsa", nil
}

// checkPCIFallbackForSerials verifies if PCI paths are being used as serial numbers
func checkPCIFallbackForSerials(ctx context.Context, executor *CommandExecutor) (bool, error) {
	// Run command to see if any device has a PCI-like serial
	output, err := executor.ExecuteCommand(ctx, "lsusb", "-v")
	if err != nil {
		return false, fmt.Errorf("could not check for PCI fallback serial numbers: %w", err)
	}
	
	hasPCISerials := strings.Contains(output, "iSerial") && strings.Contains(output, ":")
	if hasPCISerials {
		slog.Info("Detected devices with PCI path-like serial numbers. Special handling will be applied.")
	}
	
	return hasPCISerials, nil
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
func fileExists(filename string) (bool, error) {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(filename) {
		return false, fmt.Errorf("unsafe file path: %s: %w", filename, ErrInvalidPath)
	}
	
	info, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("error checking file existence: %w", err)
	}
	return !info.IsDir(), nil
}

// directoryExists checks if a directory exists
func directoryExists(path string) (bool, error) {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(path) {
		return false, fmt.Errorf("unsafe directory path: %s: %w", path, ErrInvalidPath)
	}
	
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("error checking directory existence: %w", err)
	}
	return info.IsDir(), nil
}

// pathExists checks if a path exists (file or directory)
func pathExists(path string) (bool, error) {
	// Validate the path for safety
	if !pathSafeRegex.MatchString(path) {
		return false, fmt.Errorf("unsafe path: %s: %w", path, ErrInvalidPath)
	}
	
	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("error checking path existence: %w", err)
	}
	return true, nil
}

// setupSignalHandling sets up graceful shutdown on system signals
func setupSignalHandling(ctx context.Context, cancel context.CancelFunc, resourceTracker *ResourceTracker, config Config) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, 
		syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
	
	go func() {
		select {
		case sig := <-c:
			slog.Info("Received signal, shutting down gracefully", "signal", sig)
			
			// Cancel the context to stop ongoing operations
			cancel()
			
			// Create a context with timeout for graceful shutdown
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(), 
				config.Timeouts.GracefulShutdown,
			)
			defer shutdownCancel()
			
			// Wait for operations to complete with timeout
			err := resourceTracker.WaitForCompletion(config.Timeouts.GracefulShutdown)
			if err != nil {
				slog.Error("Error waiting for operations to complete", "error", err)
			}
			
			// Clean up all resources
			errs := resourceTracker.CleanupAll()
			if len(errs) > 0 {
				for _, err := range errs {
					slog.Error("Error during resource cleanup", "error", err)
				}
			}
			
			// If timeout occurred during shutdown
			select {
			case <-shutdownCtx.Done():
				if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
					slog.Error("Graceful shutdown timed out, forcing exit")
					os.Exit(1)
				}
			default:
				// Normal shutdown
			}
			
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
	if i.card.IsVirtual {
		title += " [Virtual]"
	}
	return title
}

func (i listItem) Description() string {
	desc := fmt.Sprintf("VID:PID %s:%s", i.card.VendorID, i.card.ProductID)
	if i.card.PhysicalPort != "" {
		desc += fmt.Sprintf(", Port: %s", i.card.PhysicalPort)
	}
	if i.card.ValidationErr != nil {
		desc += fmt.Sprintf(" [Warning: %s]", i.card.ValidationErr)
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
	stateSuccess
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

	warningStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFA500"))

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
	fileAccess      *SafeFileAccess
	error           string
	warning         string
	width           int
	height          int
	successMessage  string
	ctx             context.Context
	cancel          context.CancelFunc
	resourceTracker *ResourceTracker
	operationLock   sync.Mutex
	uiClosed        bool
}

// Initialize UI model
func initialUIModel(cards []USBSoundCard, config Config, executor *CommandExecutor, fileAccess *SafeFileAccess, resourceTracker *ResourceTracker) uiModel {
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
		cards:           cards,
		list:            l,
		textInput:       ti,
		state:           stateCardSelect,
		config:          config,
		executor:        executor,
		fileAccess:      fileAccess,
		ctx:             ctx,
		cancel:          cancel,
		resourceTracker: resourceTracker,
	}
}

// Initialize the model
func (m uiModel) Init() tea.Cmd {
	return nil
}

// safelyPerformBackgroundOperation executes a background operation with proper error handling
func (m *uiModel) safelyPerformBackgroundOperation(operation func() (string, error)) tea.Cmd {
	return func() tea.Msg {
		// Ensure we don't run multiple operations simultaneously
		m.operationLock.Lock()
		defer m.operationLock.Unlock()
		
		// Check if UI is closed
		if m.uiClosed {
			return nil
		}
		
		// Check if context is canceled
		if m.ctx.Err() != nil {
			return errMsg{err: m.ctx.Err()}
		}
		
		// Execute the operation
		result, err := operation()
		if err != nil {
			return errMsg{err: err}
		}
		
		return successMsg{message: result}
	}
}

// Custom messages for handling background operations
type successMsg struct {
	message string
}

type errMsg struct {
	err error
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
		
	case successMsg:
		// Handle operation success
		m.successMessage = msg.message
		m.state = stateSuccess
		return m, nil
		
	case errMsg:
		// Handle operation error
		if errors.Is(msg.err, context.Canceled) {
			// Operation was canceled - exit gracefully
			m.cancel()
			m.uiClosed = true
			return m, tea.Quit
		}
		
		// Set error message and transition to error state
		m.error = msg.err.Error()
		m.state = stateError
		return m, nil
		
	case tea.KeyMsg:
		// Global key handlers
		switch {
		case key.Matches(msg, keys.Quit):
			slog.Debug("User quit application")
			m.cancel() // Cancel the context
			m.uiClosed = true
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
				
				// Show warning for virtual devices
				if m.selectedCard.IsVirtual {
					m.warning = "This appears to be a virtual audio device. Continue with caution."
				} else {
					m.warning = ""
				}
				
				// Show warning for validation errors
				if m.selectedCard.ValidationErr != nil {
					if m.warning != "" {
						m.warning += "\n"
					}
					m.warning += fmt.Sprintf("Validation warning: %s", m.selectedCard.ValidationErr)
				}
				
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
				m.warning = ""
				m.state = stateCardSelect
				return m, nil
			}
			
			// Pass the message to the text input component
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)
			
		case stateConfirmation:
			switch {
			case key.Matches(msg, keys.Confirm):
				// Run the installation in the background to keep UI responsive
				return m, m.safelyPerformBackgroundOperation(func() (string, error) {
					// Create udev rule with custom name
					rule, err := createUdevRule(m.ctx, m.selectedCard, m.customName, m.config)
					if err != nil {
						slog.Error("Failed to create udev rule", "error", err)
						return "", fmt.Errorf("failed to create udev rule: %w", err)
					}
					
					// Backup existing rules for this device
					if err := backupExistingUdevRules(m.selectedCard, m.config, m.fileAccess); err != nil {
						slog.Warn("Failed to backup existing rules", "error", err)
					}
					
					// Install the rule
					if err := installUdevRule(m.ctx, rule, m.config, m.fileAccess); err != nil {
						slog.Error("Failed to install udev rule", "error", err)
						return "", fmt.Errorf("failed to install udev rule: %w", err)
					}
					
					// Reload udev rules if not skipped
					if !m.config.SkipReload {
						if err := reloadUdevRules(m.ctx, m.executor, m.config); err != nil {
							slog.Error("Failed to reload udev rules", "error", err)
							return "", fmt.Errorf("failed to reload udev rules: %w", err)
						}
						
						// Verify the rule installation
						success, err := verifyUdevRuleInstallation(m.ctx, m.executor, m.selectedCard, m.customName, m.config)
						if err != nil {
							if errors.Is(err, ErrDeviceDisconnected) {
								m.warning = "Device appears to have been disconnected. Rules were created but could not be verified."
							} else {
								slog.Warn("Rule verification issue", "error", err)
								m.warning = fmt.Sprintf("Rules created but verification had issues: %v", err)
							}
						} else if !success {
							m.warning = "Rules created but verification could not confirm they were applied correctly."
						}
					}
					
					// Success message
					var messageBuilder strings.Builder
					messageBuilder.WriteString(fmt.Sprintf("Created persistent mapping for %s %s (VID:PID %s:%s) as '%s'\n\n",
						m.selectedCard.Vendor, m.selectedCard.Product, 
						m.selectedCard.VendorID, m.selectedCard.ProductID, 
						m.customName))
					
					messageBuilder.WriteString(
						"The sound card will use this name consistently across reboots and reconnections.\n"+
						"You can see this device in 'aplay -l' output as card with ID '%s'\n"+
						"once you disconnect and reconnect the device.\n")
					
					if m.warning != "" {
						messageBuilder.WriteString("\nWarning: " + m.warning)
					}
					
					return messageBuilder.String(), nil
				})
				
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
			
		case stateSuccess:
			// Quit on any key press
			m.cancel() // Cancel the context before quitting
			m.uiClosed = true
			return m, tea.Quit
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
		
		if m.warning != "" {
			sb.WriteString(warningStyle.Render("Warning: " + m.warning) + "\n\n")
		}
		
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
		
		if m.selectedCard.IsVirtual {
			sb.WriteString("Type: Virtual Device\n")
		}
		
		sb.WriteString(fmt.Sprintf("\nCustom Name: %s\n\n", highlightStyle.Render(m.customName)))
		
		if m.warning != "" {
			sb.WriteString(warningStyle.Render("Warning: " + m.warning) + "\n\n")
		}
		
		sb.WriteString("Press 'y' to confirm or Esc to go back.")
		
	case stateError:
		sb.WriteString(errorStyle.Render("Error:") + "\n\n")
		sb.WriteString(m.error + "\n\n")
		sb.WriteString("Press any key to return to device selection...")
		
	case stateSuccess:
		sb.WriteString(infoStyle.Render("Success!") + "\n\n")
		sb.WriteString(m.successMessage + "\n\n")
		
		// Add rule file info
		rulePath := filepath.Join(m.config.UdevRulesPath, 
			fmt.Sprintf("89-usb-soundcard-%s-%s.rules", m.selectedCard.VendorID, m.selectedCard.ProductID))
		sb.WriteString(fmt.Sprintf("Rule file created at: %s\n\n", rulePath))
		
		sb.WriteString("Important: For the changes to take full effect, please:\n")
		sb.WriteString("1. Disconnect and reconnect the USB sound device, or\n")
		sb.WriteString("2. Reboot your system\n\n")
		
		sb.WriteString("For immediate application of rules without rebooting, run:\n")
		sb.WriteString("sudo udevadm control --reload-rules && sudo udevadm trigger --action=add --subsystem-match=sound\n\n")
		
		sb.WriteString("Press any key to exit...")
	}
	
	return docStyle.Render(sb.String())
}

// runUI starts the terminal UI for interactive mode
func runUI(ctx context.Context, cards []USBSoundCard, config Config, executor *CommandExecutor, fileAccess *SafeFileAccess, resourceTracker *ResourceTracker) (string, error) {
	if len(cards) == 0 {
		return "", ErrNoUSBSoundCards
	}
	
	model := initialUIModel(cards, config, executor, fileAccess, resourceTracker)
	
	// Create a new program with alt screen enabled
	p := tea.NewProgram(model, tea.WithAltScreen())
	
	// Set up a channel to handle context cancellation
	cancelCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Context was canceled, send a quit message to the program
			p.Send(errMsg{err: ctx.Err()})
		case <-cancelCh:
			// Program finished normally, clean up
			return
		}
	}()
	
	// Run the UI
	finalModel, err := p.Run()
	close(cancelCh) // Signal that the program is done
	
	if err != nil {
		return "", fmt.Errorf("UI error: %w", err)
	}
	
	// Extract the model
	m, ok := finalModel.(uiModel)
	if !ok {
		return "", fmt.Errorf("unexpected model type returned from UI")
	}
	
	// Check if we have a success message
	if m.successMessage != "" {
		return m.successMessage, nil
	}
	
	// If we don't have a success message, the user probably quit early
	return "", ErrOperationCancelled
}

// nonInteractiveMode handles the non-interactive operation
func nonInteractiveMode(ctx context.Context, config Config, executor *CommandExecutor, fileAccess *SafeFileAccess, cards []USBSoundCard) error {
	// Validate required parameters
	if config.VendorID == "" || config.ProductID == "" {
		return fmt.Errorf("in non-interactive mode, --vendor-id and --product-id are required: %w", ErrInvalidDeviceParams)
	}
	
	// Validate vendor and product IDs
	if !vendorIDRegex.MatchString(config.VendorID) {
		return fmt.Errorf("invalid vendor ID format: %s: %w", config.VendorID, ErrInvalidDeviceParams)
	}
	
	if !productIDRegex.MatchString(config.ProductID) {
		return fmt.Errorf("invalid product ID format: %s: %w", config.ProductID, ErrInvalidDeviceParams)
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
	
	// Check if it's a virtual device
	if selectedCard.IsVirtual && !config.IgnoreVirtual {
		slog.Warn("Selected device appears to be virtual", "card", selectedCard.String())
		if !config.ForceOverwrite {
			return fmt.Errorf("selected device appears to be virtual: %w", ErrVirtualDevice)
		}
	}
	
	// If a custom name was specified, use it
	customName := selectedCard.FriendlyName
	if config.DeviceName != "" {
		customName = cleanupName(config.DeviceName)
	}
	
	// Validate the name
	if customName == "" {
		return ErrDeviceNameEmpty
	}
	
	// Create a transaction for the entire operation
	transaction := NewTransaction()
	
	// Add backup operation to transaction
	transaction.AddOperation(
		func() error {
			return backupExistingUdevRules(selectedCard, config, fileAccess)
		},
		// No rollback needed for backup
		func() error { return nil },
	)
	
	// Add rule creation and installation to transaction
	var rule *UdevRule
	transaction.AddOperation(
		func() error {
			var err error
			// Create udev rule
			rule, err = createUdevRule(ctx, selectedCard, customName, config)
			if err != nil {
				return fmt.Errorf("failed to create udev rule: %w", err)
			}
			
			// Install the rule
			return installUdevRule(ctx, rule, config, fileAccess)
		},
		// Rollback - remove the rule file if it was created
		func() error {
			if rule != nil && !config.DryRun {
				if exists, _ := fileExists(rule.Path); exists {
					return os.Remove(rule.Path)
				}
			}
			return nil
		},
	)
	
	// Add rule reloading to transaction if not skipped
	if !config.SkipReload {
		transaction.AddOperation(
			func() error {
				return reloadUdevRules(ctx, executor, config)
			},
			// No rollback needed for reloading
			func() error { return nil },
		)
	}
	
	// Execute the transaction
	if err := transaction.Execute(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}
	
	// Verify the installation if not in dry run mode and reloading wasn't skipped
	if !config.DryRun && !config.SkipReload {
		success, err := verifyUdevRuleInstallation(ctx, executor, selectedCard, customName, config)
		if err != nil {
			if errors.Is(err, ErrDeviceDisconnected) {
				slog.Warn("Device appears to have been disconnected. Rules were created but could not be verified.")
			} else {
				slog.Warn("Rule verification issue", "error", err)
			}
		} else if !success {
			slog.Warn("Rules created but verification could not confirm they were applied correctly.")
		}
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
	
	// Commit the transaction
	transaction.Commit()
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
		
		if card.IsVirtual {
			fmt.Printf("   Type: Virtual Device\n")
		}
		
		fmt.Printf("   Suggested Name: %s\n", card.FriendlyName)
		
		if card.ValidationErr != nil {
			fmt.Printf("   Validation Warning: %s\n", card.ValidationErr)
		}
		
		fmt.Println()
	}
}

// validateConfig validates the configuration for consistency and safety
func validateConfig(config *Config) error {
	// Validate UdevRulesPath
	if !pathSafeRegex.MatchString(config.UdevRulesPath) {
		return fmt.Errorf("unsafe udev rules path: %s: %w", config.UdevRulesPath, ErrInvalidPath)
	}
	
	// Make sure MaxBackupCount is reasonable
	if config.MaxBackupCount <= 0 {
		config.MaxBackupCount = maxBackupCount
	}
	
	// Set resource limits if not specified
	if config.ResourceLimits.MaxConcurrentOps <= 0 {
		config.ResourceLimits.MaxConcurrentOps = config.ConcurrencyOpts.MaxWorkers
	}
	
	if config.ResourceLimits.MaxQueueSize <= 0 {
		config.ResourceLimits.MaxQueueSize = maxQueueSize
	}
	
	if config.ResourceLimits.MaxFileSize <= 0 {
		config.ResourceLimits.MaxFileSize = maxFileSize
	}
	
	// Check for conflicting options
	if config.DryRun && config.ForceOverwrite {
		// Not a fatal error, but warn and prioritize dry run
		slog.Warn("Both --dry-run and --force specified; dry run takes precedence")
	}
	
	// If vendor ID or product ID is specified, validate their format
	if config.VendorID != "" {
		if !vendorIDRegex.MatchString(config.VendorID) {
			return fmt.Errorf("invalid vendor ID format: %s: %w", config.VendorID, ErrInvalidDeviceParams)
		}
	}
	
	if config.ProductID != "" {
		if !productIDRegex.MatchString(config.ProductID) {
			return fmt.Errorf("invalid product ID format: %s: %w", config.ProductID, ErrInvalidDeviceParams)
		}
	}
	
	// Ensure LockAcquisition timeout is set
	if config.Timeouts.LockAcquisition <= 0 {
		config.Timeouts.LockAcquisition = DefaultTimeouts.LockAcquisition
	}
	
	// Ensure GracefulShutdown timeout is set
	if config.Timeouts.GracefulShutdown <= 0 {
		config.Timeouts.GracefulShutdown = DefaultTimeouts.GracefulShutdown
	}
	
	return nil
}

// main function
func main() {
	// Create a root context for the entire application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create resource tracker
	resourceTracker := NewResourceTracker()
	
	// Create safe file access manager
	fileAccess := NewSafeFileAccess(resourceTracker)
	
	// Parse command line flags
	config := Config{
		UdevRulesPath: udevRulesDir,
		LogLevel:      LogLevelInfo,
		BackupRules:   true,
		Timeouts:      DefaultTimeouts,
		MaxRetries:    3,
		ForceOverwrite: false,
		IgnoreVirtual:  false,
		MaxBackupCount: maxBackupCount,
		ConcurrencyOpts: ConcurrencyOptions{
			MaxWorkers:     4,
			OperationQueue: maxQueueSize,
		},
		ResourceLimits: ResourceLimits{
			MaxConcurrentOps:    4,
			MaxQueueSize:        maxQueueSize,
			MaxFileSize:         maxFileSize,
			MaxBackupsPerDevice: maxBackupCount,
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
	flag.BoolVar(&config.ForceOverwrite, "force", false, "Force overwrite existing rules and accept virtual devices")
	flag.BoolVar(&config.IgnoreVirtual, "ignore-virtual", false, "Ignore virtual audio devices")
	flag.IntVar(&config.MaxBackupCount, "max-backups", maxBackupCount, "Maximum number of backups to keep per device")
	
	var logLevelStr string
	flag.StringVar(&logLevelStr, "log-level", string(LogLevelInfo), "Log level (debug, info, warn, error)")
	
	var commandTimeout int
	flag.IntVar(&commandTimeout, "command-timeout", int(DefaultTimeouts.CommandExecution/time.Second), "Command execution timeout in seconds")
	
	var lockTimeout int
	flag.IntVar(&lockTimeout, "lock-timeout", int(DefaultTimeouts.LockAcquisition/time.Second), "File lock acquisition timeout in seconds")
	
	var gracefulTimeout int
	flag.IntVar(&gracefulTimeout, "graceful-timeout", int(DefaultTimeouts.GracefulShutdown/time.Second), "Graceful shutdown timeout in seconds")
	
	var retries int
	flag.IntVar(&retries, "retries", config.MaxRetries, "Maximum number of retries for commands")
	
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
		fmt.Fprintf(os.Stderr, "  %s --force --ignore-virtual # Force overwrite existing rules and ignore virtual devices\n", AppName)
	}
	
	flag.Parse()
	
	// Set log level
	config.LogLevel = LogLevel(logLevelStr)
	
	// Set timeouts from command line
	config.Timeouts.CommandExecution = time.Duration(commandTimeout) * time.Second
	config.Timeouts.LockAcquisition = time.Duration(lockTimeout) * time.Second
	config.Timeouts.GracefulShutdown = time.Duration(gracefulTimeout) * time.Second
	config.MaxRetries = retries
	
	// Validate configuration
	if err := validateConfig(&config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Initialize structured logging
	initLogger(config.LogLevel)
	
	// Log basic startup info
	slog.Info(fmt.Sprintf("Starting %s v%s", AppName, AppVersion),
		"rules_path", config.UdevRulesPath,
		"interactive", !config.NonInteractive,
		"dry_run", config.DryRun,
		"force", config.ForceOverwrite,
		"ignore_virtual", config.IgnoreVirtual)
	
	// Setup signal handling for graceful shutdown
	setupSignalHandling(ctx, cancel, resourceTracker, config)
	
	// Create command executor
	executor := NewCommandExecutor(config, resourceTracker)
	
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
	
	// Check and fix permissions on udev rules directory if needed
	if !config.ListOnly && !config.DryRun {
		if err := checkAndFixPermissions(config); err != nil {
			slog.Error("Permission check failed", "error", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Test if udev system is working properly
	if !config.ListOnly && !config.DryRun {
		success, err := testUdevSystem(ctx, executor, config, fileAccess)
		if err != nil {
			slog.Error("Udev system test failed", "error", err)
			fmt.Fprintf(os.Stderr, "Warning: Udev system test failed - %v\n", err)
			// Continue anyway, but with a warning
		} else if !success {
			slog.Error("Udev system test failed", "error", ErrUdevSystemFailure)
			fmt.Fprintf(os.Stderr, "Warning: Udev system test failed - rules may not apply correctly\n")
			// Continue anyway, but with a warning
		}
	}
	
	// Check
	// Check for PCI fallback serial numbers
	hasPCISerials, err := checkPCIFallbackForSerials(ctx, executor)
	if err != nil {
		slog.Warn("Failed to check for PCI fallback serials", "error", err)
	} else {
		slog.Debug("PCI fallback serial detection", "has_pci_serials", hasPCISerials)
	}
	
	// Detect sound system type for additional compatibility
	soundSystem, err := detectSoundSystemType(ctx, executor)
	if err != nil {
		slog.Warn("Failed to detect sound system", "error", err)
	} else {
		slog.Info("Sound system detection", "system", soundSystem)
	}
	
	// Find all USB devices for reference
	allUSBDevices, err := findAllUSBDevices(ctx, executor)
	if err != nil {
		slog.Error("Failed to enumerate all USB devices", "error", err)
		// This is not fatal, continue anyway
	} else {
		slog.Debug("USB devices found", "count", len(allUSBDevices))
	}
	
	// Check if context has been canceled
	if ctx.Err() != nil {
		slog.Info("Operation interrupted, shutting down")
		fmt.Println("Operation interrupted. Shutting down...")
		
		// Ensure clean shutdown
		errs := resourceTracker.CleanupAll()
		if len(errs) > 0 {
			for _, err := range errs {
				slog.Error("Error during resource cleanup", "error", err)
			}
		}
		
		os.Exit(0)
	}
	
	// List all USB sound cards
	cards, err := GetUSBSoundCards(ctx, executor, config)
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
		err := nonInteractiveMode(ctx, config, executor, fileAccess, cards)
		if err != nil {
			slog.Error("Non-interactive mode failed", "error", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	
	// Interactive mode - run the terminal UI
	result, err := runUI(ctx, cards, config, executor, fileAccess, resourceTracker)
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
	
	// Perform final cleanup
	if errs := resourceTracker.CleanupAll(); len(errs) > 0 {
		slog.Warn("Some errors occurred during final cleanup", "count", len(errs))
		for _, err := range errs {
			slog.Error("Cleanup error", "error", err)
		}
	}
}
