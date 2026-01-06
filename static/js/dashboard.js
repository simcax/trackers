/**
 * Dashboard.js - Interactive tracker card features for Tracker Web UI
 * 
 * This module provides comprehensive interactive functionality for tracker cards including:
 * - "Add Today's Value" button functionality with API integration
 * - "View Chart" button behavior and navigation
 * - Interactive value badges with hover and click effects
 * - Loading states and visual feedback for all interactions
 * - Integration with existing tracker and tracker-value API endpoints
 * 
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
 */

class TrackerDashboard {
    constructor() {
        this.isLoading = false;
        this.loadingStates = new Map(); // Track loading states per tracker
        this.apiBaseUrl = '/api';
        this.webBaseUrl = '/web';
        
        this.init();
    }
    
    /**
     * Initialize the dashboard interactions
     */
    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupInteractions());
        } else {
            this.setupInteractions();
        }
    }
    
    /**
     * Set up all interactive elements and event listeners
     */
    setupInteractions() {
        this.setupAddValueButtons();
        this.setupViewChartButtons();
        this.setupValueBadges();
        this.setupKeyboardNavigation();
        this.setupTooltips();
        this.setupJobButtons();
        this.setupTrackerJobNavigation();
        this.initializeCharts();
        
        console.log('TrackerDashboard: Interactive features initialized');
    }
    
    /**
     * Set up "Add Today's Value" button functionality
     * Validates: Requirements 4.1, 4.5
     */
    setupAddValueButtons() {
        const addValueButtons = document.querySelectorAll('[data-action="add-value"]');
        
        addValueButtons.forEach(button => {
            // Remove any existing event listeners
            button.removeEventListener('click', this.handleAddValue);
            
            // Add new event listener
            button.addEventListener('click', (e) => this.handleAddValue(e));
            
            // Add keyboard support
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleAddValue(e);
                }
            });
            
            // Add hover effects
            button.addEventListener('mouseenter', () => {
                if (!this.isButtonLoading(button)) {
                    button.classList.add('transform', 'scale-105');
                }
            });
            
            button.addEventListener('mouseleave', () => {
                button.classList.remove('transform', 'scale-105');
            });
        });
    }
    
    /**
     * Set up "View Chart" button functionality
     * Validates: Requirements 4.2, 4.5
     */
    setupViewChartButtons() {
        const viewChartButtons = document.querySelectorAll('[data-action="view-chart"]');
        
        viewChartButtons.forEach(button => {
            // Remove any existing event listeners
            button.removeEventListener('click', this.handleViewChart);
            
            // Add new event listener
            button.addEventListener('click', (e) => this.handleViewChart(e));
            
            // Add keyboard support
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleViewChart(e);
                }
            });
            
            // Add hover effects
            button.addEventListener('mouseenter', () => {
                button.classList.add('bg-gray-600', 'scale-105');
                button.classList.remove('bg-gray-700');
            });
            
            button.addEventListener('mouseleave', () => {
                button.classList.remove('bg-gray-600', 'scale-105');
                button.classList.add('bg-gray-700');
            });
        });
    }
    
    /**
     * Set up interactive value badges with hover and click effects
     * Validates: Requirements 4.3, 4.5
     */
    setupValueBadges() {
        const valueBadges = document.querySelectorAll('[data-action="show-value-details"]');
        
        valueBadges.forEach(badge => {
            // Remove any existing event listeners
            badge.removeEventListener('click', this.handleValueBadgeClick);
            
            // Add new event listener
            badge.addEventListener('click', (e) => this.handleValueBadgeClick(e));
            
            // Add keyboard support
            badge.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleValueBadgeClick(e);
                }
            });
            
            // Enhanced hover effects
            badge.addEventListener('mouseenter', () => {
                badge.classList.add('bg-gray-600', 'text-white', 'transform', 'scale-110');
                badge.classList.remove('bg-gray-700', 'text-gray-300');
                
                // Show tooltip with additional info
                this.showValueTooltip(badge);
            });
            
            badge.addEventListener('mouseleave', () => {
                badge.classList.remove('bg-gray-600', 'text-white', 'transform', 'scale-110');
                badge.classList.add('bg-gray-700', 'text-gray-300');
                
                // Hide tooltip
                this.hideValueTooltip(badge);
            });
        });
    }
    
    /**
     * Set up keyboard navigation for accessibility
     */
    setupKeyboardNavigation() {
        // Handle Escape key to close any open modals or tooltips
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideAllTooltips();
                this.hideAllModals();
            }
        });
        
        // Handle Tab navigation for better accessibility
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                // Ensure focus is visible on interactive elements
                const focusedElement = document.activeElement;
                if (focusedElement && focusedElement.classList.contains('focus:ring-2')) {
                    focusedElement.classList.add('ring-2', 'ring-blue-500');
                }
            }
        });
    }
    
    /**
     * Initialize mini charts for all tracker cards
     */
    initializeCharts() {
        // Initialize charts system if available
        if (window.trackerCharts) {
            window.trackerCharts.renderAllCharts();
        } else if (window.TrackerCharts) {
            // Fallback: create charts instance if not already created
            window.trackerCharts = new window.TrackerCharts();
        }
        
        console.log('TrackerDashboard: Charts initialized');
    }
    
    /**
     * Set up tooltips for enhanced user experience
     */
    setupTooltips() {
        // Initialize tooltip container if it doesn't exist
        if (!document.getElementById('tooltip-container')) {
            const tooltipContainer = document.createElement('div');
            tooltipContainer.id = 'tooltip-container';
            tooltipContainer.className = 'fixed z-50 pointer-events-none';
            document.body.appendChild(tooltipContainer);
        }
    }
    
    /**
     * Set up job-related buttons (view jobs, create job)
     */
    setupJobButtons() {
        // Set up "View Jobs" buttons
        const viewJobsButtons = document.querySelectorAll('[data-action="view-jobs"]');
        viewJobsButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleViewJobs(e));
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleViewJobs(e);
                }
            });
        });
        
        // Set up "Create Job" buttons
        const createJobButtons = document.querySelectorAll('[data-action="create-job"]');
        createJobButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleCreateJob(e));
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleCreateJob(e);
                }
            });
        });
        
        // Set up "Edit Tracker" buttons
        const editTrackerButtons = document.querySelectorAll('[data-action="edit-tracker"]');
        editTrackerButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleEditTracker(e));
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleEditTracker(e);
                }
            });
        });
        
        // Set up "Delete Tracker" buttons
        const deleteTrackerButtons = document.querySelectorAll('[data-action="delete-tracker"]');
        deleteTrackerButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleDeleteTracker(e));
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleDeleteTracker(e);
                }
            });
        });
    }
    
    /**
     * Set up tracker navigation from job cards
     */
    setupTrackerJobNavigation() {
        // Set up "View Tracker" buttons in job cards
        const viewTrackerButtons = document.querySelectorAll('[data-action="view-tracker"]');
        viewTrackerButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleViewTracker(e));
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.handleViewTracker(e);
                }
            });
        });
    }
    
    /**
     * Handle "Add Today's Value" button clicks
     * @param {Event} event - Click event
     */
    async handleAddValue(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        if (this.isButtonLoading(button)) {
            return; // Prevent double-clicks
        }
        
        try {
            // Show input modal for value and date entry
            const result = await this.showValueInputModal(trackerName);
            
            if (!result || !result.value || result.value.trim() === '') {
                return; // User cancelled or entered empty value
            }
            
            // Set loading state
            this.setButtonLoading(button, true);
            
            // Submit value to web endpoint
            // Parse Danish number format before submitting
            const parsedValue = this.parseDanishNumber(result.value);
            const formattedValue = isNaN(parsedValue) ? result.value : parsedValue.toString();
            
            const submitResult = await this.submitTrackerValue(trackerId, formattedValue, result.date);
            
            if (submitResult.success) {
                // Show success message with Danish formatted number
                const displayValue = isNaN(parsedValue) ? result.value : this.formatDanishNumber(parsedValue);
                const displayDate = this.formatDanishDate(result.date);
                this.showToast(`Added value ${displayValue} for ${displayDate} to ${trackerName}`, 'success');
                
                // Update the tracker card with new data
                await this.refreshTrackerCard(trackerId);
                
                // Optional: Refresh entire page after delay
                setTimeout(() => {
                    location.reload();
                }, 2000);
            } else {
                this.showToast(submitResult.message || 'Failed to add value', 'error');
            }
            
        } catch (error) {
            console.error('Error adding tracker value:', error);
            this.showToast('An error occurred while adding the value', 'error');
        } finally {
            this.setButtonLoading(button, false);
        }
    }
    
    /**
     * Handle "View Chart" button clicks
     * @param {Event} event - Click event
     */
    async handleViewChart(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        try {
            // Set loading state
            this.setButtonLoading(button, true);
            
            // Fetch tracker data for chart
            const trackerData = await this.fetchTrackerData(trackerId);
            
            if (trackerData.success) {
                // Show chart modal with data
                this.showChartModal(trackerName, trackerData.values);
            } else {
                this.showToast(trackerData.message || 'Failed to load chart data', 'error');
            }
            
        } catch (error) {
            console.error('Error loading chart:', error);
            this.showToast('An error occurred while loading the chart', 'error');
        } finally {
            this.setButtonLoading(button, false);
        }
    }
    
    /**
     * Handle value badge clicks
     * @param {Event} event - Click event
     */
    handleValueBadgeClick(event) {
        event.preventDefault();
        
        const badge = event.currentTarget;
        const value = badge.dataset.value;
        const daysAgo = badge.dataset.daysAgo;
        const date = badge.dataset.date;
        
        // Show detailed value information
        this.showValueDetailsModal(value, daysAgo, date);
    }
    
    /**
     * Handle "View Jobs" button clicks
     * @param {Event} event - Click event
     */
    async handleViewJobs(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        if (this.isButtonLoading(button)) {
            return; // Prevent double-clicks
        }
        
        try {
            this.setButtonLoading(button, true);
            
            // Fetch jobs for this tracker
            const response = await fetch(`/web/trackers/${trackerId}/jobs`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            // Show jobs modal
            this.showJobsModal(trackerName, data.jobs);
            
        } catch (error) {
            console.error('Error loading jobs:', error);
            this.showToast('Failed to load jobs for this tracker', 'error');
        } finally {
            this.setButtonLoading(button, false);
        }
    }
    
    /**
     * Handle "Create Job" button clicks
     * @param {Event} event - Click event
     */
    async handleCreateJob(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        // Navigate to jobs page with pre-selected tracker
        if (window.showJobForm) {
            window.showJobForm(trackerId);
        } else {
            // Fallback: navigate to jobs page
            window.location.href = `/web/jobs?tracker_id=${trackerId}`;
        }
    }
    
    /**
     * Handle "View Tracker" button clicks from job cards
     * @param {Event} event - Click event
     */
    async handleViewTracker(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const jobId = button.dataset.jobId;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        // Navigate to dashboard and highlight the tracker
        if (window.location.pathname === '/web/trackers' || window.location.pathname === '/') {
            // Already on dashboard, just scroll to tracker
            this.scrollToTracker(trackerId);
        } else {
            // Navigate to dashboard with tracker highlight
            window.location.href = `/?highlight=${trackerId}`;
        }
    }
    
    /**
     * Handle "Edit Tracker" button clicks
     * @param {Event} event - Click event
     */
    async handleEditTracker(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        const trackerDescription = button.dataset.trackerDescription || '';
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        if (this.isButtonLoading(button)) {
            return; // Prevent double-clicks
        }
        
        try {
            // Show edit modal and get updated values
            const result = await this.showTrackerEditModal(trackerName, trackerDescription);
            
            if (!result) {
                return; // User cancelled
            }
            
            this.setButtonLoading(button, true);
            
            // Update tracker via API
            const response = await fetch(`${this.webBaseUrl}/tracker/${trackerId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: result.name,
                    description: result.description
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            // Show success message
            this.showToast(`Tracker "${data.tracker.name}" updated successfully`, 'success');
            
            // Refresh the page to show updated tracker
            setTimeout(() => {
                window.location.reload();
            }, 1000);
            
        } catch (error) {
            console.error('Error updating tracker:', error);
            this.showToast(`Failed to update tracker: ${error.message}`, 'error');
        } finally {
            this.setButtonLoading(button, false);
        }
    }
    
    /**
     * Handle "Delete Tracker" button clicks
     * @param {Event} event - Click event
     */
    async handleDeleteTracker(event) {
        event.preventDefault();
        
        const button = event.currentTarget;
        const trackerId = button.dataset.trackerId;
        const trackerName = button.dataset.trackerName;
        
        if (!trackerId) {
            this.showToast('Error: Tracker ID not found', 'error');
            return;
        }
        
        if (this.isButtonLoading(button)) {
            return; // Prevent double-clicks
        }
        
        try {
            // Show confirmation dialog
            const confirmed = await this.showDeleteConfirmationModal(trackerName);
            
            if (!confirmed) {
                return; // User cancelled
            }
            
            this.setButtonLoading(button, true);
            
            // Delete tracker via API
            const response = await fetch(`${this.webBaseUrl}/tracker/${trackerId}`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            // Show success message
            this.showToast(`Tracker "${trackerName}" deleted successfully`, 'success');
            
            // Remove the tracker card from the DOM
            const trackerCard = button.closest('article');
            if (trackerCard) {
                trackerCard.style.transition = 'all 0.3s ease-out';
                trackerCard.style.transform = 'scale(0.95)';
                trackerCard.style.opacity = '0';
                
                setTimeout(() => {
                    trackerCard.remove();
                }, 300);
            }
            
        } catch (error) {
            console.error('Error deleting tracker:', error);
            this.showToast(`Failed to delete tracker: ${error.message}`, 'error');
        } finally {
            this.setButtonLoading(button, false);
        }
    }
    
    /**
     * Show input modal for entering tracker value
     * @param {string} trackerName - Name of the tracker
     * @returns {Promise<Object|null>} - Entered value and date or null if cancelled
     */
    showValueInputModal(trackerName) {
        return new Promise((resolve) => {
            // Get today's date in YYYY-MM-DD format for the input
            const today = new Date().toISOString().split('T')[0];
            // Get today's date in Danish format for display
            const todayDanish = this.formatDanishDate(today);
            
            // Create modal HTML
            const modalHtml = `
                <div id="value-input-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <h3 class="text-lg font-semibold text-white mb-4">Add Value for ${trackerName}</h3>
                        
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-2">Date:</label>
                                <input 
                                    type="date" 
                                    id="date-input" 
                                    value="${today}"
                                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                >
                                <p class="text-xs text-gray-400 mt-1">Select the date for this value (today: ${todayDanish})</p>
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-2">Value:</label>
                                <input 
                                    type="text" 
                                    id="value-input" 
                                    placeholder="Enter value (use comma for decimals)..."
                                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    autocomplete="off"
                                >
                                <p class="text-xs text-gray-400 mt-1">Enter a numeric value (e.g., 1.234,56 or 42,5)</p>
                            </div>
                            
                            <div class="flex space-x-3">
                                <button 
                                    id="save-value-btn" 
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                                >
                                    Save Value
                                </button>
                                <button 
                                    id="cancel-value-btn" 
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Add modal to page
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            const modal = document.getElementById('value-input-modal');
            const dateInput = document.getElementById('date-input');
            const valueInput = document.getElementById('value-input');
            const saveBtn = document.getElementById('save-value-btn');
            const cancelBtn = document.getElementById('cancel-value-btn');
            
            // Focus value input
            setTimeout(() => valueInput.focus(), 100);
            
            // Handle save
            const handleSave = () => {
                const value = valueInput.value.trim();
                const date = dateInput.value;
                
                if (!value) {
                    valueInput.focus();
                    return;
                }
                
                this.removeModal(modal);
                resolve({ value, date });
            };
            
            // Handle cancel
            const handleCancel = () => {
                this.removeModal(modal);
                resolve(null);
            };
            
            // Event listeners
            saveBtn.addEventListener('click', handleSave);
            cancelBtn.addEventListener('click', handleCancel);
            
            // Handle Enter key on value input
            valueInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    handleSave();
                }
                if (e.key === 'Escape') {
                    e.preventDefault();
                    handleCancel();
                }
            });
            
            // Handle Enter key on date input
            dateInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    valueInput.focus();
                }
                if (e.key === 'Escape') {
                    e.preventDefault();
                    handleCancel();
                }
            });
            
            // Handle click outside modal
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    handleCancel();
                }
            });
        });
    }
    
    /**
     * Show chart modal with tracker data
     * @param {string} trackerName - Name of the tracker
     * @param {Array} values - Array of tracker values
     */
    showChartModal(trackerName, values) {
        // Create chart modal HTML
        const modalHtml = `
            <div id="chart-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                <div class="bg-gray-800 rounded-xl p-6 max-w-4xl w-full mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-semibold text-white">${trackerName} - Chart View</h3>
                        <button 
                            id="close-chart-btn" 
                            class="text-gray-400 hover:text-white transition-colors"
                            aria-label="Close chart"
                        >
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <div class="space-y-6">
                        <!-- Chart Container -->
                        <div class="bg-gray-700 rounded-lg p-4 h-64 flex items-center justify-center">
                            <div id="chart-container" class="w-full h-full bg-gray-700 rounded">
                                ${this.generateSimpleChart(values)}
                            </div>
                        </div>
                        
                        <!-- Values Table -->
                        <div class="bg-gray-700 rounded-lg p-4">
                            <h4 class="text-lg font-medium text-white mb-3">Recent Values</h4>
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm">
                                    <thead>
                                        <tr class="text-gray-300 border-b border-gray-600">
                                            <th class="text-left py-2">Date</th>
                                            <th class="text-left py-2">Value</th>
                                            <th class="text-left py-2">Change</th>
                                        </tr>
                                    </thead>
                                    <tbody class="text-gray-200">
                                        ${this.generateValuesTable(values)}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        const modal = document.getElementById('chart-modal');
        const closeBtn = document.getElementById('close-chart-btn');
        
        // Handle close
        const handleClose = () => {
            this.removeModal(modal);
        };
        
        // Event listeners
        closeBtn.addEventListener('click', handleClose);
        
        // Handle Escape key
        document.addEventListener('keydown', function escapeHandler(e) {
            if (e.key === 'Escape') {
                handleClose();
                document.removeEventListener('keydown', escapeHandler);
            }
        });
        
        // Handle click outside modal
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                handleClose();
            }
        });
    }
    
    /**
     * Show value details modal
     * @param {string} value - The value
     * @param {string} daysAgo - Days ago text
     * @param {string} date - The date
     */
    showValueDetailsModal(value, daysAgo, date) {
        const dayText = daysAgo === '1' ? 'yesterday' : `${daysAgo} days ago`;
        
        const modalHtml = `
            <div id="value-details-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                <div class="bg-gray-800 rounded-xl p-6 max-w-sm w-full mx-4 shadow-2xl">
                    <div class="text-center space-y-4">
                        <div class="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center mx-auto">
                            <span class="text-2xl font-bold text-white">${value}</span>
                        </div>
                        
                        <div>
                            <h3 class="text-lg font-semibold text-white">Value Details</h3>
                            <p class="text-gray-300 mt-2">
                                Value: <span class="font-medium text-white">${value}</span>
                            </p>
                            <p class="text-gray-300">
                                Recorded: <span class="font-medium text-white">${dayText}</span>
                            </p>
                            ${date ? `<p class="text-gray-400 text-sm">Date: ${date}</p>` : ''}
                        </div>
                        
                        <button 
                            id="close-details-btn" 
                            class="w-full bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                        >
                            Close
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        const modal = document.getElementById('value-details-modal');
        const closeBtn = document.getElementById('close-details-btn');
        
        // Handle close
        const handleClose = () => {
            this.removeModal(modal);
        };
        
        // Event listeners
        closeBtn.addEventListener('click', handleClose);
        
        // Handle click outside modal
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                handleClose();
            }
        });
        
        // Auto-close after 3 seconds
        setTimeout(handleClose, 3000);
    }
    
    /**
     * Show tracker edit modal
     * @param {string} currentName - Current tracker name
     * @param {string} currentDescription - Current tracker description
     * @returns {Promise<Object|null>} - Updated name and description or null if cancelled
     */
    showTrackerEditModal(currentName, currentDescription) {
        return new Promise((resolve) => {
            const modalHtml = `
                <div id="tracker-edit-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <h3 class="text-lg font-semibold text-white mb-4">Edit Tracker</h3>
                        
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-2">Name:</label>
                                <input 
                                    type="text" 
                                    id="tracker-name-input" 
                                    value="${currentName}"
                                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="Enter tracker name"
                                    maxlength="100"
                                    required
                                >
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-2">Description:</label>
                                <textarea 
                                    id="tracker-description-input" 
                                    class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                                    placeholder="Enter tracker description (optional)"
                                    rows="3"
                                    maxlength="500"
                                >${currentDescription}</textarea>
                            </div>
                        </div>
                        
                        <div class="flex space-x-3 mt-6">
                            <button 
                                id="save-tracker-btn" 
                                class="flex-1 bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded-lg text-white font-medium transition-colors focus:ring-2 focus:ring-blue-500"
                            >
                                Save Changes
                            </button>
                            <button 
                                id="cancel-tracker-btn" 
                                class="flex-1 bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            // Add modal to page
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            const modal = document.getElementById('tracker-edit-modal');
            const nameInput = document.getElementById('tracker-name-input');
            const descriptionInput = document.getElementById('tracker-description-input');
            const saveBtn = document.getElementById('save-tracker-btn');
            const cancelBtn = document.getElementById('cancel-tracker-btn');
            
            // Focus name input
            setTimeout(() => nameInput.focus(), 100);
            
            // Handle save
            const handleSave = () => {
                const name = nameInput.value.trim();
                const description = descriptionInput.value.trim();
                
                if (!name) {
                    nameInput.focus();
                    return;
                }
                
                this.removeModal(modal);
                resolve({ name, description });
            };
            
            // Handle cancel
            const handleCancel = () => {
                this.removeModal(modal);
                resolve(null);
            };
            
            // Event listeners
            saveBtn.addEventListener('click', handleSave);
            cancelBtn.addEventListener('click', handleCancel);
            
            // Handle Enter key
            nameInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    handleSave();
                }
                if (e.key === 'Escape') {
                    e.preventDefault();
                    handleCancel();
                }
            });
            
            descriptionInput.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    e.preventDefault();
                    handleCancel();
                }
            });
            
            // Handle click outside modal
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    handleCancel();
                }
            });
        });
    }
    
    /**
     * Show delete confirmation modal
     * @param {string} trackerName - Name of the tracker to delete
     * @returns {Promise<boolean>} - True if confirmed, false if cancelled
     */
    showDeleteConfirmationModal(trackerName) {
        return new Promise((resolve) => {
            const modalHtml = `
                <div id="delete-confirmation-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center">
                                <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Delete Tracker</h3>
                        </div>
                        
                        <div class="mb-6">
                            <p class="text-gray-300">
                                Are you sure you want to delete the tracker <strong class="text-white">"${trackerName}"</strong>?
                            </p>
                            <p class="text-red-400 text-sm mt-2">
                                This action cannot be undone. All associated values and jobs will also be deleted.
                            </p>
                        </div>
                        
                        <div class="flex space-x-3">
                            <button 
                                id="confirm-delete-btn" 
                                class="flex-1 bg-red-600 hover:bg-red-700 py-2 px-4 rounded-lg text-white font-medium transition-colors focus:ring-2 focus:ring-red-500"
                            >
                                Delete Tracker
                            </button>
                            <button 
                                id="cancel-delete-btn" 
                                class="flex-1 bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            // Add modal to page
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            const modal = document.getElementById('delete-confirmation-modal');
            const confirmBtn = document.getElementById('confirm-delete-btn');
            const cancelBtn = document.getElementById('cancel-delete-btn');
            
            // Focus cancel button by default for safety
            setTimeout(() => cancelBtn.focus(), 100);
            
            // Handle confirm
            const handleConfirm = () => {
                this.removeModal(modal);
                resolve(true);
            };
            
            // Handle cancel
            const handleCancel = () => {
                this.removeModal(modal);
                resolve(false);
            };
            
            // Event listeners
            confirmBtn.addEventListener('click', handleConfirm);
            cancelBtn.addEventListener('click', handleCancel);
            
            // Handle Escape key (should cancel)
            document.addEventListener('keydown', function escapeHandler(e) {
                if (e.key === 'Escape') {
                    handleCancel();
                    document.removeEventListener('keydown', escapeHandler);
                }
            });
            
            // Handle click outside modal (should cancel)
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    handleCancel();
                }
            });
        });
    }
    
    /**
     * Show jobs modal for a tracker
     * @param {string} trackerName - Name of the tracker
     * @param {Array} jobs - Array of jobs for the tracker
     */
    showJobsModal(trackerName, jobs) {
        const modalHtml = `
            <div id="jobs-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                <div class="bg-gray-800 rounded-xl p-6 max-w-4xl w-full mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-semibold text-white">Jobs for ${trackerName}</h3>
                        <button 
                            id="close-jobs-btn" 
                            class="text-gray-400 hover:text-white transition-colors"
                            aria-label="Close jobs modal"
                        >
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <div class="space-y-4">
                        ${jobs.length === 0 ? 
                            '<div class="text-center py-8"><p class="text-gray-400">No jobs found for this tracker.</p></div>' :
                            jobs.map(job => this.generateJobCard(job)).join('')
                        }
                        
                        <div class="pt-4 border-t border-gray-600">
                            <button 
                                id="create-job-from-modal-btn"
                                class="w-full bg-purple-600 hover:bg-purple-700 py-3 px-4 rounded-lg text-white font-medium transition-colors flex items-center justify-center space-x-2"
                            >
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                                </svg>
                                <span>Create New Job</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        const modal = document.getElementById('jobs-modal');
        const closeBtn = document.getElementById('close-jobs-btn');
        const createJobBtn = document.getElementById('create-job-from-modal-btn');
        
        // Handle close
        const handleClose = () => {
            this.removeModal(modal);
        };
        
        // Event listeners
        closeBtn.addEventListener('click', handleClose);
        
        if (createJobBtn) {
            createJobBtn.addEventListener('click', () => {
                handleClose();
                if (window.showJobForm) {
                    window.showJobForm();
                } else {
                    window.location.href = '/web/jobs';
                }
            });
        }
        
        // Handle Escape key
        document.addEventListener('keydown', function escapeHandler(e) {
            if (e.key === 'Escape') {
                handleClose();
                document.removeEventListener('keydown', escapeHandler);
            }
        });
        
        // Handle click outside modal
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                handleClose();
            }
        });
    }
    
    /**
     * Generate HTML for a job card in the modal
     * @param {Object} job - Job object
     * @returns {string} - HTML string for the job card
     */
    generateJobCard(job) {
        const statusColor = job.is_active ? 'text-green-400' : 'text-gray-400';
        const statusText = job.is_active ? 'Active' : 'Inactive';
        const typeIcon = job.job_type === 'stock' ? '📈' : '🔗';
        
        return `
            <div class="bg-gray-700 rounded-lg p-4 border border-gray-600">
                <div class="flex justify-between items-start mb-3">
                    <div>
                        <h4 class="text-lg font-medium text-white">${this.escapeHtml(job.name)}</h4>
                        <div class="flex items-center space-x-2 mt-1">
                            <span class="text-sm ${statusColor}">${statusText}</span>
                            <span class="text-sm text-gray-400">${typeIcon} ${job.job_type}</span>
                        </div>
                    </div>
                    <div class="flex space-x-2">
                        <button 
                            data-job-action="view-details"
                            data-job-id="${job.id}"
                            class="text-blue-400 hover:text-blue-300 text-sm underline"
                            onclick="window.location.href='/web/jobs?job_id=${job.id}'"
                        >
                            View Details
                        </button>
                        <button 
                            data-job-action="edit-job"
                            data-job-id="${job.id}"
                            class="text-green-400 hover:text-green-300 text-sm underline"
                        >
                            Edit
                        </button>
                        <button 
                            data-job-action="delete-job"
                            data-job-id="${job.id}"
                            data-job-name="${this.escapeHtml(job.name)}"
                            class="text-red-400 hover:text-red-300 text-sm underline"
                        >
                            Delete
                        </button>
                    </div>
                </div>
                
                <div class="text-sm text-gray-400 space-y-1">
                    <div class="flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span class="font-mono text-xs">${this.escapeHtml(job.cron_schedule)}</span>
                    </div>
                    
                    ${job.last_run_at ? `
                        <div class="flex justify-between">
                            <span>Last Run:</span>
                            <span class="text-gray-300">${new Date(job.last_run_at).toLocaleDateString()}</span>
                        </div>
                    ` : ''}
                    
                    ${job.failure_count > 0 ? `
                        <div class="flex justify-between">
                            <span>Failures:</span>
                            <span class="text-red-400">${job.failure_count}</span>
                        </div>
                    ` : ''}
                </div>
                
                <div class="mt-3 pt-3 border-t border-gray-600">
                    <div class="flex space-x-2">
                        <button 
                            data-job-action="test-job"
                            data-job-id="${job.id}"
                            class="flex-1 bg-blue-600 hover:bg-blue-700 text-white text-sm py-2 px-3 rounded-lg transition-colors"
                        >
                            Run Now
                        </button>
                        <button 
                            data-job-action="toggle-status"
                            data-job-id="${job.id}"
                            data-new-status="${!job.is_active}"
                            class="bg-${job.is_active ? 'yellow' : 'green'}-600 hover:bg-${job.is_active ? 'yellow' : 'green'}-700 text-white text-sm py-2 px-3 rounded-lg transition-colors"
                        >
                            ${job.is_active ? 'Disable' : 'Enable'}
                        </button>
                    </div>
                </div>
            </div>
        `;
    }
    
    /**
     * Scroll to a specific tracker card and highlight it
     * @param {string} trackerId - ID of the tracker to scroll to
     */
    scrollToTracker(trackerId) {
        const trackerCard = document.querySelector(`[data-tracker-id="${trackerId}"]`);
        if (trackerCard) {
            trackerCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
            
            // Add highlight effect
            trackerCard.classList.add('ring-4', 'ring-blue-500', 'ring-opacity-50');
            setTimeout(() => {
                trackerCard.classList.remove('ring-4', 'ring-blue-500', 'ring-opacity-50');
            }, 3000);
        }
    }
    
    /**
     * Submit tracker value to web endpoint (not API endpoint)
     * @param {string} trackerId - ID of the tracker
     * @param {string} value - Value to submit
     * @param {string} date - Date in YYYY-MM-DD format (optional, defaults to today)
     * @returns {Promise<Object>} - Web response
     */
    async submitTrackerValue(trackerId, value, date = null) {
        try {
            // Use provided date or default to today
            const submitDate = date || new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
            
            const response = await fetch(`${this.webBaseUrl}/tracker/${trackerId}/value`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    date: submitDate,
                    value: value
                })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                return {
                    success: true,
                    message: result.message,
                    data: result.value
                };
            } else {
                return {
                    success: false,
                    message: result.error || 'Failed to add value'
                };
            }
        } catch (error) {
            console.error('Web request failed:', error);
            return {
                success: false,
                message: 'Network error. Please check your connection.'
            };
        }
    }
    
    /**
     * Fetch tracker data for charts from web endpoint (no authentication required)
     * @param {string} trackerId - ID of the tracker
     * @returns {Promise<Object>} - Tracker data
     */
    async fetchTrackerData(trackerId) {
        try {
            const response = await fetch(`${this.webBaseUrl}/tracker/${trackerId}/chart-data`, {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            const result = await response.json();
            
            if (response.ok && result.success) {
                return {
                    success: true,
                    values: result.values || [],
                    tracker: result.tracker
                };
            } else {
                return {
                    success: false,
                    message: result.error || 'Failed to fetch chart data'
                };
            }
        } catch (error) {
            console.error('Web request failed:', error);
            return {
                success: false,
                message: 'Network error. Please check your connection.'
            };
        }
    }
    
    /**
     * Refresh a specific tracker card with new data
     * @param {string} trackerId - ID of the tracker to refresh
     */
    async refreshTrackerCard(trackerId) {
        try {
            // Find the tracker card
            const trackerCard = document.querySelector(`[data-tracker-id="${trackerId}"]`);
            if (!trackerCard) return;
            
            // Add loading state to card
            trackerCard.classList.add('opacity-75');
            
            // Refresh chart if charts system is available
            if (window.trackerCharts && window.trackerCharts.updateTrackerChart) {
                // Fetch updated values for chart
                const trackerData = await this.fetchTrackerData(trackerId);
                if (trackerData.success) {
                    window.trackerCharts.updateTrackerChart(trackerId, trackerData.values);
                }
            }
            
            // Show success indicator
            setTimeout(() => {
                trackerCard.classList.remove('opacity-75');
                trackerCard.classList.add('ring-2', 'ring-green-500');
                
                setTimeout(() => {
                    trackerCard.classList.remove('ring-2', 'ring-green-500');
                }, 2000);
            }, 500);
            
        } catch (error) {
            console.error('Error refreshing tracker card:', error);
        }
    }
    
    /**
     * Parse Danish number format (convert comma decimals to dots)
     * @param {string} numberString - Number string in Danish format
     * @returns {number} - Parsed number
     */
    parseDanishNumber(numberString) {
        if (typeof numberString !== 'string') {
            return parseFloat(numberString) || 0;
        }
        
        // Replace Danish decimal comma with dot and remove thousand separators
        const normalized = numberString
            .replace(/\./g, '') // Remove thousand separators (dots)
            .replace(/,/g, '.'); // Replace decimal comma with dot
        
        return parseFloat(normalized) || 0;
    }
    
    /**
     * Format date using Danish format (dd-mm-yyyy)
     * @param {string} dateString - Date string in ISO format
     * @returns {string} - Formatted date
     */
    formatDanishDate(dateString) {
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return dateString; // Return original if invalid
            }
            
            // Format as dd-mm-yyyy
            const day = date.getDate().toString().padStart(2, '0');
            const month = (date.getMonth() + 1).toString().padStart(2, '0');
            const year = date.getFullYear();
            
            return `${day}-${month}-${year}`;
        } catch (error) {
            return dateString; // Return original if error
        }
    }
    
    /**
     * Format number using Danish conventions (. for thousands, , for decimals)
     * @param {number} number - Number to format
     * @returns {string} - Formatted number
     */
    formatDanishNumber(number) {
        if (typeof number !== 'number' || isNaN(number)) {
            return '0';
        }
        
        // Use Danish locale formatting
        return number.toLocaleString('da-DK', {
            minimumFractionDigits: 0,
            maximumFractionDigits: 2
        });
    }
    
    /**
     * Generate simple SVG chart for values
     * @param {Array} values - Array of tracker values
     * @returns {string} - SVG chart HTML
     */
    generateSimpleChart(values) {
        if (!values || values.length === 0) {
            return `
                <div class="flex items-center justify-center h-full text-gray-400">
                    <div class="text-center">
                        <svg class="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                        </svg>
                        <p>No data available</p>
                    </div>
                </div>
            `;
        }
        
        // Simple line chart using SVG
        const width = 400;
        const height = 200;
        const padding = 40;
        
        // Extract numeric values and reverse for chronological order (oldest first)
        const numericValues = values
            .map(v => parseFloat(v.value))
            .filter(v => !isNaN(v))
            .slice(0, 30) // Last 30 values
            .reverse(); // Reverse to get chronological order (oldest first)
        
        if (numericValues.length === 0) {
            return `
                <div class="flex items-center justify-center h-full text-gray-400">
                    <p>No numeric data to chart</p>
                </div>
            `;
        }
        
        const minValue = Math.min(...numericValues);
        const maxValue = Math.max(...numericValues);
        const valueRange = maxValue - minValue || 1;
        
        // Generate points
        const points = numericValues.map((value, index) => {
            const x = padding + (index * (width - 2 * padding)) / Math.max(numericValues.length - 1, 1);
            const y = height - padding - ((value - minValue) / valueRange) * (height - 2 * padding);
            return `${x},${y}`;
        }).join(' ');
        
        return `
            <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" class="text-blue-400" style="background-color: #374151;">
                <!-- Background -->
                <rect width="100%" height="100%" fill="#374151" />
                
                <!-- Grid lines -->
                <defs>
                    <pattern id="grid-${Date.now()}" width="40" height="40" patternUnits="userSpaceOnUse">
                        <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#6b7280" stroke-width="0.5" opacity="0.3"/>
                    </pattern>
                </defs>
                <rect width="100%" height="100%" fill="url(#grid-${Date.now()})" />
                
                <!-- Chart line -->
                <polyline 
                    points="${points}"
                    fill="none" 
                    stroke="currentColor" 
                    stroke-width="3" 
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
                
                <!-- Data points -->
                ${numericValues.map((value, index) => {
                    const x = padding + (index * (width - 2 * padding)) / Math.max(numericValues.length - 1, 1);
                    const y = height - padding - ((value - minValue) / valueRange) * (height - 2 * padding);
                    return `<circle cx="${x}" cy="${y}" r="4" fill="currentColor" opacity="0.8"/>`;
                }).join('')}
                
                <!-- Labels -->
                <text x="${padding}" y="${height - 10}" fill="#d1d5db" font-size="12" opacity="0.8">
                    ${this.formatDanishNumber(minValue)}
                </text>
                <text x="${width - padding}" y="${height - 10}" fill="#d1d5db" font-size="12" opacity="0.8" text-anchor="end">
                    ${this.formatDanishNumber(maxValue)}
                </text>
            </svg>
        `;
    }
    
    /**
     * Generate values table HTML
     * @param {Array} values - Array of tracker values
     * @returns {string} - Table rows HTML
     */
    generateValuesTable(values) {
        if (!values || values.length === 0) {
            return '<tr><td colspan="3" class="text-center py-4 text-gray-400">No data available</td></tr>';
        }
        
        return values.slice(0, 10).map((value, index) => {
            const currentValue = parseFloat(value.value);
            const previousValue = index < values.length - 1 ? parseFloat(values[index + 1].value) : null;
            
            let changeText = '-';
            let changeClass = 'text-gray-400';
            
            if (previousValue !== null && !isNaN(currentValue) && !isNaN(previousValue)) {
                const change = currentValue - previousValue;
                if (change > 0) {
                    changeText = `+${this.formatDanishNumber(change)}`;
                    changeClass = 'text-green-400';
                } else if (change < 0) {
                    changeText = this.formatDanishNumber(change);
                    changeClass = 'text-red-400';
                } else {
                    changeText = '0';
                    changeClass = 'text-gray-400';
                }
            }
            
            // Format the date in Danish format (dd-mm-yyyy)
            const formattedDate = this.formatDanishDate(value.date);
            
            return `
                <tr class="border-b border-gray-600">
                    <td class="py-2">${formattedDate}</td>
                    <td class="py-2 font-medium">${this.formatDanishNumber(parseFloat(value.value))}</td>
                    <td class="py-2 ${changeClass}">${changeText}</td>
                </tr>
            `;
        }).join('');
    }
    
    /**
     * Show tooltip for value badge
     * @param {Element} badge - Badge element
     */
    showValueTooltip(badge) {
        const value = badge.dataset.value;
        const daysAgo = badge.dataset.daysAgo;
        const date = badge.dataset.date;
        
        const dayText = daysAgo === '1' ? 'yesterday' : `${daysAgo} days ago`;
        
        const tooltip = document.createElement('div');
        tooltip.className = 'absolute bg-gray-900 text-white text-xs rounded py-1 px-2 z-10 whitespace-nowrap';
        tooltip.innerHTML = `
            <div>Value: ${value}</div>
            <div>From: ${dayText}</div>
            ${date ? `<div class="text-gray-400">${date}</div>` : ''}
        `;
        
        // Position tooltip
        const rect = badge.getBoundingClientRect();
        tooltip.style.left = `${rect.left + rect.width / 2}px`;
        tooltip.style.top = `${rect.top - 10}px`;
        tooltip.style.transform = 'translateX(-50%) translateY(-100%)';
        
        badge.setAttribute('data-tooltip-id', 'value-tooltip');
        tooltip.id = 'value-tooltip';
        
        document.body.appendChild(tooltip);
    }
    
    /**
     * Hide tooltip for value badge
     * @param {Element} badge - Badge element
     */
    hideValueTooltip(badge) {
        const tooltipId = badge.getAttribute('data-tooltip-id');
        if (tooltipId) {
            const tooltip = document.getElementById(tooltipId);
            if (tooltip) {
                tooltip.remove();
            }
            badge.removeAttribute('data-tooltip-id');
        }
    }
    
    /**
     * Hide all tooltips
     */
    hideAllTooltips() {
        const tooltips = document.querySelectorAll('[id$="-tooltip"]');
        tooltips.forEach(tooltip => tooltip.remove());
    }
    
    /**
     * Hide all modals
     */
    hideAllModals() {
        const modals = document.querySelectorAll('[id$="-modal"]');
        modals.forEach(modal => this.removeModal(modal));
    }
    
    /**
     * Remove modal with animation
     * @param {Element} modal - Modal element to remove
     */
    removeModal(modal) {
        if (!modal) return;
        
        // Animate out
        modal.style.opacity = '0';
        modal.style.transform = 'scale(0.95)';
        
        setTimeout(() => {
            if (modal.parentNode) {
                modal.parentNode.removeChild(modal);
            }
        }, 200);
    }
    
    /**
     * Set button loading state
     * @param {Element} button - Button element
     * @param {boolean} loading - Loading state
     */
    setButtonLoading(button, loading) {
        const trackerId = button.dataset.trackerId;
        
        if (loading) {
            this.loadingStates.set(trackerId, true);
            
            // Use global feedback manager if available
            if (window.feedbackManager && window.feedbackManager.showLoading) {
                window.feedbackManager.showLoading(button, {
                    text: 'Loading...',
                    size: 'small',
                    overlay: false,
                    spinner: true
                });
            } else {
                // Fallback to original implementation
                button.disabled = true;
                button.classList.add('opacity-75', 'cursor-not-allowed');
                
                // Add loading spinner
                const originalContent = button.innerHTML;
                button.setAttribute('data-original-content', originalContent);
                button.innerHTML = `
                    <div class="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                    Loading...
                `;
            }
        } else {
            this.loadingStates.delete(trackerId);
            
            // Use global feedback manager if available
            if (window.feedbackManager && window.feedbackManager.hideLoading) {
                window.feedbackManager.hideLoading(button);
            } else {
                // Fallback to original implementation
                button.disabled = false;
                button.classList.remove('opacity-75', 'cursor-not-allowed');
                
                // Restore original content
                const originalContent = button.getAttribute('data-original-content');
                if (originalContent) {
                    button.innerHTML = originalContent;
                    button.removeAttribute('data-original-content');
                }
            }
        }
    }
    
    /**
     * Check if button is in loading state
     * @param {Element} button - Button element
     * @returns {boolean} - True if loading
     */
    isButtonLoading(button) {
        const trackerId = button.dataset.trackerId;
        return this.loadingStates.has(trackerId);
    }
    
    /**
     * Show toast notification
     * @param {string} message - Message to display
     * @param {string} type - 'success', 'error', or 'info'
     */
    showToast(message, type = 'info') {
        // Use global feedback manager if available
        if (window.feedbackManager && window.feedbackManager.showToast) {
            return window.feedbackManager.showToast(message, type);
        }
        
        // Try legacy toast system if available
        if (window.TrackerUI && window.TrackerUI.showToast) {
            window.TrackerUI.showToast(message, type);
            return;
        }
        
        // Fallback: create temporary toast
        this.showTemporaryToast(message, type);
    }
    
    /**
     * Show temporary toast notification
     * @param {string} message - Message to display
     * @param {string} type - 'success', 'error', or 'info'
     */
    showTemporaryToast(message, type) {
        // Remove existing toast
        const existingToast = document.getElementById('temp-toast');
        if (existingToast) {
            existingToast.remove();
        }
        
        // Determine colors based on type
        let bgColor, textColor, icon;
        switch (type) {
            case 'success':
                bgColor = 'bg-green-600';
                textColor = 'text-white';
                icon = `<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>`;
                break;
            case 'error':
                bgColor = 'bg-red-600';
                textColor = 'text-white';
                icon = `<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>`;
                break;
            default:
                bgColor = 'bg-blue-600';
                textColor = 'text-white';
                icon = `<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>`;
        }
        
        // Create toast element
        const toast = document.createElement('div');
        toast.id = 'temp-toast';
        toast.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transition-all duration-300 ${bgColor} ${textColor}`;
        
        // Create content safely to prevent XSS
        const contentDiv = document.createElement('div');
        contentDiv.className = 'flex items-center space-x-2';
        
        const iconSvg = document.createElement('svg');
        iconSvg.className = 'w-5 h-5 flex-shrink-0';
        iconSvg.setAttribute('fill', 'currentColor');
        iconSvg.setAttribute('viewBox', '0 0 20 20');
        iconSvg.innerHTML = icon; // Icon is safe, controlled content
        
        const messageSpan = document.createElement('span');
        messageSpan.textContent = message; // Use textContent to prevent XSS
        
        contentDiv.appendChild(iconSvg);
        contentDiv.appendChild(messageSpan);
        toast.appendChild(contentDiv);
        
        // Add to page
        document.body.appendChild(toast);
        
        // Animate in
        requestAnimationFrame(() => {
            toast.style.transform = 'translateX(100%)';
            requestAnimationFrame(() => {
                toast.style.transform = 'translateX(0)';
            });
        });
        
        // Remove after delay
        setTimeout(() => {
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 4000);
    }
    
    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} - Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Remove modal from DOM
     * @param {Element} modal - Modal element to remove
     */
    removeModal(modal) {
        if (modal && modal.parentNode) {
            modal.parentNode.removeChild(modal);
        }
    }
}

// Global functions for backward compatibility with existing template
window.addTodaysValue = function(trackerId, trackerName) {
    if (window.trackerDashboard) {
        const button = document.querySelector(`[data-tracker-id="${trackerId}"][data-action="add-value"]`);
        if (button) {
            window.trackerDashboard.handleAddValue({ currentTarget: button, preventDefault: () => {} });
        }
    }
};

window.viewChart = function(trackerId) {
    if (window.trackerDashboard) {
        const button = document.querySelector(`[data-tracker-id="${trackerId}"][data-action="view-chart"]`);
        if (button) {
            window.trackerDashboard.handleViewChart({ currentTarget: button, preventDefault: () => {} });
        }
    }
};

window.showValueDetails = function(value, daysAgo, date) {
    if (window.trackerDashboard) {
        window.trackerDashboard.showValueDetailsModal(value, daysAgo, date);
    }
};

// Initialize dashboard when DOM is ready
let trackerDashboard;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        trackerDashboard = new TrackerDashboard();
        window.trackerDashboard = trackerDashboard;
    });
} else {
    trackerDashboard = new TrackerDashboard();
    window.trackerDashboard = trackerDashboard;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TrackerDashboard };
}

// Make available globally
window.TrackerDashboard = TrackerDashboard;