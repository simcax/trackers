/**
 * Forms.js - Form handling and validation for Tracker Web UI
 * 
 * This module provides comprehensive form handling including:
 * - Client-side validation for required fields
 * - Form submission handling with API integration
 * - Color selection functionality for theme picker
 * - Form show/hide animations and state management
 * 
 * Validates: Requirements 2.4, 2.5, 6.1, 6.4
 */

class TrackerFormHandler {
    constructor() {
        this.form = null;
        this.submitButton = null;
        this.isSubmitting = false;
        this.validationRules = {};
        this.colorOptions = [];
        this.selectedColor = 'blue'; // Default color
        
        this.init();
    }
    
    /**
     * Initialize the form handler
     */
    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupForm());
        } else {
            this.setupForm();
        }
    }
    
    /**
     * Set up form elements and event listeners
     */
    setupForm() {
        // Don't try to find form immediately - it might be in a hidden modal
        // Instead, set up a mutation observer or wait for form to be shown
        this.setupGlobalFormHandler();
    }
    
    /**
     * Set up global form handler that can work with dynamically shown forms
     */
    setupGlobalFormHandler() {
        // Listen for when forms become visible
        document.addEventListener('click', (e) => {
            if (e.target.id === 'create-tracker-btn' || e.target.closest('#create-tracker-btn')) {
                // Form is about to be shown, set it up
                setTimeout(() => this.initializeForm(), 100);
            }
        });
        
        // Also try to initialize immediately if form is already visible
        this.initializeForm();
    }
    
    /**
     * Initialize the form when it becomes available
     */
    initializeForm() {
        this.form = document.getElementById('tracker-form');
        this.submitButton = document.getElementById('submit-btn');
        
        if (!this.form) {
            console.warn('TrackerFormHandler: Form not found, will retry when modal opens');
            return false;
        }
        
        // Only set up once
        if (this.form.dataset.handlerSetup === 'true') {
            return true;
        }
        
        this.form.dataset.handlerSetup = 'true';
        
        this.setupValidationRules();
        this.setupEventListeners();
        this.setupColorSelection();
        this.setupFormAnimations();
        
        console.log('TrackerFormHandler: Form initialized successfully');
        return true;
    }
    
    /**
     * Define validation rules for form fields
     */
    setupValidationRules() {
        this.validationRules = {
            name: {
                required: true,
                maxLength: 100,
                validate: async (value) => {
                    if (!value.trim()) {
                        return 'Tracker name is required';
                    }
                    if (value.length > 100) {
                        return 'Name must be 100 characters or less';
                    }
                    
                    // Check for duplicate names
                    const isDuplicate = await this.checkNameExists(value.trim());
                    if (isDuplicate) {
                        return `A tracker named "${value.trim()}" already exists. Please choose a different name.`;
                    }
                    
                    return null;
                }
            },
            unit: {
                required: true,
                maxLength: 20,
                validate: (value) => {
                    if (!value.trim()) {
                        return 'Unit is required';
                    }
                    if (value.length > 20) {
                        return 'Unit must be 20 characters or less';
                    }
                    return null;
                }
            },
            goal: {
                required: false,
                maxLength: 100,
                validate: (value) => {
                    if (value && value.length > 100) {
                        return 'Goal must be 100 characters or less';
                    }
                    return null;
                }
            },
            color: {
                required: true,
                validate: (value) => {
                    const validColors = ['red', 'blue', 'green', 'teal'];
                    if (!value) {
                        return 'Please select a color theme';
                    }
                    if (!validColors.includes(value)) {
                        return 'Please select a valid color theme';
                    }
                    return null;
                }
            }
        };
    }
    
    /**
     * Set up event listeners for form interactions
     */
    setupEventListeners() {
        if (!this.form) {
            console.warn('TrackerFormHandler: Cannot set up event listeners - form not found');
            return;
        }
        
        // Form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Real-time validation on blur
        const nameInput = document.getElementById('tracker-name');
        const unitInput = document.getElementById('tracker-unit');
        const goalInput = document.getElementById('tracker-goal');
        
        if (nameInput) {
            nameInput.addEventListener('blur', async () => await this.validateField('name'));
            nameInput.addEventListener('input', () => this.clearFieldError('name'));
        }
        
        if (unitInput) {
            unitInput.addEventListener('blur', async () => await this.validateField('unit'));
            unitInput.addEventListener('input', () => this.clearFieldError('unit'));
        }
        
        if (goalInput) {
            goalInput.addEventListener('blur', async () => await this.validateField('goal'));
            goalInput.addEventListener('input', () => this.clearFieldError('goal'));
        }
        
        // Keyboard navigation support
        this.form.addEventListener('keydown', (e) => this.handleKeyNavigation(e));
    }
    
    /**
     * Set up color selection functionality
     */
    setupColorSelection() {
        this.colorOptions = document.querySelectorAll('.color-option');
        const colorInputs = document.querySelectorAll('input[name="color"]');
        
        this.colorOptions.forEach(option => {
            // Click handler
            option.addEventListener('click', (e) => {
                e.preventDefault();
                this.selectColor(option.dataset.color);
            });
            
            // Keyboard support
            option.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.selectColor(option.dataset.color);
                }
                
                // Arrow key navigation
                if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                    e.preventDefault();
                    this.navigateColorOptions(e.key === 'ArrowRight');
                }
            });
            
            // Focus management
            option.addEventListener('focus', () => {
                option.classList.add('ring-2', 'ring-white', 'ring-offset-2', 'ring-offset-gray-800');
            });
            
            option.addEventListener('blur', () => {
                option.classList.remove('ring-2', 'ring-white', 'ring-offset-2', 'ring-offset-gray-800');
            });
        });
        
        // Set initial selection (blue is default)
        this.selectColor('blue');
    }
    
    /**
     * Select a color theme
     * @param {string} color - The color to select
     */
    selectColor(color) {
        this.selectedColor = color;
        
        // Update radio buttons
        const colorInputs = document.querySelectorAll('input[name="color"]');
        colorInputs.forEach(input => {
            input.checked = input.value === color;
        });
        
        // Update visual selection
        this.colorOptions.forEach(option => {
            const checkIcon = option.querySelector('.check-icon');
            const isSelected = option.dataset.color === color;
            
            if (isSelected) {
                // Add selected styling
                option.classList.add(`border-${color}-300`);
                option.classList.remove('border-transparent');
                option.setAttribute('aria-checked', 'true');
                if (checkIcon) {
                    checkIcon.classList.remove('hidden');
                }
            } else {
                // Remove selected styling
                const currentColor = option.dataset.color;
                option.classList.remove(`border-${currentColor}-300`);
                option.classList.add('border-transparent');
                option.setAttribute('aria-checked', 'false');
                if (checkIcon) {
                    checkIcon.classList.add('hidden');
                }
            }
        });
        
        // Clear color validation error
        this.clearFieldError('color');
    }
    
    /**
     * Navigate between color options using arrow keys
     * @param {boolean} forward - True for right arrow, false for left arrow
     */
    navigateColorOptions(forward) {
        const colors = ['red', 'blue', 'green', 'teal'];
        const currentIndex = colors.indexOf(this.selectedColor);
        let nextIndex;
        
        if (forward) {
            nextIndex = (currentIndex + 1) % colors.length;
        } else {
            nextIndex = (currentIndex - 1 + colors.length) % colors.length;
        }
        
        const nextColor = colors[nextIndex];
        this.selectColor(nextColor);
        
        // Focus the new option
        const nextOption = document.querySelector(`[data-color="${nextColor}"]`);
        if (nextOption) {
            nextOption.focus();
        }
    }
    
    /**
     * Set up form show/hide animations
     */
    setupFormAnimations() {
        const formModal = document.getElementById('new-tracker-form');
        if (!formModal) return;
        
        // Add CSS classes for animations
        formModal.style.transition = 'opacity 0.3s ease-in-out, transform 0.3s ease-in-out';
        
        // Override the global show/hide functions with animated versions
        if (window.hideTrackerForm) {
            const originalHide = window.hideTrackerForm;
            window.hideTrackerForm = () => {
                this.hideFormWithAnimation(originalHide);
            };
        }
        
        // Add show animation
        const createBtn = document.getElementById('create-tracker-btn');
        if (createBtn) {
            createBtn.addEventListener('click', () => {
                this.showFormWithAnimation();
            });
        }
    }
    
    /**
     * Show form with smooth animation
     */
    showFormWithAnimation() {
        const formModal = document.getElementById('new-tracker-form');
        if (!formModal) return;
        
        // Reset form state
        this.resetForm();
        
        // Show modal with animation
        formModal.classList.remove('hidden');
        formModal.setAttribute('aria-hidden', 'false');
        
        // Trigger animation
        requestAnimationFrame(() => {
            formModal.style.opacity = '0';
            formModal.style.transform = 'scale(0.95)';
            
            requestAnimationFrame(() => {
                formModal.style.opacity = '1';
                formModal.style.transform = 'scale(1)';
            });
        });
        
        // Focus first input
        const firstInput = formModal.querySelector('input:not([type="radio"])');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 150);
        }
    }
    
    /**
     * Hide form with smooth animation
     * @param {Function} callback - Original hide function to call after animation
     */
    hideFormWithAnimation(callback) {
        const formModal = document.getElementById('new-tracker-form');
        if (!formModal) {
            callback();
            return;
        }
        
        // Animate out
        formModal.style.opacity = '0';
        formModal.style.transform = 'scale(0.95)';
        
        // Hide after animation
        setTimeout(() => {
            callback();
            formModal.style.opacity = '';
            formModal.style.transform = '';
        }, 300);
    }
    
    /**
     * Check if a tracker name already exists
     * @param {string} name - Name to check
     * @returns {Promise<boolean>} - True if name exists
     */
    async checkNameExists(name) {
        try {
            const response = await fetch('/trackers', {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            if (response.ok) {
                const result = await response.json();
                const trackers = result.trackers || [];
                
                // Check if any tracker has the same name (case-insensitive)
                return trackers.some(tracker => 
                    tracker.name.toLowerCase() === name.toLowerCase()
                );
            }
        } catch (error) {
            console.warn('Could not check for duplicate names:', error);
            // If we can't check, allow the submission and let the backend handle it
        }
        
        return false;
    }
    
    /**
     * Validate a specific field
     * @param {string} fieldName - Name of the field to validate
     * @returns {Promise<boolean>} - True if valid, false otherwise
     */
    async validateField(fieldName) {
        try {
            const rule = this.validationRules[fieldName];
            if (!rule) return true;
            
            let value;
            if (fieldName === 'color') {
                value = this.selectedColor;
            } else {
                const input = document.getElementById(`tracker-${fieldName}`);
                if (!input) return true;
                value = input.value;
            }
            
            const error = await rule.validate(value);
            
            if (error) {
                this.showFieldError(fieldName, error);
                return false;
            } else {
                this.clearFieldError(fieldName);
                return true;
            }
        } catch (error) {
            console.error(`Validation error for field ${fieldName}:`, error);
            // If validation fails, assume field is invalid to be safe
            this.showFieldError(fieldName, 'Validation error occurred');
            return false;
        }
    }
    
    /**
     * Show validation error for a field
     * @param {string} fieldName - Name of the field
     * @param {string} message - Error message to display
     */
    showFieldError(fieldName, message) {
        const inputElement = document.getElementById(`tracker-${fieldName}`);
        
        if (inputElement) {
            // Use global feedback manager if available
            if (window.feedbackManager && window.feedbackManager.showFieldError) {
                window.feedbackManager.showFieldError(inputElement, message);
            } else {
                // Fallback to original implementation
                const errorElement = document.getElementById(`${fieldName}-error`);
                
                if (errorElement) {
                    errorElement.textContent = message;
                    errorElement.classList.remove('hidden');
                }
                
                inputElement.classList.add('border-red-500');
                inputElement.classList.remove('border-gray-600');
                inputElement.setAttribute('aria-invalid', 'true');
            }
        }
    }
    
    /**
     * Clear validation error for a field
     * @param {string} fieldName - Name of the field
     */
    clearFieldError(fieldName) {
        const inputElement = document.getElementById(`tracker-${fieldName}`);
        
        if (inputElement) {
            // Use global feedback manager if available
            if (window.feedbackManager && window.feedbackManager.hideFieldError) {
                window.feedbackManager.hideFieldError(inputElement);
            } else {
                // Fallback to original implementation
                const errorElement = document.getElementById(`${fieldName}-error`);
                
                if (errorElement) {
                    errorElement.textContent = '';
                    errorElement.classList.add('hidden');
                }
                
                inputElement.classList.remove('border-red-500');
                inputElement.classList.add('border-gray-600');
                inputElement.setAttribute('aria-invalid', 'false');
            }
        }
    }
    
    /**
     * Validate entire form
     * @returns {Promise<boolean>} - True if all fields are valid
     */
    async validateForm() {
        let isValid = true;
        
        try {
            // Validate each field
            for (const fieldName of Object.keys(this.validationRules)) {
                const fieldValid = await this.validateField(fieldName);
                if (!fieldValid) {
                    isValid = false;
                }
            }
        } catch (error) {
            console.error('Form validation error:', error);
            isValid = false;
        }
        
        return isValid;
    }
    
    /**
     * Handle form submission
     * @param {Event} event - Submit event
     */
    async handleSubmit(event) {
        event.preventDefault();
        
        if (this.isSubmitting) {
            return;
        }
        
        // Validate form
        const isValid = await this.validateForm();
        if (!isValid) {
            this.showSubmissionFeedback('Please fix the errors above', 'error');
            return;
        }
        
        this.isSubmitting = true;
        this.setSubmitButtonState('loading');
        
        try {
            // Collect form data
            const formData = this.collectFormData();
            
            // Submit to API
            const result = await this.submitToAPI(formData);
            
            if (result.success) {
                this.showSubmissionFeedback(result.message || 'Tracker created successfully!', 'success');
                this.resetForm();
                
                // Close form after delay
                setTimeout(() => {
                    if (window.hideTrackerForm) {
                        window.hideTrackerForm();
                    }
                    
                    // Refresh page to show new tracker
                    setTimeout(() => {
                        location.reload();
                    }, 500);
                }, 1500);
            } else {
                this.showSubmissionFeedback(result.message || 'Failed to create tracker', 'error');
            }
        } catch (error) {
            console.error('TrackerFormHandler: Form submission error:', error);
            this.showSubmissionFeedback('An error occurred. Please try again.', 'error');
        } finally {
            this.isSubmitting = false;
            this.setSubmitButtonState('normal');
        }
    }
    
    /**
     * Collect form data
     * @returns {Object} - Form data object
     */
    collectFormData() {
        const formData = new FormData(this.form);
        
        // Safely get form values with null checks
        const name = formData.get('name');
        const unit = formData.get('unit');
        const goal = formData.get('goal');
        
        return {
            name: name ? name.trim() : '',
            unit: unit ? unit.trim() : '',
            goal: goal ? goal.trim() : null,
            color: this.selectedColor,
            icon: '📊' // Default icon
        };
    }
    
    /**
     * Submit form data to API
     * @param {Object} data - Form data to submit
     * @returns {Promise<Object>} - API response
     */
    async submitToAPI(data) {
        try {
            const response = await fetch('/web/tracker/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (response.ok) {
                return {
                    success: true,
                    message: result.message,
                    data: result.tracker
                };
            } else {
                // Handle specific error cases with better messaging
                let errorMessage = result.error || 'Failed to create tracker';
                
                if (response.status === 409) {
                    // Duplicate name error - provide helpful guidance
                    errorMessage = `A tracker with the name "${data.name}" already exists. Please choose a different name.`;
                } else if (response.status === 400) {
                    // Validation error
                    errorMessage = result.error || 'Please check your input and try again.';
                }
                
                return {
                    success: false,
                    message: errorMessage
                };
            }
        } catch (error) {
            console.error('API request failed:', error);
            return {
                success: false,
                message: 'Network error. Please check your connection.'
            };
        }
    }
    
    /**
     * Set submit button state
     * @param {string} state - 'normal', 'loading', or 'success'
     */
    setSubmitButtonState(state) {
        if (!this.submitButton) return;
        
        switch (state) {
            case 'loading':
                // Use global feedback manager if available
                if (window.feedbackManager && window.feedbackManager.showLoading) {
                    window.feedbackManager.showLoading(this.submitButton, {
                        text: 'Saving...',
                        size: 'small',
                        overlay: false,
                        spinner: true
                    });
                } else {
                    // Fallback to original implementation
                    this.submitButton.disabled = true;
                    this.submitButton.innerHTML = `
                        <div class="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                        Saving...
                    `;
                }
                break;
            case 'success':
                // Use global feedback manager if available
                if (window.feedbackManager && window.feedbackManager.hideLoading) {
                    window.feedbackManager.hideLoading(this.submitButton);
                }
                this.submitButton.innerHTML = `
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                    Saved!
                `;
                break;
            case 'normal':
            default:
                // Use global feedback manager if available
                if (window.feedbackManager && window.feedbackManager.hideLoading) {
                    window.feedbackManager.hideLoading(this.submitButton);
                }
                this.submitButton.disabled = false;
                this.submitButton.innerHTML = `
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                    Save Tracker
                `;
                break;
        }
    }
    
    /**
     * Show submission feedback to user
     * @param {string} message - Message to display
     * @param {string} type - 'success' or 'error'
     */
    showSubmissionFeedback(message, type) {
        // Use global feedback manager if available
        if (window.feedbackManager && window.feedbackManager.showToast) {
            window.feedbackManager.showToast(message, type);
            return;
        }
        
        // Try to use global toast system if available
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
     * @param {string} type - 'success' or 'error'
     */
    showTemporaryToast(message, type) {
        // Remove existing toast
        const existingToast = document.getElementById('temp-toast');
        if (existingToast) {
            existingToast.remove();
        }
        
        // Create toast element
        const toast = document.createElement('div');
        toast.id = 'temp-toast';
        toast.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transition-all duration-300 ${
            type === 'success' 
                ? 'bg-green-600 text-white' 
                : 'bg-red-600 text-white'
        }`;
        toast.innerHTML = `
            <div class="flex items-center space-x-2">
                <svg class="w-5 h-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    ${type === 'success' 
                        ? '<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>'
                        : '<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>'
                    }
                </svg>
                <span>${message}</span>
                ${type === 'error' ? '<button onclick="this.parentElement.parentElement.parentElement.remove()" class="ml-2 text-white hover:text-gray-200" aria-label="Close"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg></button>' : ''}
            </div>
        `;
        
        // Add to page
        document.body.appendChild(toast);
        
        // Animate in
        requestAnimationFrame(() => {
            toast.style.transform = 'translateX(100%)';
            requestAnimationFrame(() => {
                toast.style.transform = 'translateX(0)';
            });
        });
        
        // Remove after delay (longer for errors)
        const delay = type === 'error' ? 8000 : 4000;
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }
        }, delay);
    }
    
    /**
     * Reset form to initial state
     */
    resetForm() {
        if (!this.form) return;
        
        // Reset form fields
        this.form.reset();
        
        // Clear all validation errors
        Object.keys(this.validationRules).forEach(fieldName => {
            this.clearFieldError(fieldName);
        });
        
        // Reset color selection to blue (default)
        this.selectColor('blue');
        
        // Reset submit button
        this.setSubmitButtonState('normal');
    }
    
    /**
     * Handle keyboard navigation
     * @param {KeyboardEvent} event - Keyboard event
     */
    handleKeyNavigation(event) {
        // Handle Escape key to close form
        if (event.key === 'Escape') {
            if (window.hideTrackerForm) {
                window.hideTrackerForm();
            }
        }
        
        // Handle Enter key on color options
        if (event.key === 'Enter' && event.target.classList.contains('color-option')) {
            event.preventDefault();
            this.selectColor(event.target.dataset.color);
        }
    }
}

// Form validation utilities
const FormValidation = {
    /**
     * Validate email format
     * @param {string} email - Email to validate
     * @returns {boolean} - True if valid email format
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },
    
    /**
     * Validate phone number format
     * @param {string} phone - Phone number to validate
     * @returns {boolean} - True if valid phone format
     */
    isValidPhone(phone) {
        const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
        return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
    },
    
    /**
     * Validate URL format
     * @param {string} url - URL to validate
     * @returns {boolean} - True if valid URL format
     */
    isValidURL(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },
    
    /**
     * Sanitize input to prevent XSS
     * @param {string} input - Input to sanitize
     * @returns {string} - Sanitized input
     */
    sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }
};

// Initialize form handler when DOM is ready
let trackerFormHandler;

function initializeTrackerFormHandler() {
    if (!trackerFormHandler) {
        trackerFormHandler = new TrackerFormHandler();
        window.trackerFormHandler = trackerFormHandler;
        console.log('TrackerFormHandler: Global instance created');
    }
    return trackerFormHandler;
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initializeTrackerFormHandler();
    });
} else {
    initializeTrackerFormHandler();
}

// Also make the initializer available globally for manual initialization
window.initializeTrackerFormHandler = initializeTrackerFormHandler;

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TrackerFormHandler, FormValidation };
}

// Make available globally
window.TrackerFormHandler = TrackerFormHandler;
window.FormValidation = FormValidation;