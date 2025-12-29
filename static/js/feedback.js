/**
 * Feedback.js - User feedback and loading states for Tracker Web UI
 * 
 * This module provides comprehensive user feedback management including:
 * - Toast notifications for success and error messages
 * - Loading spinners and skeleton screens for data loading
 * - Smooth transitions and animations for state changes
 * - Visual feedback for button clicks and form interactions
 * 
 * Validates: Requirements 6.1, 6.2, 6.3, 6.4
 */

class FeedbackManager {
    constructor() {
        this.toasts = new Map(); // Track active toasts
        this.loadingStates = new Map(); // Track loading states
        this.animationDuration = 300; // Default animation duration in ms
        this.toastContainer = null;
        this.skeletonContainer = null;
        
        this.init();
    }
    
    /**
     * Initialize the feedback system
     */
    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupFeedbackSystem());
        } else {
            this.setupFeedbackSystem();
        }
    }
    
    /**
     * Set up the feedback system components
     */
    setupFeedbackSystem() {
        this.createToastContainer();
        this.createSkeletonContainer();
        this.setupGlobalStyles();
        this.setupButtonFeedback();
        this.setupFormFeedback();
        
        console.log('FeedbackManager: User feedback system initialized');
    }
    
    /**
     * Create toast notification container
     */
    createToastContainer() {
        if (document.getElementById('toast-container')) {
            this.toastContainer = document.getElementById('toast-container');
            return;
        }
        
        this.toastContainer = document.createElement('div');
        this.toastContainer.id = 'toast-container';
        this.toastContainer.className = 'fixed top-4 right-4 z-50 space-y-2 pointer-events-none';
        this.toastContainer.setAttribute('aria-live', 'polite');
        this.toastContainer.setAttribute('aria-label', 'Notifications');
        
        document.body.appendChild(this.toastContainer);
    }
    
    /**
     * Create skeleton screen container
     */
    createSkeletonContainer() {
        if (document.getElementById('skeleton-container')) {
            this.skeletonContainer = document.getElementById('skeleton-container');
            return;
        }
        
        this.skeletonContainer = document.createElement('div');
        this.skeletonContainer.id = 'skeleton-container';
        this.skeletonContainer.className = 'hidden';
        
        document.body.appendChild(this.skeletonContainer);
    }
    
    /**
     * Set up global CSS styles for animations and feedback
     */
    setupGlobalStyles() {
        const styleId = 'feedback-styles';
        if (document.getElementById(styleId)) return;
        
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            /* Toast animations */
            .toast-enter {
                transform: translateX(100%);
                opacity: 0;
            }
            
            .toast-enter-active {
                transform: translateX(0);
                opacity: 1;
                transition: all ${this.animationDuration}ms ease-out;
            }
            
            .toast-exit {
                transform: translateX(0);
                opacity: 1;
            }
            
            .toast-exit-active {
                transform: translateX(100%);
                opacity: 0;
                transition: all ${this.animationDuration}ms ease-in;
            }
            
            /* Button feedback animations */
            .btn-feedback {
                transition: all 0.2s ease-in-out;
            }
            
            .btn-feedback:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            }
            
            .btn-feedback:active {
                transform: translateY(0);
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }
            
            .btn-feedback.loading {
                cursor: not-allowed;
                opacity: 0.7;
            }
            
            /* Skeleton loading animations */
            .skeleton {
                background: linear-gradient(90deg, #374151 25%, #4b5563 50%, #374151 75%);
                background-size: 200% 100%;
                animation: skeleton-loading 1.5s infinite;
            }
            
            @keyframes skeleton-loading {
                0% { background-position: 200% 0; }
                100% { background-position: -200% 0; }
            }
            
            /* Form feedback animations */
            .form-field-error {
                animation: shake 0.5s ease-in-out;
            }
            
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
            
            /* Loading spinner */
            .spinner {
                border: 2px solid transparent;
                border-top: 2px solid currentColor;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            /* Fade transitions */
            .fade-enter {
                opacity: 0;
            }
            
            .fade-enter-active {
                opacity: 1;
                transition: opacity ${this.animationDuration}ms ease-in;
            }
            
            .fade-exit {
                opacity: 1;
            }
            
            .fade-exit-active {
                opacity: 0;
                transition: opacity ${this.animationDuration}ms ease-out;
            }
            
            /* Scale transitions */
            .scale-enter {
                transform: scale(0.95);
                opacity: 0;
            }
            
            .scale-enter-active {
                transform: scale(1);
                opacity: 1;
                transition: all ${this.animationDuration}ms ease-out;
            }
            
            .scale-exit {
                transform: scale(1);
                opacity: 1;
            }
            
            .scale-exit-active {
                transform: scale(0.95);
                opacity: 0;
                transition: all ${this.animationDuration}ms ease-in;
            }
        `;
        
        document.head.appendChild(style);
    }
    
    /**
     * Set up button feedback for all interactive buttons
     */
    setupButtonFeedback() {
        // Add feedback classes to all buttons
        const buttons = document.querySelectorAll('button:not(.no-feedback)');
        buttons.forEach(button => {
            if (!button.classList.contains('btn-feedback')) {
                button.classList.add('btn-feedback');
            }
            
            // Add click feedback
            button.addEventListener('click', (e) => {
                this.addClickFeedback(button);
            });
            
            // Add keyboard feedback
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    this.addClickFeedback(button);
                }
            });
        });
    }
    
    /**
     * Set up form feedback for all form elements
     */
    setupFormFeedback() {
        // Add feedback to form inputs
        const inputs = document.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            // Focus feedback
            input.addEventListener('focus', () => {
                this.addFocusFeedback(input);
            });
            
            // Blur feedback
            input.addEventListener('blur', () => {
                this.removeFocusFeedback(input);
            });
            
            // Input feedback
            input.addEventListener('input', () => {
                this.addInputFeedback(input);
            });
        });
    }
    
    /**
     * Show toast notification
     * @param {string} message - Message to display
     * @param {string} type - 'success', 'error', 'warning', or 'info'
     * @param {Object} options - Additional options
     */
    showToast(message, type = 'info', options = {}) {
        const {
            duration = 4000,
            persistent = false,
            action = null,
            id = null
        } = options;
        
        const toastId = id || `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Remove existing toast with same ID
        if (this.toasts.has(toastId)) {
            this.hideToast(toastId);
        }
        
        // Create toast element
        const toast = this.createToastElement(message, type, toastId, action);
        
        // Add to container
        this.toastContainer.appendChild(toast);
        this.toasts.set(toastId, { element: toast, timer: null });
        
        // Animate in
        requestAnimationFrame(() => {
            toast.classList.remove('toast-enter');
            toast.classList.add('toast-enter-active');
        });
        
        // Auto-hide if not persistent
        if (!persistent && duration > 0) {
            const timer = setTimeout(() => {
                this.hideToast(toastId);
            }, duration);
            
            this.toasts.get(toastId).timer = timer;
        }
        
        return toastId;
    }
    
    /**
     * Create toast element
     * @param {string} message - Toast message
     * @param {string} type - Toast type
     * @param {string} id - Toast ID
     * @param {Object} action - Optional action button
     * @returns {Element} - Toast element
     */
    createToastElement(message, type, id, action) {
        const toast = document.createElement('div');
        toast.id = id;
        toast.className = `toast-enter pointer-events-auto flex items-center p-4 rounded-lg shadow-lg max-w-sm ${this.getToastClasses(type)}`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        
        const icon = this.getToastIcon(type);
        
        toast.innerHTML = `
            <div class="flex items-start space-x-3">
                <div class="flex-shrink-0">
                    ${icon}
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium">${message}</p>
                    ${action ? `
                        <div class="mt-2">
                            <button 
                                class="text-xs underline hover:no-underline focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-white rounded"
                                onclick="${action.onClick}"
                            >
                                ${action.text}
                            </button>
                        </div>
                    ` : ''}
                </div>
                <div class="flex-shrink-0">
                    <button 
                        class="inline-flex text-gray-400 hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-white rounded"
                        onclick="window.feedbackManager.hideToast('${id}')"
                        aria-label="Close notification"
                    >
                        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `;
        
        return toast;
    }
    
    /**
     * Get CSS classes for toast type
     * @param {string} type - Toast type
     * @returns {string} - CSS classes
     */
    getToastClasses(type) {
        const baseClasses = 'text-white';
        
        switch (type) {
            case 'success':
                return `${baseClasses} bg-green-600`;
            case 'error':
                return `${baseClasses} bg-red-600`;
            case 'warning':
                return `${baseClasses} bg-yellow-600`;
            case 'info':
            default:
                return `${baseClasses} bg-blue-600`;
        }
    }
    
    /**
     * Get icon for toast type
     * @param {string} type - Toast type
     * @returns {string} - SVG icon HTML
     */
    getToastIcon(type) {
        const iconClass = 'w-5 h-5';
        
        switch (type) {
            case 'success':
                return `
                    <svg class="${iconClass} text-green-300" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                    </svg>
                `;
            case 'error':
                return `
                    <svg class="${iconClass} text-red-300" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                    </svg>
                `;
            case 'warning':
                return `
                    <svg class="${iconClass} text-yellow-300" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                    </svg>
                `;
            case 'info':
            default:
                return `
                    <svg class="${iconClass} text-blue-300" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                    </svg>
                `;
        }
    }
    
    /**
     * Hide toast notification
     * @param {string} toastId - ID of toast to hide
     */
    hideToast(toastId) {
        const toastData = this.toasts.get(toastId);
        if (!toastData) return;
        
        const { element, timer } = toastData;
        
        // Clear timer
        if (timer) {
            clearTimeout(timer);
        }
        
        // Animate out
        element.classList.remove('toast-enter-active');
        element.classList.add('toast-exit', 'toast-exit-active');
        
        // Remove after animation
        setTimeout(() => {
            if (element.parentNode) {
                element.parentNode.removeChild(element);
            }
            this.toasts.delete(toastId);
        }, this.animationDuration);
    }
    
    /**
     * Hide all toast notifications
     */
    hideAllToasts() {
        this.toasts.forEach((_, toastId) => {
            this.hideToast(toastId);
        });
    }
    
    /**
     * Show loading spinner on element
     * @param {Element|string} target - Target element or selector
     * @param {Object} options - Loading options
     */
    showLoading(target, options = {}) {
        const element = typeof target === 'string' ? document.querySelector(target) : target;
        if (!element) return;
        
        const {
            text = 'Loading...',
            size = 'medium',
            overlay = false,
            spinner = true
        } = options;
        
        const loadingId = `loading-${Date.now()}`;
        element.setAttribute('data-loading-id', loadingId);
        
        if (overlay) {
            this.showLoadingOverlay(element, text, size, spinner, loadingId);
        } else {
            this.showInlineLoading(element, text, size, spinner, loadingId);
        }
        
        this.loadingStates.set(loadingId, { element, options });
    }
    
    /**
     * Show loading overlay on element
     * @param {Element} element - Target element
     * @param {string} text - Loading text
     * @param {string} size - Spinner size
     * @param {boolean} spinner - Show spinner
     * @param {string} loadingId - Loading ID
     */
    showLoadingOverlay(element, text, size, spinner, loadingId) {
        const overlay = document.createElement('div');
        overlay.id = `overlay-${loadingId}`;
        overlay.className = 'absolute inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-10 fade-enter';
        
        const spinnerSize = this.getSpinnerSize(size);
        
        overlay.innerHTML = `
            <div class="text-center text-white">
                ${spinner ? `
                    <div class="spinner ${spinnerSize} mx-auto mb-2"></div>
                ` : ''}
                <p class="text-sm">${text}</p>
            </div>
        `;
        
        // Make element relative if not already positioned
        const computedStyle = window.getComputedStyle(element);
        if (computedStyle.position === 'static') {
            element.style.position = 'relative';
            element.setAttribute('data-position-changed', 'true');
        }
        
        element.appendChild(overlay);
        
        // Animate in
        requestAnimationFrame(() => {
            overlay.classList.remove('fade-enter');
            overlay.classList.add('fade-enter-active');
        });
    }
    
    /**
     * Show inline loading in element
     * @param {Element} element - Target element
     * @param {string} text - Loading text
     * @param {string} size - Spinner size
     * @param {boolean} spinner - Show spinner
     * @param {string} loadingId - Loading ID
     */
    showInlineLoading(element, text, size, spinner, loadingId) {
        // Store original content
        element.setAttribute('data-original-content', element.innerHTML);
        element.setAttribute('data-original-disabled', element.disabled || false);
        
        const spinnerSize = this.getSpinnerSize(size);
        
        element.innerHTML = `
            <div class="flex items-center justify-center space-x-2">
                ${spinner ? `
                    <div class="spinner ${spinnerSize}"></div>
                ` : ''}
                <span>${text}</span>
            </div>
        `;
        
        // Disable if it's a button or input
        if (element.tagName === 'BUTTON' || element.tagName === 'INPUT') {
            element.disabled = true;
            element.classList.add('loading');
        }
    }
    
    /**
     * Get spinner size classes
     * @param {string} size - Size name
     * @returns {string} - CSS classes
     */
    getSpinnerSize(size) {
        switch (size) {
            case 'small':
                return 'w-4 h-4';
            case 'large':
                return 'w-8 h-8';
            case 'medium':
            default:
                return 'w-6 h-6';
        }
    }
    
    /**
     * Hide loading state
     * @param {Element|string} target - Target element or selector
     */
    hideLoading(target) {
        const element = typeof target === 'string' ? document.querySelector(target) : target;
        if (!element) return;
        
        const loadingId = element.getAttribute('data-loading-id');
        if (!loadingId) return;
        
        const loadingData = this.loadingStates.get(loadingId);
        if (!loadingData) return;
        
        const { options } = loadingData;
        
        if (options.overlay) {
            this.hideLoadingOverlay(element, loadingId);
        } else {
            this.hideInlineLoading(element);
        }
        
        element.removeAttribute('data-loading-id');
        this.loadingStates.delete(loadingId);
    }
    
    /**
     * Hide loading overlay
     * @param {Element} element - Target element
     * @param {string} loadingId - Loading ID
     */
    hideLoadingOverlay(element, loadingId) {
        const overlay = document.getElementById(`overlay-${loadingId}`);
        if (!overlay) return;
        
        // Animate out
        overlay.classList.remove('fade-enter-active');
        overlay.classList.add('fade-exit', 'fade-exit-active');
        
        // Remove after animation
        setTimeout(() => {
            if (overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
            
            // Restore position if we changed it
            if (element.getAttribute('data-position-changed')) {
                element.style.position = '';
                element.removeAttribute('data-position-changed');
            }
        }, this.animationDuration);
    }
    
    /**
     * Hide inline loading
     * @param {Element} element - Target element
     */
    hideInlineLoading(element) {
        // Restore original content
        const originalContent = element.getAttribute('data-original-content');
        const originalDisabled = element.getAttribute('data-original-disabled') === 'true';
        
        if (originalContent) {
            element.innerHTML = originalContent;
            element.removeAttribute('data-original-content');
        }
        
        // Restore disabled state
        if (element.tagName === 'BUTTON' || element.tagName === 'INPUT') {
            element.disabled = originalDisabled;
            element.classList.remove('loading');
            element.removeAttribute('data-original-disabled');
        }
    }
    
    /**
     * Show skeleton screen
     * @param {Element|string} target - Target element or selector
     * @param {Object} options - Skeleton options
     */
    showSkeleton(target, options = {}) {
        const element = typeof target === 'string' ? document.querySelector(target) : target;
        if (!element) return;
        
        const {
            lines = 3,
            height = '1rem',
            spacing = '0.5rem',
            animated = true
        } = options;
        
        // Store original content
        element.setAttribute('data-original-content', element.innerHTML);
        
        // Create skeleton HTML
        const skeletonLines = Array.from({ length: lines }, (_, index) => {
            const width = index === lines - 1 ? '75%' : '100%'; // Last line shorter
            return `
                <div 
                    class="skeleton rounded ${animated ? '' : 'bg-gray-600'}" 
                    style="height: ${height}; width: ${width}; margin-bottom: ${index < lines - 1 ? spacing : '0'}"
                ></div>
            `;
        }).join('');
        
        element.innerHTML = `<div class="space-y-2">${skeletonLines}</div>`;
        element.classList.add('fade-enter');
        
        // Animate in
        requestAnimationFrame(() => {
            element.classList.remove('fade-enter');
            element.classList.add('fade-enter-active');
        });
    }
    
    /**
     * Hide skeleton screen
     * @param {Element|string} target - Target element or selector
     */
    hideSkeleton(target) {
        const element = typeof target === 'string' ? document.querySelector(target) : target;
        if (!element) return;
        
        const originalContent = element.getAttribute('data-original-content');
        if (!originalContent) return;
        
        // Animate out
        element.classList.remove('fade-enter-active');
        element.classList.add('fade-exit', 'fade-exit-active');
        
        // Restore content after animation
        setTimeout(() => {
            element.innerHTML = originalContent;
            element.removeAttribute('data-original-content');
            element.classList.remove('fade-exit', 'fade-exit-active');
        }, this.animationDuration);
    }
    
    /**
     * Add click feedback to button
     * @param {Element} button - Button element
     */
    addClickFeedback(button) {
        // Add ripple effect
        const ripple = document.createElement('span');
        ripple.className = 'absolute inset-0 rounded-lg bg-white bg-opacity-20 scale-0';
        ripple.style.animation = 'ripple 0.6s linear';
        
        // Make button relative if not already
        const computedStyle = window.getComputedStyle(button);
        if (computedStyle.position === 'static') {
            button.style.position = 'relative';
        }
        
        button.appendChild(ripple);
        
        // Remove ripple after animation
        setTimeout(() => {
            if (ripple.parentNode) {
                ripple.parentNode.removeChild(ripple);
            }
        }, 600);
        
        // Add ripple animation if not exists
        if (!document.getElementById('ripple-animation')) {
            const style = document.createElement('style');
            style.id = 'ripple-animation';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    /**
     * Add focus feedback to form element
     * @param {Element} element - Form element
     */
    addFocusFeedback(element) {
        element.classList.add('ring-2', 'ring-blue-500', 'border-transparent');
        
        // Add glow effect
        element.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.1)';
    }
    
    /**
     * Remove focus feedback from form element
     * @param {Element} element - Form element
     */
    removeFocusFeedback(element) {
        element.classList.remove('ring-2', 'ring-blue-500', 'border-transparent');
        element.style.boxShadow = '';
    }
    
    /**
     * Add input feedback to form element
     * @param {Element} element - Form element
     */
    addInputFeedback(element) {
        // Add subtle scale animation
        element.style.transform = 'scale(1.01)';
        
        setTimeout(() => {
            element.style.transform = '';
        }, 150);
    }
    
    /**
     * Show form field error with animation
     * @param {Element} field - Form field element
     * @param {string} message - Error message
     */
    showFieldError(field, message) {
        // Add error styling
        field.classList.add('border-red-500', 'form-field-error');
        field.classList.remove('border-gray-600');
        
        // Find or create error message element
        let errorElement = field.parentNode.querySelector('.field-error');
        if (!errorElement) {
            errorElement = document.createElement('p');
            errorElement.className = 'field-error text-red-400 text-sm mt-1';
            field.parentNode.appendChild(errorElement);
        }
        
        errorElement.textContent = message;
        errorElement.classList.add('fade-enter');
        
        // Animate in
        requestAnimationFrame(() => {
            errorElement.classList.remove('fade-enter');
            errorElement.classList.add('fade-enter-active');
        });
        
        // Remove shake animation after it completes
        setTimeout(() => {
            field.classList.remove('form-field-error');
        }, 500);
    }
    
    /**
     * Hide form field error
     * @param {Element} field - Form field element
     */
    hideFieldError(field) {
        // Remove error styling
        field.classList.remove('border-red-500');
        field.classList.add('border-gray-600');
        
        // Hide error message
        const errorElement = field.parentNode.querySelector('.field-error');
        if (errorElement) {
            errorElement.classList.remove('fade-enter-active');
            errorElement.classList.add('fade-exit', 'fade-exit-active');
            
            setTimeout(() => {
                if (errorElement.parentNode) {
                    errorElement.parentNode.removeChild(errorElement);
                }
            }, this.animationDuration);
        }
    }
    
    /**
     * Show success feedback for form field
     * @param {Element} field - Form field element
     */
    showFieldSuccess(field) {
        field.classList.add('border-green-500');
        field.classList.remove('border-gray-600', 'border-red-500');
        
        // Add checkmark icon temporarily
        const checkmark = document.createElement('div');
        checkmark.className = 'absolute right-2 top-1/2 transform -translate-y-1/2 text-green-500';
        checkmark.innerHTML = `
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
            </svg>
        `;
        
        // Make parent relative if needed
        const parent = field.parentNode;
        if (window.getComputedStyle(parent).position === 'static') {
            parent.style.position = 'relative';
        }
        
        parent.appendChild(checkmark);
        
        // Remove after delay
        setTimeout(() => {
            if (checkmark.parentNode) {
                checkmark.parentNode.removeChild(checkmark);
            }
            field.classList.remove('border-green-500');
            field.classList.add('border-gray-600');
        }, 2000);
    }
}

// Global utility functions
const FeedbackUtils = {
    /**
     * Debounce function calls
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function} - Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    /**
     * Throttle function calls
     * @param {Function} func - Function to throttle
     * @param {number} limit - Time limit in ms
     * @returns {Function} - Throttled function
     */
    throttle(func, limit) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// Initialize feedback manager when DOM is ready
let feedbackManager;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        feedbackManager = new FeedbackManager();
        window.feedbackManager = feedbackManager;
    });
} else {
    feedbackManager = new FeedbackManager();
    window.feedbackManager = feedbackManager;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { FeedbackManager, FeedbackUtils };
}

// Make available globally
window.FeedbackManager = FeedbackManager;
window.FeedbackUtils = FeedbackUtils;

// Global convenience functions
window.showToast = (message, type, options) => {
    if (window.feedbackManager) {
        return window.feedbackManager.showToast(message, type, options);
    }
};

window.showLoading = (target, options) => {
    if (window.feedbackManager) {
        window.feedbackManager.showLoading(target, options);
    }
};

window.hideLoading = (target) => {
    if (window.feedbackManager) {
        window.feedbackManager.hideLoading(target);
    }
};

window.showSkeleton = (target, options) => {
    if (window.feedbackManager) {
        window.feedbackManager.showSkeleton(target, options);
    }
};

window.hideSkeleton = (target) => {
    if (window.feedbackManager) {
        window.feedbackManager.hideSkeleton(target);
    }
};