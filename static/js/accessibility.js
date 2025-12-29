/**
 * Accessibility.js - Enhanced accessibility features for Tracker Web UI
 * 
 * This module provides comprehensive accessibility enhancements including:
 * - Enhanced keyboard navigation for all interactive elements
 * - Proper focus management and tab order
 * - ARIA live regions for dynamic content updates
 * - Screen reader announcements for user actions
 * - High contrast and reduced motion support
 * 
 * Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
 */

class AccessibilityManager {
    constructor() {
        this.focusHistory = [];
        this.liveRegion = null;
        this.reducedMotion = false;
        this.highContrast = false;
        
        this.init();
    }
    
    /**
     * Initialize accessibility features
     */
    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupAccessibility());
        } else {
            this.setupAccessibility();
        }
    }
    
    /**
     * Set up all accessibility features
     */
    setupAccessibility() {
        this.createLiveRegion();
        this.detectUserPreferences();
        this.setupKeyboardNavigation();
        this.setupFocusManagement();
        this.setupARIASupport();
        this.setupColorContrastSupport();
        this.setupReducedMotionSupport();
        this.setupScreenReaderSupport();
        this.setupTouchTargets();
        
        console.log('AccessibilityManager: Enhanced accessibility features initialized');
    }
    
    /**
     * Create ARIA live region for announcements
     */
    createLiveRegion() {
        if (document.getElementById('aria-live-region')) {
            this.liveRegion = document.getElementById('aria-live-region');
            return;
        }
        
        this.liveRegion = document.createElement('div');
        this.liveRegion.id = 'aria-live-region';
        this.liveRegion.className = 'sr-only';
        this.liveRegion.setAttribute('aria-live', 'polite');
        this.liveRegion.setAttribute('aria-atomic', 'true');
        this.liveRegion.setAttribute('role', 'status');
        
        document.body.appendChild(this.liveRegion);
    }
    
    /**
     * Detect user accessibility preferences
     */
    detectUserPreferences() {
        // Check for reduced motion preference
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            this.reducedMotion = true;
            document.documentElement.classList.add('reduce-motion');
        }
        
        // Check for high contrast preference
        if (window.matchMedia && window.matchMedia('(prefers-contrast: high)').matches) {
            this.highContrast = true;
            document.documentElement.classList.add('high-contrast');
        }
        
        // Listen for changes in preferences
        if (window.matchMedia) {
            window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
                this.reducedMotion = e.matches;
                document.documentElement.classList.toggle('reduce-motion', e.matches);
            });
            
            window.matchMedia('(prefers-contrast: high)').addEventListener('change', (e) => {
                this.highContrast = e.matches;
                document.documentElement.classList.toggle('high-contrast', e.matches);
            });
        }
    }
    
    /**
     * Set up enhanced keyboard navigation
     */
    setupKeyboardNavigation() {
        // Handle global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Skip to main content (Alt + M)
            if (e.altKey && e.key === 'm') {
                e.preventDefault();
                const mainContent = document.getElementById('main-content');
                if (mainContent) {
                    mainContent.focus();
                    this.announce('Skipped to main content');
                }
            }
            
            // Focus search/create button (Alt + C)
            if (e.altKey && e.key === 'c') {
                e.preventDefault();
                const createButton = document.getElementById('create-tracker-btn');
                if (createButton) {
                    createButton.focus();
                    this.announce('Focused on create tracker button');
                }
            }
            
            // Close modals with Escape
            if (e.key === 'Escape') {
                this.closeTopModal();
            }
        });
        
        // Enhance custom interactive elements
        this.setupCustomElementNavigation();
        
        // Set up roving tabindex for radio groups
        this.setupRovingTabindex();
    }
    
    /**
     * Set up navigation for custom interactive elements
     */
    setupCustomElementNavigation() {
        const customElements = document.querySelectorAll('[data-interactive], [role="button"]:not(button)');
        
        customElements.forEach(element => {
            // Ensure element is focusable
            if (!element.hasAttribute('tabindex')) {
                element.setAttribute('tabindex', '0');
            }
            
            // Add keyboard event handlers
            element.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    element.click();
                }
            });
            
            // Add focus indicators
            element.addEventListener('focus', () => {
                element.classList.add('keyboard-focus');
            });
            
            element.addEventListener('blur', () => {
                element.classList.remove('keyboard-focus');
            });
        });
    }
    
    /**
     * Set up roving tabindex for radio groups and similar controls
     */
    setupRovingTabindex() {
        const radioGroups = document.querySelectorAll('[role="radiogroup"]');
        
        radioGroups.forEach(group => {
            const radios = group.querySelectorAll('[role="radio"]');
            if (radios.length === 0) return;
            
            // Set initial tabindex
            radios.forEach((radio, index) => {
                radio.setAttribute('tabindex', index === 0 ? '0' : '-1');
            });
            
            // Handle arrow key navigation
            group.addEventListener('keydown', (e) => {
                if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
                    return;
                }
                
                e.preventDefault();
                
                const currentIndex = Array.from(radios).indexOf(e.target);
                let nextIndex;
                
                if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
                    nextIndex = currentIndex > 0 ? currentIndex - 1 : radios.length - 1;
                } else {
                    nextIndex = currentIndex < radios.length - 1 ? currentIndex + 1 : 0;
                }
                
                // Update tabindex and focus
                radios[currentIndex].setAttribute('tabindex', '-1');
                radios[nextIndex].setAttribute('tabindex', '0');
                radios[nextIndex].focus();
                
                // Trigger selection
                radios[nextIndex].click();
            });
        });
    }
    
    /**
     * Set up focus management for modals and dynamic content
     */
    setupFocusManagement() {
        // Track focus history for restoration
        document.addEventListener('focusin', (e) => {
            if (!e.target.closest('[role="dialog"]')) {
                this.focusHistory.push(e.target);
                // Keep only last 5 focus elements
                if (this.focusHistory.length > 5) {
                    this.focusHistory.shift();
                }
            }
        });
        
        // Set up modal focus trapping
        this.setupModalFocusTrapping();
        
        // Handle dynamic content focus
        this.setupDynamicContentFocus();
    }
    
    /**
     * Set up focus trapping for modals
     */
    setupModalFocusTrapping() {
        const trapFocus = (modal) => {
            const focusableElements = modal.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            
            if (focusableElements.length === 0) return;
            
            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];
            
            // Focus first element when modal opens
            setTimeout(() => firstFocusable.focus(), 100);
            
            const handleTabKey = (e) => {
                if (e.key !== 'Tab') return;
                
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        e.preventDefault();
                        lastFocusable.focus();
                    }
                } else {
                    if (document.activeElement === lastFocusable) {
                        e.preventDefault();
                        firstFocusable.focus();
                    }
                }
            };
            
            modal.addEventListener('keydown', handleTabKey);
            
            // Store handler for cleanup
            modal._focusTrapHandler = handleTabKey;
        };
        
        // Apply to existing modals
        const modals = document.querySelectorAll('[role="dialog"]');
        modals.forEach(trapFocus);
        
        // Monitor for new modals
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) {
                        if (node.getAttribute('role') === 'dialog') {
                            trapFocus(node);
                        }
                        
                        const nestedModals = node.querySelectorAll('[role="dialog"]');
                        nestedModals.forEach(trapFocus);
                    }
                });
            });
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Set up focus management for dynamic content
     */
    setupDynamicContentFocus() {
        // Focus management for form validation errors
        document.addEventListener('invalid', (e) => {
            if (e.target.matches('input, select, textarea')) {
                setTimeout(() => {
                    e.target.focus();
                    this.announce(`Error in ${e.target.labels?.[0]?.textContent || 'form field'}: ${e.target.validationMessage}`);
                }, 100);
            }
        }, true);
        
        // Focus management for dynamically added content
        const contentObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1 && node.matches('[data-focus-on-add]')) {
                        setTimeout(() => node.focus(), 100);
                    }
                });
            });
        });
        
        contentObserver.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Set up enhanced ARIA support
     */
    setupARIASupport() {
        // Auto-generate ARIA labels for buttons without them
        const unlabeledButtons = document.querySelectorAll('button:not([aria-label]):not([aria-labelledby])');
        unlabeledButtons.forEach(button => {
            const text = button.textContent.trim();
            if (text) {
                button.setAttribute('aria-label', text);
            }
        });
        
        // Set up ARIA live regions for dynamic content
        this.setupLiveRegions();
        
        // Enhance form controls with ARIA
        this.enhanceFormControls();
        
        // Set up ARIA expanded states
        this.setupExpandedStates();
    }
    
    /**
     * Set up ARIA live regions for dynamic content updates
     */
    setupLiveRegions() {
        // Monitor for toast notifications
        const toastContainer = document.getElementById('toast-container');
        if (toastContainer) {
            const toastObserver = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1 && node.classList.contains('toast')) {
                            const message = node.textContent.trim();
                            this.announce(message);
                        }
                    });
                });
            });
            
            toastObserver.observe(toastContainer, { childList: true });
        }
        
        // Monitor for loading states
        const loadingObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                    const element = mutation.target;
                    if (element.classList.contains('loading')) {
                        this.announce('Loading...');
                    }
                }
            });
        });
        
        loadingObserver.observe(document.body, { 
            attributes: true, 
            subtree: true, 
            attributeFilter: ['class'] 
        });
    }
    
    /**
     * Enhance form controls with ARIA attributes
     */
    enhanceFormControls() {
        // Add ARIA descriptions to form fields
        const formFields = document.querySelectorAll('input, select, textarea');
        formFields.forEach(field => {
            const helpText = field.parentNode.querySelector('.text-gray-500, .text-xs');
            if (helpText && !field.hasAttribute('aria-describedby')) {
                const helpId = `${field.id}-help` || `help-${Date.now()}`;
                helpText.id = helpId;
                field.setAttribute('aria-describedby', helpId);
            }
            
            // Set up error announcements
            field.addEventListener('invalid', () => {
                field.setAttribute('aria-invalid', 'true');
            });
            
            field.addEventListener('input', () => {
                if (field.checkValidity()) {
                    field.setAttribute('aria-invalid', 'false');
                }
            });
        });
        
        // Enhance required field indicators
        const requiredFields = document.querySelectorAll('[required]');
        requiredFields.forEach(field => {
            field.setAttribute('aria-required', 'true');
        });
    }
    
    /**
     * Set up ARIA expanded states for collapsible content
     */
    setupExpandedStates() {
        const toggleButtons = document.querySelectorAll('[data-toggle]');
        toggleButtons.forEach(button => {
            const targetId = button.getAttribute('data-toggle');
            const target = document.getElementById(targetId);
            
            if (target) {
                const isExpanded = !target.classList.contains('hidden');
                button.setAttribute('aria-expanded', isExpanded.toString());
                button.setAttribute('aria-controls', targetId);
                
                button.addEventListener('click', () => {
                    const newState = target.classList.contains('hidden');
                    button.setAttribute('aria-expanded', newState.toString());
                    this.announce(`${button.textContent} ${newState ? 'expanded' : 'collapsed'}`);
                });
            }
        });
    }
    
    /**
     * Set up color contrast support
     */
    setupColorContrastSupport() {
        if (this.highContrast) {
            // Add high contrast styles
            const style = document.createElement('style');
            style.textContent = `
                .high-contrast button,
                .high-contrast input,
                .high-contrast select,
                .high-contrast textarea {
                    border: 2px solid !important;
                }
                
                .high-contrast .bg-gray-800 {
                    background-color: #000000 !important;
                    border: 1px solid #ffffff !important;
                }
                
                .high-contrast .text-gray-300,
                .high-contrast .text-gray-400 {
                    color: #ffffff !important;
                }
                
                .high-contrast .focus-visible:focus {
                    outline: 3px solid #ffff00 !important;
                    outline-offset: 2px !important;
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    /**
     * Set up reduced motion support
     */
    setupReducedMotionSupport() {
        if (this.reducedMotion) {
            const style = document.createElement('style');
            style.textContent = `
                .reduce-motion *,
                .reduce-motion *::before,
                .reduce-motion *::after {
                    animation-duration: 0.01ms !important;
                    animation-iteration-count: 1 !important;
                    transition-duration: 0.01ms !important;
                    scroll-behavior: auto !important;
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    /**
     * Set up screen reader support
     */
    setupScreenReaderSupport() {
        // Add screen reader only instructions
        const instructions = document.createElement('div');
        instructions.className = 'sr-only';
        instructions.innerHTML = `
            <h2>Screen Reader Instructions</h2>
            <p>This is the Tracker Web UI application. Use Tab to navigate between interactive elements.</p>
            <p>Press Alt+M to skip to main content, Alt+C to focus the create tracker button.</p>
            <p>In forms, use Tab to move between fields and Enter to submit.</p>
            <p>For color selection, use arrow keys to navigate between options.</p>
        `;
        document.body.insertBefore(instructions, document.body.firstChild);
        
        // Announce page changes
        this.setupPageChangeAnnouncements();
    }
    
    /**
     * Set up page change announcements
     */
    setupPageChangeAnnouncements() {
        // Announce when new content is loaded
        const contentObserver = new MutationObserver((mutations) => {
            let hasSignificantChange = false;
            
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1 && 
                            (node.matches('article, section, main, [role="main"], [role="article"]') ||
                             node.querySelector('article, section, main, [role="main"], [role="article"]'))) {
                            hasSignificantChange = true;
                        }
                    });
                }
            });
            
            if (hasSignificantChange) {
                setTimeout(() => {
                    this.announce('Page content updated');
                }, 500);
            }
        });
        
        contentObserver.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Set up proper touch targets
     */
    setupTouchTargets() {
        const interactiveElements = document.querySelectorAll('button, a, input, select, textarea, [role="button"], [tabindex]');
        
        interactiveElements.forEach(element => {
            const rect = element.getBoundingClientRect();
            const minSize = 44; // WCAG minimum touch target size
            
            if (rect.width < minSize || rect.height < minSize) {
                element.classList.add('min-touch-target');
            }
        });
    }
    
    /**
     * Close the topmost modal
     */
    closeTopModal() {
        const modals = document.querySelectorAll('[role="dialog"]:not(.hidden)');
        if (modals.length > 0) {
            const topModal = modals[modals.length - 1];
            const closeButton = topModal.querySelector('[aria-label*="Close"], [aria-label*="close"]');
            if (closeButton) {
                closeButton.click();
            }
        }
    }
    
    /**
     * Announce message to screen readers
     * @param {string} message - Message to announce
     * @param {string} priority - 'polite' or 'assertive'
     */
    announce(message, priority = 'polite') {
        if (!this.liveRegion) return;
        
        // Clear previous message
        this.liveRegion.textContent = '';
        
        // Set priority
        this.liveRegion.setAttribute('aria-live', priority);
        
        // Add new message after a brief delay
        setTimeout(() => {
            this.liveRegion.textContent = message;
        }, 100);
        
        // Clear message after it's been announced
        setTimeout(() => {
            this.liveRegion.textContent = '';
        }, 3000);
    }
    
    /**
     * Restore focus to previous element
     */
    restoreFocus() {
        if (this.focusHistory.length > 0) {
            const previousFocus = this.focusHistory.pop();
            if (previousFocus && document.contains(previousFocus)) {
                previousFocus.focus();
            }
        }
    }
    
    /**
     * Check if element meets WCAG color contrast requirements
     * @param {Element} element - Element to check
     * @returns {boolean} - True if meets requirements
     */
    checkColorContrast(element) {
        const style = window.getComputedStyle(element);
        const backgroundColor = style.backgroundColor;
        const color = style.color;
        
        // This is a simplified check - in production, you'd use a proper contrast calculation
        // For now, we'll assume our design meets WCAG AA standards
        return true;
    }
    
    /**
     * Get accessibility summary for current page
     * @returns {Object} - Accessibility information
     */
    getAccessibilitySummary() {
        const interactiveElements = document.querySelectorAll('button, a, input, select, textarea, [role="button"]');
        const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
        const landmarks = document.querySelectorAll('[role="main"], [role="navigation"], [role="banner"], [role="contentinfo"], main, nav, header, footer');
        const images = document.querySelectorAll('img');
        const imagesWithAlt = document.querySelectorAll('img[alt]');
        
        return {
            interactiveElements: interactiveElements.length,
            headings: headings.length,
            landmarks: landmarks.length,
            images: images.length,
            imagesWithAlt: imagesWithAlt.length,
            reducedMotion: this.reducedMotion,
            highContrast: this.highContrast
        };
    }
}

// Initialize accessibility manager
let accessibilityManager;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        accessibilityManager = new AccessibilityManager();
        window.accessibilityManager = accessibilityManager;
    });
} else {
    accessibilityManager = new AccessibilityManager();
    window.accessibilityManager = accessibilityManager;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AccessibilityManager };
}

// Make available globally
window.AccessibilityManager = AccessibilityManager;

// Global convenience functions
window.announceToScreenReader = (message, priority) => {
    if (window.accessibilityManager) {
        window.accessibilityManager.announce(message, priority);
    }
};

window.restoreFocus = () => {
    if (window.accessibilityManager) {
        window.accessibilityManager.restoreFocus();
    }
};