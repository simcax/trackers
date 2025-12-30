/**
 * Charts.js - Mini chart visualization for Tracker Web UI
 * 
 * This module provides trend visualization functionality for tracker cards including:
 * - SVG-based mini trend lines for each tracker
 * - Chart data generation from recent tracker values
 * - Responsive and accessible chart rendering
 * - Dark theme styling to match mobile design aesthetic
 * 
 * Validates: Requirements 1.4, 7.5
 */

class TrackerCharts {
    constructor() {
        this.defaultOptions = {
            width: 64,
            height: 32,
            strokeWidth: 2,
            strokeColor: 'currentColor',
            fillColor: 'none',
            padding: 2,
            maxDataPoints: 7, // Show last 7 data points for mini charts
            smoothing: 0.2, // Curve smoothing factor
            responsive: true,
            accessible: true
        };
        
        this.colorMap = {
            red: '#ef4444',
            blue: '#3b82f6',
            green: '#10b981',
            yellow: '#f59e0b',
            purple: '#8b5cf6',
            pink: '#ec4899',
            indigo: '#6366f1',
            teal: '#14b8a6'
        };
        
        this.init();
    }
    
    /**
     * Initialize the charts system
     */
    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.renderAllCharts());
        } else {
            this.renderAllCharts();
        }
        
        // Set up resize handler for responsive charts
        if (this.defaultOptions.responsive) {
            window.addEventListener('resize', this.debounce(() => {
                this.renderAllCharts();
            }, 250));
        }
        
        console.log('TrackerCharts: Mini chart visualization initialized');
    }
    
    /**
     * Render all mini charts on the page
     */
    renderAllCharts() {
        const chartContainers = document.querySelectorAll('[data-chart-container]');
        
        chartContainers.forEach(container => {
            // Check if container already has a properly rendered chart
            const existingSvg = container.querySelector('svg[viewBox="0 0 64 32"]');
            
            if (existingSvg) {
                // Check if this is a server-rendered chart with actual data
                const hasNoDataText = existingSvg.querySelector('text');
                const hasPlaceholderLine = existingSvg.querySelector('polyline[opacity="0.4"]');
                const hasDataPolyline = existingSvg.querySelector('polyline:not([opacity="0.4"])');
                const hasDataCircles = existingSvg.querySelector('circle');
                
                // If it has "No data" text, it's a placeholder - replace it
                if (hasNoDataText && hasNoDataText.textContent.trim() === 'No data') {
                    this.renderMiniChart(container);
                    return;
                }
                
                // If it has only placeholder line (opacity 0.4), replace it
                if (hasPlaceholderLine && !hasDataPolyline && !hasDataCircles) {
                    this.renderMiniChart(container);
                    return;
                }
                
                // If it has real data (polylines without opacity 0.4 or circles), preserve it
                if (hasDataPolyline || hasDataCircles) {
                    return; // Skip rendering for this container
                }
                
                // Fallback: if we can't determine, try to render
                this.renderMiniChart(container);
            } else {
                // No existing SVG, render new chart
                this.renderMiniChart(container);
            }
        });
    }
    
    /**
     * Render a mini chart in the specified container
     * @param {Element} container - Container element for the chart
     * @param {Object} options - Chart options (optional)
     */
    renderMiniChart(container, options = {}) {
        const config = { ...this.defaultOptions, ...options };
        
        // Get tracker data from container or parent element
        const trackerData = this.extractTrackerData(container);
        
        if (!trackerData || !trackerData.values || trackerData.values.length === 0) {
            this.renderEmptyChart(container, config);
            return;
        }
        
        // Generate chart SVG
        const chartSvg = this.generateMiniChartSVG(trackerData, config);
        
        // Update container
        container.innerHTML = chartSvg;
        
        // Add accessibility attributes
        if (config.accessible) {
            this.addAccessibilityAttributes(container, trackerData);
        }
    }
    
    /**
     * Update an existing chart SVG element
     * @param {Element} svg - Existing SVG element
     * @param {Element} trackerCard - Parent tracker card element
     */
    updateExistingChart(svg, trackerCard) {
        const trackerData = this.extractTrackerDataFromCard(trackerCard);
        
        if (!trackerData || !trackerData.values || trackerData.values.length === 0) {
            return; // Keep existing placeholder
        }
        
        const config = {
            ...this.defaultOptions,
            strokeColor: this.getTrackerColor(trackerData.color)
        };
        
        // Generate new polyline points
        const points = this.generateChartPoints(trackerData.values, config);
        
        // Update the polyline element
        const polyline = svg.querySelector('polyline');
        if (polyline && points.length > 0) {
            polyline.setAttribute('points', points);
            polyline.setAttribute('stroke', config.strokeColor);
            polyline.setAttribute('stroke-width', config.strokeWidth);
            polyline.setAttribute('fill', config.fillColor);
            polyline.setAttribute('stroke-linecap', 'round');
            polyline.setAttribute('stroke-linejoin', 'round');
        }
        
        // Add accessibility
        this.addAccessibilityToSVG(svg, trackerData);
    }
    
    /**
     * Extract tracker data from container element
     * @param {Element} container - Container element
     * @returns {Object|null} - Tracker data object
     */
    extractTrackerData(container) {
        try {
            // Try to get data from data attributes
            const dataAttr = container.dataset.chartData;
            if (dataAttr) {
                return JSON.parse(dataAttr);
            }
            
            // Try to get data from parent tracker card
            const trackerCard = container.closest('[data-tracker-id]');
            if (trackerCard) {
                return this.extractTrackerDataFromCard(trackerCard);
            }
            
            return null;
        } catch (error) {
            console.warn('TrackerCharts: Error extracting tracker data:', error);
            return null;
        }
    }
    
    /**
     * Extract tracker data from tracker card element
     * @param {Element} trackerCard - Tracker card element
     * @returns {Object|null} - Tracker data object
     */
    extractTrackerDataFromCard(trackerCard) {
        try {
            const trackerId = trackerCard.dataset.trackerId;
            const trackerName = trackerCard.dataset.trackerName || 
                              trackerCard.querySelector('h3')?.textContent?.trim();
            
            // Extract recent values from value badges
            const valueBadges = trackerCard.querySelectorAll('[data-value]');
            const values = Array.from(valueBadges).map(badge => {
                const value = parseFloat(badge.dataset.value);
                const daysAgo = parseInt(badge.dataset.daysAgo) || 0;
                return {
                    value: isNaN(value) ? 0 : value,
                    daysAgo: daysAgo,
                    date: badge.dataset.date || ''
                };
            });
            
            // Sort by daysAgo descending to get chronological order (oldest first for chart)
            // Higher daysAgo = older date, so we want highest daysAgo first
            values.sort((a, b) => b.daysAgo - a.daysAgo);
            
            // Get tracker color from icon or data attribute
            const colorElement = trackerCard.querySelector('[class*="bg-"]');
            let color = 'blue'; // default
            if (colorElement) {
                const classes = colorElement.className.split(' ');
                const colorClass = classes.find(cls => cls.match(/bg-(red|blue|green|yellow|purple|pink|indigo|teal)-/));
                if (colorClass) {
                    color = colorClass.split('-')[1];
                }
            }
            
            return {
                id: trackerId,
                name: trackerName,
                color: color,
                values: values
            };
        } catch (error) {
            console.warn('TrackerCharts: Error extracting data from card:', error);
            return null;
        }
    }
    
    /**
     * Generate mini chart SVG markup
     * @param {Object} trackerData - Tracker data
     * @param {Object} config - Chart configuration
     * @returns {string} - SVG markup
     */
    generateMiniChartSVG(trackerData, config) {
        const points = this.generateChartPoints(trackerData.values, config);
        const strokeColor = this.getTrackerColor(trackerData.color);
        
        if (points.length === 0) {
            return this.generateEmptyChartSVG(config);
        }
        
        return `
            <svg 
                class="w-full h-full text-${trackerData.color}-400" 
                viewBox="0 0 ${config.width} ${config.height}" 
                fill="none" 
                xmlns="http://www.w3.org/2000/svg"
                role="img"
                aria-label="Trend chart for ${trackerData.name}"
            >
                <title>Trend chart for ${trackerData.name}</title>
                <desc>Mini trend visualization showing recent values: ${trackerData.values.map(v => v.value).join(', ')}</desc>
                
                <!-- Trend line -->
                <polyline 
                    points="${points}"
                    stroke="${strokeColor}" 
                    stroke-width="${config.strokeWidth}" 
                    fill="${config.fillColor}"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    opacity="0.9"
                />
                
                <!-- Data points (optional, for better visibility) -->
                ${this.generateDataPoints(trackerData.values, config, strokeColor)}
                
                <!-- Gradient fill area (optional) -->
                ${this.generateGradientFill(points, config, trackerData.color)}
            </svg>
        `;
    }
    
    /**
     * Generate chart points from values
     * @param {Array} values - Array of value objects
     * @param {Object} config - Chart configuration
     * @returns {string} - SVG points string
     */
    generateChartPoints(values, config) {
        if (!values || values.length === 0) {
            return '';
        }
        
        // Take the last N data points
        const dataPoints = values.slice(-config.maxDataPoints);
        
        // Extract numeric values
        const numericValues = dataPoints.map(v => {
            const num = parseFloat(v.value);
            return isNaN(num) ? 0 : num;
        });
        
        if (numericValues.length === 0) {
            return '';
        }
        
        // Calculate value range
        const minValue = Math.min(...numericValues);
        const maxValue = Math.max(...numericValues);
        const valueRange = maxValue - minValue || 1; // Avoid division by zero
        
        // Calculate chart dimensions
        const chartWidth = config.width - (config.padding * 2);
        const chartHeight = config.height - (config.padding * 2);
        
        // Generate points
        const points = numericValues.map((value, index) => {
            const x = config.padding + (index * chartWidth) / Math.max(numericValues.length - 1, 1);
            const y = config.padding + chartHeight - ((value - minValue) / valueRange) * chartHeight;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
        });
        
        return points.join(' ');
    }
    
    /**
     * Generate data points (circles) for better visibility
     * @param {Array} values - Array of value objects
     * @param {Object} config - Chart configuration
     * @param {string} color - Stroke color
     * @returns {string} - SVG circles markup
     */
    generateDataPoints(values, config, color) {
        if (!values || values.length === 0 || values.length < 2) {
            return ''; // Don't show points for single values
        }
        
        const dataPoints = values.slice(-config.maxDataPoints);
        const numericValues = dataPoints.map(v => {
            const num = parseFloat(v.value);
            return isNaN(num) ? 0 : num;
        });
        
        if (numericValues.length === 0) {
            return '';
        }
        
        const minValue = Math.min(...numericValues);
        const maxValue = Math.max(...numericValues);
        const valueRange = maxValue - minValue || 1;
        
        const chartWidth = config.width - (config.padding * 2);
        const chartHeight = config.height - (config.padding * 2);
        
        return numericValues.map((value, index) => {
            const x = config.padding + (index * chartWidth) / Math.max(numericValues.length - 1, 1);
            const y = config.padding + chartHeight - ((value - minValue) / valueRange) * chartHeight;
            
            return `
                <circle 
                    cx="${x.toFixed(1)}" 
                    cy="${y.toFixed(1)}" 
                    r="1.5" 
                    fill="${color}" 
                    opacity="0.8"
                />
            `;
        }).join('');
    }
    
    /**
     * Generate gradient fill area under the line
     * @param {string} points - SVG points string
     * @param {Object} config - Chart configuration
     * @param {string} colorName - Color name (red, blue, etc.)
     * @returns {string} - SVG gradient markup
     */
    generateGradientFill(points, config, colorName) {
        if (!points || points.length === 0) {
            return '';
        }
        
        const gradientId = `gradient-${colorName}-${Date.now()}`;
        const color = this.getTrackerColor(colorName);
        
        // Create path for filled area
        const pointsArray = points.split(' ');
        if (pointsArray.length < 2) {
            return '';
        }
        
        const firstPoint = pointsArray[0];
        const lastPoint = pointsArray[pointsArray.length - 1];
        const [lastX] = lastPoint.split(',');
        const [firstX] = firstPoint.split(',');
        
        const fillPath = `M ${firstX},${config.height - config.padding} L ${points} L ${lastX},${config.height - config.padding} Z`;
        
        return `
            <defs>
                <linearGradient id="${gradientId}" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:${color};stop-opacity:0.3" />
                    <stop offset="100%" style="stop-color:${color};stop-opacity:0.05" />
                </linearGradient>
            </defs>
            <path 
                d="${fillPath}" 
                fill="url(#${gradientId})"
                opacity="0.6"
            />
        `;
    }
    
    /**
     * Generate empty chart SVG
     * @param {Object} config - Chart configuration
     * @returns {string} - Empty chart SVG markup
     */
    generateEmptyChartSVG(config) {
        return `
            <svg 
                class="w-full h-full text-gray-500" 
                viewBox="0 0 ${config.width} ${config.height}" 
                fill="none" 
                xmlns="http://www.w3.org/2000/svg"
                role="img"
                aria-label="No data available for chart"
            >
                <title>No chart data</title>
                <desc>No data points available to display trend</desc>
                
                <!-- Placeholder line -->
                <line 
                    x1="${config.padding}" 
                    y1="${config.height / 2}" 
                    x2="${config.width - config.padding}" 
                    y2="${config.height / 2}" 
                    stroke="currentColor" 
                    stroke-width="1" 
                    stroke-dasharray="2,2"
                    opacity="0.3"
                />
                
                <!-- No data indicator -->
                <text 
                    x="${config.width / 2}" 
                    y="${config.height / 2 + 2}" 
                    text-anchor="middle" 
                    font-size="8" 
                    fill="currentColor" 
                    opacity="0.5"
                >
                    No data
                </text>
            </svg>
        `;
    }
    
    /**
     * Render empty chart in container
     * @param {Element} container - Container element
     * @param {Object} config - Chart configuration
     */
    renderEmptyChart(container, config) {
        container.innerHTML = this.generateEmptyChartSVG(config);
        
        if (config.accessible) {
            container.setAttribute('role', 'img');
            container.setAttribute('aria-label', 'No chart data available');
        }
    }
    
    /**
     * Get color value for tracker
     * @param {string} colorName - Color name (red, blue, etc.)
     * @returns {string} - Hex color value
     */
    getTrackerColor(colorName) {
        return this.colorMap[colorName] || this.colorMap.blue;
    }
    
    /**
     * Add accessibility attributes to chart container
     * @param {Element} container - Chart container
     * @param {Object} trackerData - Tracker data
     */
    addAccessibilityAttributes(container, trackerData) {
        container.setAttribute('role', 'img');
        container.setAttribute('aria-label', `Trend chart for ${trackerData.name}`);
        
        // Add detailed description
        const values = trackerData.values.map(v => v.value).join(', ');
        const description = `Mini trend chart showing recent values: ${values}`;
        container.setAttribute('aria-describedby', `chart-desc-${trackerData.id}`);
        
        // Create hidden description element
        const descElement = document.createElement('div');
        descElement.id = `chart-desc-${trackerData.id}`;
        descElement.className = 'sr-only';
        descElement.textContent = description;
        container.appendChild(descElement);
    }
    
    /**
     * Add accessibility attributes to existing SVG
     * @param {Element} svg - SVG element
     * @param {Object} trackerData - Tracker data
     */
    addAccessibilityToSVG(svg, trackerData) {
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', `Trend chart for ${trackerData.name}`);
        
        // Update or create title and desc elements
        let title = svg.querySelector('title');
        if (!title) {
            title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
            svg.insertBefore(title, svg.firstChild);
        }
        title.textContent = `Trend chart for ${trackerData.name}`;
        
        let desc = svg.querySelector('desc');
        if (!desc) {
            desc = document.createElementNS('http://www.w3.org/2000/svg', 'desc');
            svg.insertBefore(desc, title.nextSibling);
        }
        const values = trackerData.values.map(v => v.value).join(', ');
        desc.textContent = `Mini trend visualization showing recent values: ${values}`;
    }
    
    /**
     * Debounce function for performance optimization
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in milliseconds
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
    }
    
    /**
     * Update chart data for a specific tracker
     * @param {string} trackerId - Tracker ID
     * @param {Array} newValues - New values array
     */
    updateTrackerChart(trackerId, newValues) {
        const trackerCard = document.querySelector(`[data-tracker-id="${trackerId}"]`);
        if (!trackerCard) return;
        
        const chartContainer = trackerCard.querySelector('[data-chart-container]');
        const chartSvg = trackerCard.querySelector('svg[viewBox="0 0 64 32"]');
        
        if (chartContainer) {
            // Update data attribute
            const trackerData = this.extractTrackerDataFromCard(trackerCard);
            if (trackerData) {
                trackerData.values = newValues;
                chartContainer.dataset.chartData = JSON.stringify(trackerData);
                this.renderMiniChart(chartContainer);
            }
        } else if (chartSvg) {
            // Update existing SVG
            this.updateExistingChart(chartSvg, trackerCard);
        }
    }
    
    /**
     * Refresh all charts (useful after data updates)
     */
    refreshAllCharts() {
        this.renderAllCharts();
    }
}

// Utility functions for external use
const TrackerChartsUtils = {
    /**
     * Create a standalone mini chart
     * @param {Element} container - Container element
     * @param {Array} values - Array of numeric values
     * @param {Object} options - Chart options
     */
    createMiniChart(container, values, options = {}) {
        const charts = new TrackerCharts();
        const trackerData = {
            id: 'standalone',
            name: 'Chart',
            color: options.color || 'blue',
            values: values.map((value, index) => ({
                value: value,
                daysAgo: values.length - index - 1,
                date: ''
            }))
        };
        
        const config = { ...charts.defaultOptions, ...options };
        const chartSvg = charts.generateMiniChartSVG(trackerData, config);
        container.innerHTML = chartSvg;
    },
    
    /**
     * Generate chart points for external use
     * @param {Array} values - Array of numeric values
     * @param {Object} options - Chart options
     * @returns {string} - SVG points string
     */
    generatePoints(values, options = {}) {
        const charts = new TrackerCharts();
        const config = { ...charts.defaultOptions, ...options };
        const valueObjects = values.map(v => ({ value: v }));
        return charts.generateChartPoints(valueObjects, config);
    }
};

// Global functions for backward compatibility
window.renderTrackerCharts = function() {
    if (window.trackerCharts) {
        window.trackerCharts.renderAllCharts();
    }
};

window.updateTrackerChart = function(trackerId, values) {
    if (window.trackerCharts) {
        window.trackerCharts.updateTrackerChart(trackerId, values);
    }
};

// Initialize charts when DOM is ready
let trackerCharts;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        trackerCharts = new TrackerCharts();
        window.trackerCharts = trackerCharts;
    });
} else {
    trackerCharts = new TrackerCharts();
    window.trackerCharts = trackerCharts;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TrackerCharts, TrackerChartsUtils };
}

// Make available globally
window.TrackerCharts = TrackerCharts;
window.TrackerChartsUtils = TrackerChartsUtils;