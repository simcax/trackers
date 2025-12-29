/**
 * Color Contrast Checker for WCAG 2.1 AA Compliance
 * 
 * This utility checks if color combinations meet WCAG 2.1 AA standards
 * for normal text (4.5:1) and large text (3:1).
 */

class ColorContrastChecker {
    constructor() {
        this.wcagAANormal = 4.5;
        this.wcagAALarge = 3.0;
    }
    
    /**
     * Convert hex color to RGB
     * @param {string} hex - Hex color code
     * @returns {Object} - RGB values
     */
    hexToRgb(hex) {
        const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        return result ? {
            r: parseInt(result[1], 16),
            g: parseInt(result[2], 16),
            b: parseInt(result[3], 16)
        } : null;
    }
    
    /**
     * Calculate relative luminance
     * @param {Object} rgb - RGB color object
     * @returns {number} - Relative luminance
     */
    getLuminance(rgb) {
        const { r, g, b } = rgb;
        
        const [rs, gs, bs] = [r, g, b].map(c => {
            c = c / 255;
            return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
        });
        
        return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
    }
    
    /**
     * Calculate contrast ratio between two colors
     * @param {string} color1 - First color (hex)
     * @param {string} color2 - Second color (hex)
     * @returns {number} - Contrast ratio
     */
    getContrastRatio(color1, color2) {
        const rgb1 = this.hexToRgb(color1);
        const rgb2 = this.hexToRgb(color2);
        
        if (!rgb1 || !rgb2) return 0;
        
        const lum1 = this.getLuminance(rgb1);
        const lum2 = this.getLuminance(rgb2);
        
        const brightest = Math.max(lum1, lum2);
        const darkest = Math.min(lum1, lum2);
        
        return (brightest + 0.05) / (darkest + 0.05);
    }
    
    /**
     * Check if contrast ratio meets WCAG AA standards
     * @param {number} ratio - Contrast ratio
     * @param {boolean} isLargeText - Whether text is large (18pt+ or 14pt+ bold)
     * @returns {Object} - Compliance result
     */
    checkCompliance(ratio, isLargeText = false) {
        const threshold = isLargeText ? this.wcagAALarge : this.wcagAANormal;
        
        return {
            ratio: ratio,
            passes: ratio >= threshold,
            level: ratio >= 7 ? 'AAA' : ratio >= threshold ? 'AA' : 'Fail',
            threshold: threshold
        };
    }
    
    /**
     * Test our application's color combinations
     * @returns {Array} - Test results
     */
    testApplicationColors() {
        const colorTests = [
            // Background and text combinations used in our app
            { name: 'White text on gray-900 background', bg: '#111827', text: '#ffffff', isLarge: false },
            { name: 'Gray-300 text on gray-900 background', bg: '#111827', text: '#d1d5db', isLarge: false },
            { name: 'Gray-400 text on gray-900 background', bg: '#111827', text: '#9ca3af', isLarge: false },
            { name: 'Gray-500 text on gray-900 background', bg: '#111827', text: '#6b7280', isLarge: false },
            { name: 'White text on gray-800 background', bg: '#1f2937', text: '#ffffff', isLarge: false },
            { name: 'Gray-300 text on gray-800 background', bg: '#1f2937', text: '#d1d5db', isLarge: false },
            { name: 'Gray-400 text on gray-800 background', bg: '#1f2937', text: '#9ca3af', isLarge: false },
            { name: 'White text on gray-700 background', bg: '#374151', text: '#ffffff', isLarge: false },
            { name: 'Gray-300 text on gray-700 background', bg: '#374151', text: '#d1d5db', isLarge: false },
            { name: 'White text on blue-600 background', bg: '#2563eb', text: '#ffffff', isLarge: false },
            { name: 'White text on green-600 background', bg: '#16a34a', text: '#ffffff', isLarge: false },
            { name: 'White text on red-600 background', bg: '#dc2626', text: '#ffffff', isLarge: false },
            { name: 'White text on teal-500 background', bg: '#14b8a6', text: '#ffffff', isLarge: false },
            
            // Large text versions (headings)
            { name: 'White heading on gray-900 background', bg: '#111827', text: '#ffffff', isLarge: true },
            { name: 'Gray-300 heading on gray-900 background', bg: '#111827', text: '#d1d5db', isLarge: true },
        ];
        
        const results = colorTests.map(test => {
            const ratio = this.getContrastRatio(test.bg, test.text);
            const compliance = this.checkCompliance(ratio, test.isLarge);
            
            return {
                name: test.name,
                backgroundColor: test.bg,
                textColor: test.text,
                isLargeText: test.isLarge,
                contrastRatio: Math.round(ratio * 100) / 100,
                passes: compliance.passes,
                level: compliance.level,
                threshold: compliance.threshold
            };
        });
        
        return results;
    }
    
    /**
     * Generate a report of color contrast compliance
     * @returns {Object} - Compliance report
     */
    generateReport() {
        const results = this.testApplicationColors();
        const passing = results.filter(r => r.passes);
        const failing = results.filter(r => !r.passes);
        
        return {
            totalTests: results.length,
            passing: passing.length,
            failing: failing.length,
            passRate: Math.round((passing.length / results.length) * 100),
            results: results,
            summary: {
                compliant: failing.length === 0,
                message: failing.length === 0 
                    ? 'All color combinations meet WCAG 2.1 AA standards'
                    : `${failing.length} color combinations fail WCAG 2.1 AA standards`
            }
        };
    }
    
    /**
     * Log compliance report to console
     */
    logReport() {
        const report = this.generateReport();
        
        console.group('🎨 WCAG 2.1 AA Color Contrast Compliance Report');
        console.log(`📊 Total Tests: ${report.totalTests}`);
        console.log(`✅ Passing: ${report.passing}`);
        console.log(`❌ Failing: ${report.failing}`);
        console.log(`📈 Pass Rate: ${report.passRate}%`);
        console.log(`🎯 Overall Compliance: ${report.summary.compliant ? '✅ COMPLIANT' : '❌ NON-COMPLIANT'}`);
        
        if (report.failing > 0) {
            console.group('❌ Failing Tests:');
            report.results.filter(r => !r.passes).forEach(result => {
                console.log(`• ${result.name}: ${result.contrastRatio}:1 (needs ${result.threshold}:1)`);
            });
            console.groupEnd();
        }
        
        console.group('📋 Detailed Results:');
        report.results.forEach(result => {
            const status = result.passes ? '✅' : '❌';
            console.log(`${status} ${result.name}: ${result.contrastRatio}:1 (${result.level})`);
        });
        console.groupEnd();
        
        console.groupEnd();
        
        return report;
    }
}

// Initialize and run color contrast check
const colorChecker = new ColorContrastChecker();

// Make available globally for manual testing
window.colorContrastChecker = colorChecker;

// Auto-run check in development
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            colorChecker.logReport();
        }, 1000);
    });
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ColorContrastChecker };
}