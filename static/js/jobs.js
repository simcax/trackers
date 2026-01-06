/**
 * Job Management JavaScript
 * 
 * Handles job creation, editing, testing, and monitoring functionality
 * for the automated job scheduling system.
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.4, 5.1, 5.3, 7.1, 7.2, 10.1, 10.2
 */

// Job management utilities
window.JobManager = {
    // Configuration templates for different job types
    templates: {
        stock: {
            name: '',
            job_type: 'stock',
            config: {
                symbol: '',
                provider: 'alpha_vantage',
                api_key: ''
            },
            cron_schedule: '0 9 * * *' // Daily at 9 AM
        },
        generic: {
            name: '',
            job_type: 'generic',
            config: {
                url: '',
                method: 'GET',
                json_path: '$.value',
                headers: {}
            },
            cron_schedule: '0 */6 * * *' // Every 6 hours
        }
    },
    
    // Cron expression examples
    cronExamples: [
        { expression: '0 9 * * *', description: 'Every day at 9:00 AM' },
        { expression: '0 */6 * * *', description: 'Every 6 hours' },
        { expression: '0 9 * * 1-5', description: 'Weekdays at 9:00 AM' },
        { expression: '0 0 1 * *', description: 'First day of every month' },
        { expression: '*/15 * * * *', description: 'Every 15 minutes' },
        { expression: '0 0 * * 0', description: 'Every Sunday at midnight' },
        { expression: '0 12 * * *', description: 'Every day at noon' },
        { expression: '0 0,12 * * *', description: 'Twice daily (midnight and noon)' }
    ],
    
    // Initialize job management functionality
    init() {
        console.log('JobManager: Initializing...');
        this.setupEventListeners();
        this.loadJobStatistics();
        
        // Auto-refresh statistics every 30 seconds
        setInterval(() => this.loadJobStatistics(), 30000);
        
        console.log('JobManager: Initialization complete');
    },
    
    setupEventListeners() {
        console.log('JobManager: Setting up event listeners...');
        
        // Remove any existing listeners to prevent duplicates
        if (this._clickHandler) {
            document.removeEventListener('click', this._clickHandler);
        }
        
        // Create and store the click handler
        this._clickHandler = (e) => {
            console.log('JobManager: Click detected on', e.target);
            
            // Check if the clicked element or its parent has a job action
            const target = e.target.closest('[data-job-action]');
            if (!target) {
                console.log('JobManager: No data-job-action found');
                return;
            }
            
            const action = target.dataset.jobAction;
            const jobId = target.dataset.jobId;
            
            console.log(`JobManager: Handling action "${action}" for job ${jobId}`);
            
            // Prevent default behavior and stop propagation
            e.preventDefault();
            e.stopPropagation();
            
            // Close any open dropdowns first
            this.closeAllDropdowns();
            
            switch (action) {
                case 'view-details':
                    this.showJobDetails(jobId);
                    break;
                case 'test-job':
                    this.testJob(jobId);
                    break;
                case 'edit-job':
                    this.editJob(jobId);
                    break;
                case 'toggle-status':
                    this.toggleJobStatus(jobId, target.dataset.newStatus === 'true');
                    break;
                case 'delete-job':
                    this.deleteJob(jobId, target.dataset.jobName);
                    break;
                case 'reset-failures':
                    this.resetJobFailures(jobId);
                    break;
                default:
                    console.warn(`JobManager: Unknown action "${action}"`);
            }
        };
        
        // Global event delegation for job actions
        document.addEventListener('click', this._clickHandler);
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + N to create new job
            if ((e.ctrlKey || e.metaKey) && e.key === 'n' && !e.target.matches('input, textarea, select')) {
                e.preventDefault();
                const createBtn = document.getElementById('create-job-btn');
                if (createBtn) createBtn.click();
            }
            
            // Escape to close modals
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });
        
        console.log('JobManager: Event listeners set up successfully');
    },
    
    // Load and display job statistics
    async loadJobStatistics() {
        try {
            const response = await fetch('/api/jobs/statistics');
            if (!response.ok) return;
            
            const data = await response.json();
            const stats = data.statistics;
            
            if (stats) {
                this.updateStatistic('total-jobs-stat', stats.total_jobs || 0);
                this.updateStatistic('active-jobs-stat', stats.active_jobs || 0);
                this.updateStatistic('attention-jobs-stat', stats.problematic_jobs || 0);
                this.updateStatistic('recent-runs-stat', stats.executions_last_24h || 0);
                
                // Update counts in header
                this.updateStatistic('job-count', stats.total_jobs || 0);
                this.updateStatistic('active-count', stats.active_jobs || 0);
                this.updateStatistic('problematic-count', stats.problematic_jobs || 0);
            }
            
        } catch (error) {
            console.error('Error loading job statistics:', error);
        }
    },
    
    updateStatistic(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
            
            // Add animation for changes
            element.classList.add('animate-pulse');
            setTimeout(() => element.classList.remove('animate-pulse'), 1000);
        }
    },
    
    // Show job details modal
    async showJobDetails(jobId) {
        const modal = document.getElementById('job-details-modal');
        const content = document.getElementById('job-details-content');
        
        if (!modal || !content) return;
        
        // Show modal with loading state
        content.innerHTML = this.getLoadingHTML('Loading job details...');
        modal.classList.remove('hidden');
        modal.setAttribute('aria-hidden', 'false');
        
        try {
            // Load job details
            const response = await fetch(`/api/jobs/${jobId}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            this.displayJobDetails(data.job);
            
            // Load execution history
            await this.loadJobHistory(jobId);
            
        } catch (error) {
            console.error('Error loading job details:', error);
            content.innerHTML = this.getErrorHTML('Failed to load job details', error.message);
        }
    },
    
    // Edit job functionality
    async editJob(jobId) {
        try {
            // Load current job data
            const response = await fetch(`/api/jobs/${jobId}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            const job = data.job;
            
            // Show edit modal with current job data
            this.showJobEditModal(job);
            
        } catch (error) {
            console.error('Error loading job for editing:', error);
            this.showToast('Failed to load job data for editing', 'error');
        }
    },
    
    // Delete job functionality
    async deleteJob(jobId, jobName) {
        // Show confirmation dialog
        const confirmed = await this.showDeleteConfirmationModal(jobName);
        if (!confirmed) return;
        
        try {
            const response = await fetch(`/api/jobs/${jobId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }
            
            this.showToast(`Job "${jobName}" deleted successfully`, 'success');
            
            // Refresh the page or remove the job card
            setTimeout(() => {
                window.location.reload();
            }, 1000);
            
        } catch (error) {
            console.error('Error deleting job:', error);
            this.showToast(`Failed to delete job: ${error.message}`, 'error');
        }
    },
    
    // Show job edit modal
    showJobEditModal(job) {
        const modalHtml = `
            <div id="job-edit-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                <div class="bg-gray-800 rounded-xl p-6 max-w-2xl w-full mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-semibold text-white">Edit Job</h3>
                        <button 
                            id="close-edit-modal-btn" 
                            class="text-gray-400 hover:text-white transition-colors"
                            aria-label="Close edit modal"
                        >
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <form id="job-edit-form" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">Job Name:</label>
                            <input 
                                type="text" 
                                id="edit-job-name" 
                                value="${this.escapeHtml(job.name)}"
                                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                required
                            >
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">Schedule (Cron):</label>
                            <input 
                                type="text" 
                                id="edit-cron-schedule" 
                                value="${this.escapeHtml(job.cron_schedule)}"
                                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono"
                                required
                            >
                            <p class="text-xs text-gray-400 mt-1">Example: "0 9 * * *" for daily at 9 AM</p>
                        </div>
                        
                        <div>
                            <label class="flex items-center space-x-2">
                                <input 
                                    type="checkbox" 
                                    id="edit-is-active" 
                                    ${job.is_active ? 'checked' : ''}
                                    class="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                                >
                                <span class="text-sm text-gray-300">Job is active</span>
                            </label>
                        </div>
                        
                        <div class="flex space-x-3 mt-6">
                            <button 
                                type="submit" 
                                class="flex-1 bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Save Changes
                            </button>
                            <button 
                                type="button" 
                                id="cancel-edit-btn" 
                                class="flex-1 bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        
        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        const modal = document.getElementById('job-edit-modal');
        const form = document.getElementById('job-edit-form');
        const closeBtn = document.getElementById('close-edit-modal-btn');
        const cancelBtn = document.getElementById('cancel-edit-btn');
        
        // Handle close
        const handleClose = () => {
            this.removeModal(modal);
        };
        
        // Handle form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                name: document.getElementById('edit-job-name').value.trim(),
                cron_schedule: document.getElementById('edit-cron-schedule').value.trim(),
                is_active: document.getElementById('edit-is-active').checked
            };
            
            if (!formData.name || !formData.cron_schedule) {
                this.showToast('Please fill in all required fields', 'error');
                return;
            }
            
            try {
                const response = await fetch(`/api/jobs/${job.id}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || `HTTP ${response.status}`);
                }
                
                this.showToast('Job updated successfully', 'success');
                handleClose();
                
                // Refresh the page
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
                
            } catch (error) {
                console.error('Error updating job:', error);
                this.showToast(`Failed to update job: ${error.message}`, 'error');
            }
        });
        
        // Event listeners
        closeBtn.addEventListener('click', handleClose);
        cancelBtn.addEventListener('click', handleClose);
        
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
    },
    
    // Show delete confirmation modal
    showDeleteConfirmationModal(jobName) {
        return new Promise((resolve) => {
            const modalHtml = `
                <div id="delete-job-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center">
                                <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Delete Job</h3>
                        </div>
                        
                        <div class="mb-6">
                            <p class="text-gray-300">
                                Are you sure you want to delete the job <strong class="text-white">"${this.escapeHtml(jobName)}"</strong>?
                            </p>
                            <p class="text-red-400 text-sm mt-2">
                                This action cannot be undone. The job will be permanently removed and will no longer run automatically.
                            </p>
                        </div>
                        
                        <div class="flex space-x-3">
                            <button 
                                id="confirm-delete-btn" 
                                class="flex-1 bg-red-600 hover:bg-red-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Delete Job
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
            
            const modal = document.getElementById('delete-job-modal');
            const confirmBtn = document.getElementById('confirm-delete-btn');
            const cancelBtn = document.getElementById('cancel-delete-btn');
            
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
            
            // Handle Escape key
            document.addEventListener('keydown', function escapeHandler(e) {
                if (e.key === 'Escape') {
                    handleCancel();
                    document.removeEventListener('keydown', escapeHandler);
                }
            });
            
            // Handle click outside modal
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    handleCancel();
                }
            });
        });
    },
    
    displayJobDetails(job) {
        const content = document.getElementById('job-details-content');
        const statusClass = job.is_active ? 'bg-green-500' : 'bg-gray-500';
        const statusText = job.is_active ? 'Active' : 'Inactive';
        const typeIcon = job.job_type === 'stock' ? '📈' : '🔗';
        
        content.innerHTML = `
            <div class="space-y-6">
                <!-- Job Overview -->
                <div class="bg-gray-700 rounded-lg p-6">
                    <div class="flex justify-between items-start mb-4">
                        <div class="flex-1">
                            <div class="flex items-center space-x-3 mb-2">
                                <span class="text-2xl">${typeIcon}</span>
                                <div>
                                    <h3 class="text-xl font-semibold text-white">${this.escapeHtml(job.name)}</h3>
                                    <p class="text-gray-400 text-sm">${job.job_type.charAt(0).toUpperCase() + job.job_type.slice(1)} Job</p>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2">
                            <span class="px-3 py-1 text-sm font-medium text-white rounded-full ${statusClass}">
                                ${statusText}
                            </span>
                            <div class="flex space-x-1">
                                <button onclick="JobManager.testJob(${job.id})" 
                                        class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition-colors"
                                        title="Test job execution">
                                    Test
                                </button>
                                <button onclick="JobManager.editJob(${job.id})" 
                                        class="bg-gray-600 hover:bg-gray-700 text-white px-3 py-1 rounded text-sm transition-colors"
                                        title="Edit job configuration">
                                    Edit
                                </button>
                                <button onclick="JobManager.toggleJobStatus(${job.id}, ${!job.is_active})" 
                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm transition-colors"
                                        title="${job.is_active ? 'Disable' : 'Enable'} job">
                                    ${job.is_active ? 'Disable' : 'Enable'}
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                        <div>
                            <p class="text-gray-400 mb-1">Schedule:</p>
                            <p class="text-white font-mono bg-gray-800 px-2 py-1 rounded">${job.cron_schedule}</p>
                        </div>
                        <div>
                            <p class="text-gray-400 mb-1">Tracker ID:</p>
                            <p class="text-white">${job.tracker_id}</p>
                        </div>
                        <div>
                            <p class="text-gray-400 mb-1">Created:</p>
                            <p class="text-white">${job.created_at ? new Date(job.created_at).toLocaleDateString() : 'N/A'}</p>
                        </div>
                        <div>
                            <p class="text-gray-400 mb-1">Last Run:</p>
                            <p class="text-white">${job.last_run_at ? new Date(job.last_run_at).toLocaleString() : 'Never'}</p>
                        </div>
                    </div>
                    
                    ${job.failure_count > 0 ? `
                    <div class="mt-4 p-4 bg-red-900 border border-red-700 rounded-lg">
                        <div class="flex justify-between items-start">
                            <div>
                                <p class="text-red-300 font-medium">
                                    ⚠️ ${job.failure_count} consecutive failure${job.failure_count > 1 ? 's' : ''}
                                </p>
                                ${job.last_error ? `<p class="text-red-400 text-sm mt-1">${this.escapeHtml(job.last_error)}</p>` : ''}
                            </div>
                            <button onclick="JobManager.resetJobFailures(${job.id})" 
                                    class="bg-red-700 hover:bg-red-600 text-white px-3 py-1 rounded text-sm transition-colors"
                                    title="Reset failure count">
                                Reset
                            </button>
                        </div>
                    </div>
                    ` : ''}
                </div>
                
                <!-- Execution History -->
                <div class="bg-gray-700 rounded-lg p-6">
                    <h4 class="text-lg font-semibold text-white mb-4">Recent Execution History</h4>
                    <div id="job-history-content">
                        ${this.getLoadingHTML('Loading execution history...')}
                    </div>
                </div>
            </div>
        `;
    },
    
    async loadJobHistory(jobId) {
        try {
            const response = await fetch(`/api/jobs/${jobId}/history?limit=20`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            this.displayJobHistory(data.execution_history);
            
        } catch (error) {
            console.error('Error loading job history:', error);
            document.getElementById('job-history-content').innerHTML = 
                this.getErrorHTML('Failed to load execution history', error.message);
        }
    },
    
    displayJobHistory(history) {
        const content = document.getElementById('job-history-content');
        
        if (!history || history.length === 0) {
            content.innerHTML = `
                <div class="text-center py-8">
                    <div class="text-gray-400 mb-2">
                        <svg class="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                        </svg>
                    </div>
                    <p class="text-gray-400">No execution history available</p>
                    <p class="text-gray-500 text-sm mt-1">This job hasn't been executed yet</p>
                </div>
            `;
            return;
        }
        
        const historyHtml = history.map(execution => {
            const statusClass = execution.success ? 'text-green-400' : 'text-red-400';
            const statusIcon = execution.success ? '✓' : '✗';
            const bgClass = execution.success ? 'bg-green-900 border-green-700' : 'bg-red-900 border-red-700';
            
            return `
                <div class="flex justify-between items-center py-3 px-4 rounded-lg ${bgClass} border mb-2">
                    <div class="flex items-center space-x-3">
                        <span class="${statusClass} font-mono text-lg">${statusIcon}</span>
                        <div>
                            <p class="text-white text-sm font-medium">
                                ${execution.executed_at ? new Date(execution.executed_at).toLocaleString() : 'Unknown time'}
                            </p>
                            ${execution.error_message ? `<p class="text-red-300 text-xs mt-1">${this.escapeHtml(execution.error_message)}</p>` : ''}
                        </div>
                    </div>
                    <div class="text-right text-sm">
                        ${execution.value_extracted !== null ? `<p class="text-gray-200 font-medium">Value: ${execution.value_extracted}</p>` : ''}
                        <div class="flex items-center space-x-2 text-gray-400 text-xs mt-1">
                            ${execution.duration_seconds ? `<span>⏱️ ${execution.duration_seconds}s</span>` : ''}
                            ${execution.http_status_code ? `<span>📡 ${execution.http_status_code}</span>` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        content.innerHTML = `
            <div class="space-y-0">
                ${historyHtml}
                <div class="text-center mt-4">
                    <p class="text-gray-500 text-xs">Showing last ${history.length} execution${history.length > 1 ? 's' : ''}</p>
                </div>
            </div>
        `;
    },
    
    // Test job execution (Run Now functionality)
    async testJob(jobId) {
        try {
            this.showToast('🚀 Starting job execution...', 'info');
            
            const response = await fetch(`/api/jobs/${jobId}/test`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.success && data.result.success) {
                this.showToast('✅ Job executed successfully!', 'success');
                if (data.result.value !== null) {
                    this.showToast(`📊 Value collected: ${data.result.value}`, 'info');
                }
                
                // Show execution details
                const executionTime = data.result.execution_time ? `${data.result.execution_time}s` : 'N/A';
                this.showToast(`⏱️ Execution time: ${executionTime}`, 'info');
            } else {
                const errorMsg = data.result?.error_message || 'Job execution failed with unknown error';
                this.showToast(`❌ Job execution failed: ${errorMsg}`, 'error');
            }
            
            // Refresh job details if modal is open
            const modal = document.getElementById('job-details-modal');
            if (modal && !modal.classList.contains('hidden')) {
                setTimeout(() => this.loadJobHistory(jobId), 1000);
            }
            
            // Refresh job statistics
            setTimeout(() => this.loadJobStatistics(), 1500);
            
        } catch (error) {
            console.error('Error executing job:', error);
            this.showToast(`❌ Failed to execute job: ${error.message}`, 'error');
        }
    },
    
    // Toggle job active status
    async toggleJobStatus(jobId, newStatus) {
        try {
            this.showToast('Updating job status...', 'info');
            
            const response = await fetch(`/api/jobs/${jobId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    is_active: newStatus
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            
            const statusText = newStatus ? 'enabled' : 'disabled';
            this.showToast(`✅ Job ${statusText} successfully`, 'success');
            
            // Refresh the page to update job cards
            setTimeout(() => window.location.reload(), 1000);
            
        } catch (error) {
            console.error('Error toggling job status:', error);
            this.showToast(`❌ Failed to update job status: ${error.message}`, 'error');
        }
    },
    
    // Delete job
    async deleteJob(jobId, jobName) {
        const confirmed = await this.showDeleteConfirmationModal(jobName);
        if (!confirmed) return;
        
        try {
            this.showToast('Deleting job...', 'info');
            
            const response = await fetch(`/api/jobs/${jobId}`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            
            this.showToast('✅ Job deleted successfully', 'success');
            
            // Remove the job card from the DOM
            const jobCard = document.querySelector(`[data-job-id="${jobId}"]`);
            if (jobCard) {
                jobCard.style.transition = 'opacity 0.3s ease-out';
                jobCard.style.opacity = '0';
                setTimeout(() => jobCard.remove(), 300);
            }
            
            // Close details modal if open
            this.closeAllModals();
            
            // Update statistics
            setTimeout(() => this.loadJobStatistics(), 500);
            
        } catch (error) {
            console.error('Error deleting job:', error);
            this.showToast(`❌ Failed to delete job: ${error.message}`, 'error');
        }
    },
    
    // Reset job failure count
    async resetJobFailures(jobId) {
        try {
            this.showToast('Resetting failure count...', 'info');
            
            const response = await fetch(`/api/jobs/${jobId}/reset-failures`, {
                method: 'POST'
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            
            this.showToast('✅ Job failure count reset successfully', 'success');
            
            // Refresh job details
            setTimeout(() => this.showJobDetails(jobId), 1000);
            
        } catch (error) {
            console.error('Error resetting job failures:', error);
            this.showToast(`❌ Failed to reset failures: ${error.message}`, 'error');
        }
    },
    
    // Close all modals
    closeAllModals() {
        const modals = document.querySelectorAll('[role="dialog"]');
        modals.forEach(modal => {
            modal.classList.add('hidden');
            modal.setAttribute('aria-hidden', 'true');
        });
    },
    
    // Close all dropdowns
    closeAllDropdowns() {
        const dropdowns = document.querySelectorAll('[id$="-menu"]');
        dropdowns.forEach(dropdown => {
            dropdown.classList.add('hidden');
        });
    },
    
    // Utility functions
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    getLoadingHTML(message = 'Loading...') {
        return `
            <div class="text-center py-8">
                <div class="spinner mx-auto mb-4"></div>
                <p class="text-gray-400">${message}</p>
            </div>
        `;
    },
    
    getErrorHTML(title, message) {
        return `
            <div class="text-center py-8">
                <div class="text-red-400 mb-4">
                    <svg class="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                </div>
                <p class="text-gray-300 font-medium">${title}</p>
                <p class="text-gray-500 text-sm mt-1">${message}</p>
            </div>
        `;
    },
    
    // Show confirmation dialog
    async showDeleteConfirmationModal(jobName) {
        return new Promise((resolve) => {
            const modalHtml = `
                <div id="delete-job-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div class="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center">
                                <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Delete Job</h3>
                        </div>
                        
                        <div class="mb-6">
                            <p class="text-gray-300">
                                Are you sure you want to delete the job <strong class="text-white">"${this.escapeHtml(jobName)}"</strong>?
                            </p>
                            <p class="text-red-400 text-sm mt-2">
                                This action cannot be undone. The job will be permanently removed and will no longer run automatically.
                            </p>
                        </div>
                        
                        <div class="flex space-x-3">
                            <button 
                                id="confirm-delete-btn" 
                                class="flex-1 bg-red-600 hover:bg-red-700 py-2 px-4 rounded-lg text-white font-medium transition-colors"
                            >
                                Delete Job
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
            
            const modal = document.getElementById('delete-job-modal');
            const confirmBtn = document.getElementById('confirm-delete-btn');
            const cancelBtn = document.getElementById('cancel-delete-btn');
            
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
            
            // Handle Escape key
            document.addEventListener('keydown', function escapeHandler(e) {
                if (e.key === 'Escape') {
                    handleCancel();
                    document.removeEventListener('keydown', escapeHandler);
                }
            });
            
            // Handle click outside modal
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    handleCancel();
                }
            });
        });
    },

    // Utility functions for job management
    removeModal(modal) {
        if (modal && modal.parentNode) {
            modal.parentNode.removeChild(modal);
        }
    },
    
    showToast(message, type = 'info') {
        // Use global feedback system if available
        if (window.trackerDashboard && window.trackerDashboard.showToast) {
            return window.trackerDashboard.showToast(message, type);
        }
        
        // Fallback: create toast notification
        const toast = document.createElement('div');
        toast.className = `fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-white font-medium transition-all duration-300 transform translate-x-full`;
        
        // Set color based on type
        switch (type) {
            case 'success':
                toast.className += ' bg-green-600';
                break;
            case 'error':
                toast.className += ' bg-red-600';
                break;
            case 'warning':
                toast.className += ' bg-yellow-600';
                break;
            default:
                toast.className += ' bg-blue-600';
        }
        
        toast.textContent = message;
        document.body.appendChild(toast);
        
        // Animate in
        setTimeout(() => {
            toast.classList.remove('translate-x-full');
        }, 100);
        
        // Auto remove after 3 seconds
        setTimeout(() => {
            toast.classList.add('translate-x-full');
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 3000);
    }
};

// Make JobManager globally available
window.JobManager = JobManager;

// Global functions for job management (called from templates)
window.showJobDetails = (jobId) => {
    console.log('Global showJobDetails called with jobId:', jobId);
    return JobManager.showJobDetails(jobId);
};

window.testJob = (jobId) => {
    console.log('Global testJob called with jobId:', jobId);
    return JobManager.testJob(jobId);
};

window.editJob = (jobId) => {
    console.log('Global editJob called with jobId:', jobId);
    return JobManager.editJob(jobId);
};

window.deleteJob = (jobId, jobName) => {
    console.log('Global deleteJob called with jobId:', jobId, 'jobName:', jobName);
    return JobManager.deleteJob(jobId, jobName);
};

window.toggleJobStatus = (jobId, newStatus) => {
    console.log('Global toggleJobStatus called with jobId:', jobId, 'newStatus:', newStatus);
    return JobManager.toggleJobStatus(jobId, newStatus);
};

window.resetJobFailures = (jobId) => {
    console.log('Global resetJobFailures called with jobId:', jobId);
    return JobManager.resetJobFailures(jobId);
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('JobManager: DOM ready, initializing...');
    
    // Initialize JobManager
    if (window.JobManager) {
        window.JobManager.init();
        console.log('JobManager: Initialized successfully');
    } else {
        console.error('JobManager: JobManager object not found!');
    }
});