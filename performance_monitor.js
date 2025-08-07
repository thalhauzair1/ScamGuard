/**
 * Performance Monitoring for ScamGuard Extension
 * Tracks execution times, memory usage, and optimization opportunities
 */

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      scanTimes: [],
      memoryUsage: [],
      cacheHits: 0,
      cacheMisses: 0,
      domOperations: 0,
      observerTriggers: 0
    };
    
    this.startTime = Date.now();
    this.lastReport = Date.now();
    
    // Performance thresholds
    this.thresholds = {
      maxScanTime: 100, // ms
      maxMemoryUsage: 50, // MB
      maxObserverTriggers: 10 // per minute
    };
  }
  
  /**
   * Start timing an operation
   * @param {string} operation - Name of the operation
   * @returns {number} - Start timestamp
   */
  startTimer(operation) {
    const start = performance.now();
    this.currentOperation = operation;
    this.currentStart = start;
    return start;
  }
  
  /**
   * End timing an operation
   * @param {string} operation - Name of the operation
   * @returns {number} - Duration in milliseconds
   */
  endTimer(operation) {
    if (this.currentOperation === operation && this.currentStart) {
      const duration = performance.now() - this.currentStart;
      this.metrics.scanTimes.push({
        operation,
        duration,
        timestamp: Date.now()
      });
      
      // Keep only last 100 measurements
      if (this.metrics.scanTimes.length > 100) {
        this.metrics.scanTimes.shift();
      }
      
      this.currentOperation = null;
      this.currentStart = null;
      
      // Check for performance issues
      this.checkPerformance(duration, operation);
      
      return duration;
    }
    return 0;
  }
  
  /**
   * Record cache hit/miss
   * @param {boolean} isHit - Whether it was a cache hit
   */
  recordCache(isHit) {
    if (isHit) {
      this.metrics.cacheHits++;
    } else {
      this.metrics.cacheMisses++;
    }
  }
  
  /**
   * Record DOM operation
   */
  recordDOMOperation() {
    this.metrics.domOperations++;
  }
  
  /**
   * Record observer trigger
   */
  recordObserverTrigger() {
    this.metrics.observerTriggers++;
  }
  
  /**
   * Check for performance issues
   * @param {number} duration - Operation duration
   * @param {string} operation - Operation name
   */
  checkPerformance(duration, operation) {
    if (duration > this.thresholds.maxScanTime) {
      console.warn(`Performance warning: ${operation} took ${duration.toFixed(2)}ms`);
      
      // Suggest optimizations
      if (operation === 'pageScan') {
        this.suggestOptimizations('pageScan');
      }
    }
    
    // Check observer trigger rate
    const now = Date.now();
    const recentTriggers = this.metrics.observerTriggers.filter(
      trigger => (now - trigger) < 60000
    );
    
    if (recentTriggers.length > this.thresholds.maxObserverTriggers) {
      console.warn('Performance warning: Too many observer triggers');
    }
  }
  
  /**
   * Suggest performance optimizations
   * @param {string} operation - Operation type
   */
  suggestOptimizations(operation) {
    const suggestions = {
      pageScan: [
        'Consider reducing keyword list size',
        'Implement more aggressive caching',
        'Use Web Workers for heavy computations',
        'Reduce DOM query frequency'
      ],
      observer: [
        'Increase debounce time',
        'Filter mutation types',
        'Use throttling for rapid changes'
      ],
      memory: [
        'Clear old cache entries',
        'Reduce object allocations',
        'Use object pooling'
      ]
    };
    
    const relevantSuggestions = suggestions[operation] || [];
    if (relevantSuggestions.length > 0) {
      console.log('Performance suggestions:', relevantSuggestions);
    }
  }
  
  /**
   * Get performance report
   * @returns {Object} - Performance metrics
   */
  getReport() {
    const now = Date.now();
    const uptime = now - this.startTime;
    
    // Calculate averages
    const avgScanTime = this.metrics.scanTimes.length > 0 
      ? this.metrics.scanTimes.reduce((sum, item) => sum + item.duration, 0) / this.metrics.scanTimes.length
      : 0;
    
    const cacheHitRate = (this.metrics.cacheHits + this.metrics.cacheMisses) > 0
      ? (this.metrics.cacheHits / (this.metrics.cacheHits + this.metrics.cacheMisses)) * 100
      : 0;
    
    return {
      uptime: Math.round(uptime / 1000), // seconds
      totalScans: this.metrics.scanTimes.length,
      averageScanTime: Math.round(avgScanTime * 100) / 100, // ms
      cacheHitRate: Math.round(cacheHitRate * 100) / 100, // percentage
      domOperations: this.metrics.domOperations,
      observerTriggers: this.metrics.observerTriggers,
      recentScans: this.metrics.scanTimes.slice(-10) // Last 10 scans
    };
  }
  
  /**
   * Log performance report
   */
  logReport() {
    const report = this.getReport();
    console.log('ScamGuard Performance Report:', report);
    
    // Log to storage for analysis
    chrome.storage.local.get(['performanceReports'], (result) => {
      const reports = result.performanceReports || [];
      reports.push({
        timestamp: Date.now(),
        ...report
      });
      
      // Keep only last 50 reports
      if (reports.length > 50) {
        reports.shift();
      }
      
      chrome.storage.local.set({ performanceReports: reports });
    });
  }
  
  /**
   * Reset metrics
   */
  reset() {
    this.metrics = {
      scanTimes: [],
      memoryUsage: [],
      cacheHits: 0,
      cacheMisses: 0,
      domOperations: 0,
      observerTriggers: 0
    };
    this.startTime = Date.now();
  }
}

// Global performance monitor instance
const performanceMonitor = new PerformanceMonitor();

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PerformanceMonitor;
} else {
  window.PerformanceMonitor = PerformanceMonitor;
  window.performanceMonitor = performanceMonitor;
}
