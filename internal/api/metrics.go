package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secretvault_requests_total",
		Help: "Total number of HTTP requests.",
	}, []string{"method", "path", "status"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "secretvault_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	secretsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "secretvault_secrets_total",
		Help: "Total number of secrets by type.",
	}, []string{"type"})

	activeTokensTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "secretvault_active_tokens_total",
		Help: "Number of active (non-revoked, non-expired) tokens.",
	})

	sealStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "secretvault_seal_status",
		Help: "Vault seal status: 0=sealed, 1=unsealed.",
	})
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration, secretsTotal, activeTokensTotal, sealStatus)
}

// MetricsHandler returns the Prometheus metrics HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// metricsMiddleware records request metrics.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rr := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rr, r)

		dur := time.Since(start).Seconds()
		status := strconv.Itoa(rr.statusCode)
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, status).Inc()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(dur)
	})
}
