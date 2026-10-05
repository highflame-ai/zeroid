// Package telemetry provides OpenTelemetry instrumentation for ZeroID.
// Initialises a shared TracerProvider and MeterProvider that export to an OTEL
// Collector via gRPC. When telemetry is disabled, all instruments are no-ops.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	otelmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config mirrors the telemetry section of the service config.
// Endpoint and TLS are read by the OTel SDK from standard env vars
// (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, etc.).
type Config struct {
	Enabled      bool
	ServiceName  string
	SamplingRate float64
}

// Package-level instruments — initialised as no-ops, replaced by Init().
var (
	Tracer trace.Tracer
	Meter  metric.Meter

	// Metrics
	TokenIssuances     metric.Int64Counter
	TokenLatency       metric.Float64Histogram
	IdentityOps        metric.Int64Counter
	PolicyEnforcements metric.Int64Counter
	AuthErrors         metric.Int64Counter
	// WorkloadUnboundedScope counts tokens issued for a named scope with no
	// configured ceiling: a workload subject whose every scope ceiling was
	// empty, or a user-subject root bounded only by the caller's request.
	// Exported to Prometheus as zeroid_workload_unbounded_scope_total. The
	// ceiling rule (human-rooted delegation P1) counts in phase 1 and refuses
	// in phase 2, so this lists the identities enforcement will affect.
	WorkloadUnboundedScope metric.Int64Counter
)

func init() {
	initNoOpMetrics()
}

func initNoOpMetrics() {
	Tracer = otel.Tracer("zeroid")
	Meter = otel.Meter("zeroid")
	registerInstruments(Meter)
}

// registerInstruments creates every instrument on m. It is the one place an
// instrument is declared, called for the no-op defaults and again by Init with
// the real meter, so a new instrument cannot be registered in one and silently
// stay a no-op because it was missed in the other.
func registerInstruments(m metric.Meter) {
	TokenIssuances, _ = m.Int64Counter("zeroid.token.issuances",
		metric.WithDescription("Total token issuances"),
	)
	TokenLatency, _ = m.Float64Histogram("zeroid.token.latency_ms",
		metric.WithDescription("Token issuance latency in milliseconds"),
	)
	IdentityOps, _ = m.Int64Counter("zeroid.identity.operations",
		metric.WithDescription("Identity CRUD operations"),
	)
	PolicyEnforcements, _ = m.Int64Counter("zeroid.policy.enforcements",
		metric.WithDescription("Credential policy enforcement decisions"),
	)
	AuthErrors, _ = m.Int64Counter("zeroid.errors",
		metric.WithDescription("Authentication errors"),
	)
	WorkloadUnboundedScope, _ = m.Int64Counter("zeroid.workload.unbounded_scope",
		metric.WithDescription("Tokens issued for a named scope with no configured scope ceiling (ceiling rule, counted before it is enforced)"),
	)
}

// providers holds references for graceful shutdown.
var (
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *otelmetric.MeterProvider
)

// Init sets up the OTEL TracerProvider and MeterProvider. If disabled, returns
// immediately and all instruments remain no-ops.
func Init(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
		resource.WithProcessRuntimeDescription(),
	)
	if err != nil {
		return fmt.Errorf("otel resource: %w", err)
	}

	// Traces — the SDK reads OTEL_EXPORTER_OTLP_ENDPOINT (with scheme)
	// and handles TLS negotiation per the OTel spec.
	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return fmt.Errorf("otel trace exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SamplingRate))
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithMaxQueueSize(4096),
			sdktrace.WithBatchTimeout(time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
	)
	otel.SetTracerProvider(tracerProvider)

	// Metrics — same SDK-managed env var handling as traces.
	metricExporter, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		return fmt.Errorf("otel metric exporter: %w", err)
	}

	meterProvider = otelmetric.NewMeterProvider(
		otelmetric.WithResource(res),
		otelmetric.WithReader(otelmetric.NewPeriodicReader(metricExporter,
			otelmetric.WithInterval(30*time.Second),
		)),
	)
	otel.SetMeterProvider(meterProvider)

	// Re-initialise instruments with real providers.
	Tracer = tracerProvider.Tracer("zeroid")
	Meter = meterProvider.Meter("zeroid")
	registerInstruments(Meter)

	return nil
}

// Shutdown flushes and shuts down the OTEL providers. Call during graceful shutdown.
func Shutdown(ctx context.Context) error {
	var firstErr error
	if tracerProvider != nil {
		if err := tracerProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if meterProvider != nil {
		if err := meterProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
