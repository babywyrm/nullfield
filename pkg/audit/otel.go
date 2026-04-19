package audit

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

// InitOTLP sets up the OpenTelemetry trace exporter.
// Call once at startup. Returns a shutdown function.
func InitOTLP(ctx context.Context, endpoint string, logger *slog.Logger) (func(context.Context) error, error) {
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("nullfield"),
			semconv.ServiceVersionKey.String("0.5.0"),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("nullfield")

	logger.Info("OTLP trace export enabled", "endpoint", endpoint)
	return tp.Shutdown, nil
}

// OTLPEmitter creates OpenTelemetry spans for audit events.
// Only emits spans when a tracer has been initialized via InitOTLP.
type OTLPEmitter struct{}

func NewOTLPEmitter() *OTLPEmitter {
	return &OTLPEmitter{}
}

func (o *OTLPEmitter) Emit(ctx context.Context, event Event) {
	if tracer == nil {
		return
	}

	event.Time = time.Now().UTC()

	spanName := "nullfield." + string(event.Type)
	_, span := tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("nullfield.event_type", string(event.Type)),
			attribute.String("nullfield.method", event.Method),
			attribute.String("nullfield.tool", event.ToolName),
			attribute.String("nullfield.identity", event.Identity),
		),
	)
	defer span.End()

	if event.Reason != "" {
		span.SetAttributes(attribute.String("nullfield.reason", event.Reason))
	}
	if event.Error != "" {
		span.SetAttributes(attribute.String("nullfield.error", event.Error))
		span.SetStatus(codes.Error, event.Error)
	}

	switch event.Type {
	case EventToolDenied, EventIdentityFailed, EventCircuitTripped:
		span.SetStatus(codes.Error, event.Reason)
	case EventToolAllowed:
		span.SetStatus(codes.Ok, "")
	case EventHoldCreated:
		span.SetAttributes(attribute.String("nullfield.hold_status", "pending"))
	case EventHoldApproved:
		span.SetAttributes(attribute.String("nullfield.hold_status", "approved"))
	case EventScopeModified:
		span.SetAttributes(attribute.String("nullfield.scope_modifications", event.Reason))
	case EventAnomalyVelocity:
		span.SetAttributes(attribute.String("nullfield.anomaly_type", "velocity"))
	}
}
