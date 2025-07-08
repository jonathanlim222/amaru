//! Escaped JSON fields formatter for tracing-subscriber
//! 
//! This crate provides a transparent solution to the JSON escaping issue with tracing-subscriber's JsonFields.
//! The problem occurs when using Debug formatting (`?field`) with fields containing special JSON characters.
//! 
//! ## Usage
//! 
//! Simply replace `JsonFields::new()` with `EscapedJsonFields::new()`:
//! 
//! ```rust
//! use tracing_json::EscapedJsonFields;
//! use tracing_subscriber::fmt;
//! 
//! let layer = fmt::layer()
//!     .event_format(fmt::format().json())
//!     .fmt_fields(EscapedJsonFields::new());  // Instead of JsonFields::new()
//! ```

pub mod escaped_fields;

pub use escaped_fields::EscapedJsonFields;

use assert_json_diff::assert_json_eq;
use serde_json as json;
use std::sync::{Arc, RwLock};
use tracing::Dispatch;
use tracing_subscriber::layer::SubscriberExt;

#[repr(transparent)]
#[derive(Clone, Default)]
pub struct JsonTraceCollector(Arc<RwLock<Vec<json::Value>>>);

impl JsonTraceCollector {
    fn insert(&self, value: json::Value) {
        if let Ok(mut lines) = self.0.write() {
            lines.push(value);
        }
    }

    pub fn flush(&self) -> Vec<json::Value> {
        match self.0.read() {
            Ok(traces) => traces.clone(),
            // The RwLock can only get poisoned should the thread panic while pushing a new line
            // onto the stack. In case this happen, we'll likely be missing traces which should be
            // caught by assertions down the line anyway. So it is fine here to simply return the
            // 'possibly corrupted' data.
            Err(err) => err.into_inner().clone(),
        }
    }
}

#[derive(Default)]
struct JsonVisitor {
    fields: json::Map<String, json::Value>,
}

impl JsonVisitor {
    #[allow(clippy::unwrap_used)]
    fn add_field(&mut self, json_path: &str, value: json::Value) {
        let steps = json_path.split('.').collect::<Vec<_>>();

        if steps.is_empty() {
            return;
        }

        if steps.len() == 1 {
            self.fields.insert(json_path.to_string(), value);
            return;
        }

        // Safe because we just ensured steps is never empty
        let (root, children) = steps.split_first().unwrap();

        let mut current_value = self
            .fields
            .entry(root.to_string())
            .or_insert_with(|| json::json!({}));

        for &key in children.iter().take(children.len() - 1) {
            if !current_value.is_object() {
                *current_value = json::json!({});
            }

            // Safe because we just ensured current_value is an object
            let current_object = current_value.as_object_mut().unwrap();

            if !current_object.contains_key(key) {
                current_object.insert(key.to_string(), json::json!({}));
            }

            // Safe because we just inserted the key if it didn't exist
            current_value = current_object.get_mut(key).unwrap()
        }

        if let Some(last) = children.last() {
            if !current_value.is_object() {
                *current_value = json::json!({});
            }

            // Safe because we just ensured that current_value is always an object
            current_value
                .as_object_mut()
                .unwrap()
                .insert(last.to_string(), value);
        }
    }
}

macro_rules! record_t {
    ($title:ident, $ty:ty) => {
        fn $title(&mut self, field: &tracing::field::Field, value: $ty) {
            self.add_field(field.name(), json::json!(value));
        }
    };
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.add_field(field.name(), json::json!(format!("{:?}", value)))
    }

    record_t!(record_f64, f64);
    record_t!(record_i64, i64);
    record_t!(record_u64, u64);
    record_t!(record_i128, i128);
    record_t!(record_u128, u128);
    record_t!(record_bool, bool);
    record_t!(record_str, &str);

    fn record_bytes(&mut self, field: &tracing::field::Field, value: &[u8]) {
        self.add_field(field.name(), json::json!(hex::encode(value)));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.add_field(field.name(), json::json!(format!("{}", value)))
    }
}

struct JsonLayer(JsonTraceCollector);

impl JsonLayer {
    pub fn new(collector: JsonTraceCollector) -> Self {
        Self(collector)
    }
}

impl<S> tracing_subscriber::Layer<S> for JsonLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        attrs.record(&mut visitor);

        if let Some(span) = ctx.span(id) {
            // Store the fields in the span for later use
            let mut extensions = span.extensions_mut();
            extensions.insert(visitor.fields);
        }
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut span_json = json::json!({
                "name": span.name().to_string() + "_span",
            });

            if let Some(fields) = span.extensions().get::<json::Map<String, json::Value>>() {
                for (key, value) in fields {
                    span_json[key] = value.clone();
                }
            }

            self.0.insert(span_json);
        }
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        let name = visitor
            .fields
            .remove("message")
            .and_then(|value| value.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let mut event_json = json::json!({
            "name": name + "_event",
        });

        for (key, value) in visitor.fields {
            event_json[key] = value.clone();
        }

        self.0.insert(event_json);
    }
}

/// TODO: Write some documentation on expectations and usage.
pub fn assert_trace<F, R>(run: F, expected: Vec<json::Value>) -> R
where
    F: FnOnce() -> R,
{
    let collector = JsonTraceCollector::default();
    let layer = JsonLayer::new(collector.clone());
    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let result = run();
    assert_json_eq!(
        json::Value::Array(collector.flush()),
        json::Value::Array(expected)
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracing::{info, info_span};

    #[test]
    fn assert_simple_tracing() {
        assert_eq!(
            assert_trace(
                || {
                    info_span!("foo").in_scope(|| {
                        info!(a = 1, "basic");
                        info!(a.foo = 1, a.bar = 2, "nested_fields");
                        "result"
                    })
                },
                vec![
                    json!({ "name": "foo_span" }),
                    json!({ "name": "basic_event", "a": 1 }),
                    json!({ "name": "nested_fields_event", "a": { "foo": 1, "bar": 2 } }),
                ],
            ),
            "result"
        );
    }

    #[test]
    fn test_escaped_json_fields_integration() {
        use crate::EscapedJsonFields;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::SubscriberExt;
        use std::sync::{Arc, Mutex};
        
        #[derive(Debug)]
        struct ProblematicStruct {
            value: String,
        }

        let problematic = ProblematicStruct {
            value: "contains \"quotes\" and \n newlines \t tabs".to_string(),
        };

        // Capture output in a buffer using Arc<Mutex<Vec<u8>>>
        let output = Arc::new(Mutex::new(Vec::new()));
        let output_clone = output.clone();
        
        {
            let layer = fmt::layer()
                .event_format(fmt::format().json())
                .fmt_fields(EscapedJsonFields::new())
                .with_writer(move || {
                    TestWriter::new(output_clone.clone())
                });
                
            let subscriber = tracing_subscriber::registry().with(layer);
            let dispatch = tracing::Dispatch::new(subscriber);
            let _guard = tracing::dispatcher::set_default(&dispatch);

            // This pattern was problematic with tracing-subscriber's JsonFields
            info!(?problematic, "test message");
        }

        let output_bytes = output.lock().unwrap().clone();
        let output_str = String::from_utf8(output_bytes).expect("Should be valid UTF-8");
        println!("JSON output: {}", output_str);
        
        // Parse as JSON to ensure it's valid
        let json_obj: serde_json::Value = serde_json::from_str(&output_str).expect("Should be valid JSON");
        
        // Verify the problematic field was properly escaped
        assert!(json_obj["fields"]["problematic"].is_string());
        let debug_value = json_obj["fields"]["problematic"].as_str().unwrap();
        assert!(debug_value.contains("ProblematicStruct"));
        assert!(debug_value.contains("contains"));
    }

    // Test writer that implements std::io::Write for capturing output
    struct TestWriter {
        output: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl TestWriter {
        fn new(output: Arc<std::sync::Mutex<Vec<u8>>>) -> Self {
            Self { output }
        }
    }

    impl std::io::Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
