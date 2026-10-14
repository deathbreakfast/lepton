//! Forwarding adapters whose target can be replaced while the process runs.

#[cfg(any(feature = "email", feature = "phone"))]
use std::sync::{Arc, PoisonError, RwLock};

#[cfg(feature = "phone")]
use lepton_sms::{SmsDeliveryError, SmsDeliveryReceipt, SmsDeliveryService, SmsEnvelope};
#[cfg(feature = "email")]
use lepton_smtp::{
    DeliveryReceipt, EmailDeliveryError, EmailDeliveryService, EmailDriver, EmailEnvelope,
};

/// [`EmailDeliveryService`] that forwards to a replaceable inner adapter.
#[cfg(feature = "email")]
pub struct SwappableEmail {
    inner: RwLock<Arc<dyn EmailDeliveryService>>,
}

#[cfg(feature = "email")]
impl SwappableEmail {
    /// Wrap `initial` as the adapter used until the first [`swap`](Self::swap).
    #[must_use]
    pub fn new(initial: Arc<dyn EmailDeliveryService>) -> Self {
        Self {
            inner: RwLock::new(initial),
        }
    }

    /// Replace the wrapped adapter and return the previous one.
    ///
    /// Sends already in flight finish on the previous adapter.
    pub fn swap(&self, next: Arc<dyn EmailDeliveryService>) -> Arc<dyn EmailDeliveryService> {
        let mut slot = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *slot, next)
    }

    /// The adapter new sends will use.
    #[must_use]
    pub fn current(&self) -> Arc<dyn EmailDeliveryService> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(feature = "email")]
#[async_trait::async_trait]
impl EmailDeliveryService for SwappableEmail {
    fn driver(&self) -> EmailDriver {
        self.current().driver()
    }

    async fn send(&self, envelope: &EmailEnvelope) -> Result<DeliveryReceipt, EmailDeliveryError> {
        // Clone the Arc out of the lock first: the guard is never held across `.await`.
        let adapter = self.current();
        adapter.send(envelope).await
    }
}

/// [`SmsDeliveryService`] that forwards to a replaceable inner adapter.
#[cfg(feature = "phone")]
pub struct SwappableSms {
    inner: RwLock<Arc<dyn SmsDeliveryService>>,
}

#[cfg(feature = "phone")]
impl SwappableSms {
    /// Wrap `initial` as the adapter used until the first [`swap`](Self::swap).
    #[must_use]
    pub fn new(initial: Arc<dyn SmsDeliveryService>) -> Self {
        Self {
            inner: RwLock::new(initial),
        }
    }

    /// Replace the wrapped adapter and return the previous one.
    ///
    /// Sends already in flight finish on the previous adapter.
    pub fn swap(&self, next: Arc<dyn SmsDeliveryService>) -> Arc<dyn SmsDeliveryService> {
        let mut slot = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *slot, next)
    }

    /// The adapter new sends will use.
    #[must_use]
    pub fn current(&self) -> Arc<dyn SmsDeliveryService> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(feature = "phone")]
#[async_trait::async_trait]
impl SmsDeliveryService for SwappableSms {
    fn driver_name(&self) -> &'static str {
        self.current().driver_name()
    }

    async fn send(&self, envelope: &SmsEnvelope) -> Result<SmsDeliveryReceipt, SmsDeliveryError> {
        let adapter = self.current();
        adapter.send(envelope).await
    }
}

#[cfg(all(test, feature = "email", feature = "phone"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    struct FakeEmail {
        driver: EmailDriver,
        provider: &'static str,
        sent: AtomicUsize,
        gate: Option<Arc<Notify>>,
    }

    #[async_trait::async_trait]
    impl EmailDeliveryService for FakeEmail {
        fn driver(&self) -> EmailDriver {
            self.driver
        }
        async fn send(&self, _: &EmailEnvelope) -> Result<DeliveryReceipt, EmailDeliveryError> {
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(DeliveryReceipt {
                provider: self.provider.to_string(),
                message_id: None,
            })
        }
    }

    struct FakeSms(&'static str);

    #[async_trait::async_trait]
    impl SmsDeliveryService for FakeSms {
        fn driver_name(&self) -> &'static str {
            self.0
        }
        async fn send(&self, _: &SmsEnvelope) -> Result<SmsDeliveryReceipt, SmsDeliveryError> {
            Ok(SmsDeliveryReceipt {
                provider: self.0.to_string(),
                message_id: None,
            })
        }
    }

    fn envelope() -> EmailEnvelope {
        EmailEnvelope {
            to: "reader@example.test".into(),
            subject: "s".into(),
            text_body: "t".into(),
            html_body: "<p>t</p>".into(),
        }
    }

    fn fake(driver: EmailDriver, provider: &'static str) -> Arc<FakeEmail> {
        Arc::new(FakeEmail {
            driver,
            provider,
            sent: AtomicUsize::new(0),
            gate: None,
        })
    }

    #[tokio::test]
    async fn swap_routes_next_send_to_new_adapter_and_returns_previous() {
        let first = fake(EmailDriver::Noop, "first");
        let second = fake(EmailDriver::Smtp, "second");
        let svc = SwappableEmail::new(first.clone());
        assert_eq!(svc.send(&envelope()).await.unwrap().provider, "first");

        let previous = svc.swap(second.clone());
        assert_eq!(previous.driver(), EmailDriver::Noop);
        assert_eq!(svc.driver(), EmailDriver::Smtp);
        assert_eq!(svc.send(&envelope()).await.unwrap().provider, "second");
        assert_eq!(first.sent.load(Ordering::SeqCst), 1);
        assert_eq!(second.sent.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn in_flight_send_finishes_on_adapter_it_started_with() {
        let gate = Arc::new(Notify::new());
        let slow = Arc::new(FakeEmail {
            driver: EmailDriver::Noop,
            provider: "slow",
            sent: AtomicUsize::new(0),
            gate: Some(gate.clone()),
        });
        let svc = Arc::new(SwappableEmail::new(slow.clone()));
        let in_flight = {
            let svc = svc.clone();
            tokio::spawn(async move { svc.send(&envelope()).await })
        };
        // Let the spawned send park on the gate, then swap underneath it.
        tokio::task::yield_now().await;
        svc.swap(fake(EmailDriver::Smtp, "fast"));
        gate.notify_one();
        let receipt = in_flight.await.unwrap().unwrap();
        assert_eq!(receipt.provider, "slow");
        assert_eq!(slow.sent.load(Ordering::SeqCst), 1);
        assert_eq!(svc.send(&envelope()).await.unwrap().provider, "fast");
    }

    #[tokio::test]
    async fn sms_swap_changes_driver_name_and_send_target() {
        let svc = SwappableSms::new(Arc::new(FakeSms("noop")));
        let msg = SmsEnvelope {
            to_e164: "+15550100".into(),
            body: "b".into(),
            otp_code: None,
        };
        assert_eq!(svc.driver_name(), "noop");
        svc.swap(Arc::new(FakeSms("twilio_verify")));
        assert_eq!(svc.driver_name(), "twilio_verify");
        assert_eq!(svc.send(&msg).await.unwrap().provider, "twilio_verify");
    }
}
