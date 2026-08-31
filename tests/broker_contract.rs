use std::time::Duration;

use bytes::Bytes;
use rustmq::{
    broker::{Broker, Outbound, SubscriptionOptions},
    protocol::{Packet, Publish},
};
use tokio::sync::mpsc;

#[tokio::test]
async fn unsubscribing_shared_filter_removes_the_member() {
    let broker = Broker::new();
    let (sender_a, mut receiver_a) = mpsc::channel(4);
    let (sender_b, mut receiver_b) = mpsc::channel(4);
    let (close_a, _close_rx_a) = mpsc::channel(1);
    let (close_b, _close_rx_b) = mpsc::channel(1);
    broker.register("a", false, sender_a, close_a);
    broker.register("b", false, sender_b, close_b);
    broker.subscribe("a", "$share/workers/jobs/+", 0).unwrap();
    broker.subscribe("b", "$share/workers/jobs/+", 0).unwrap();

    broker.unsubscribe("a", "$share/workers/jobs/+");
    broker.publish(Publish {
        dup: false,
        qos: 0,
        retain: false,
        topic: "jobs/42".into(),
        packet_id: None,
        payload: Bytes::from_static(b"work"),
        expires_at: None,
        subscription_identifiers: Vec::new(),
        topic_alias: None,
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver_a.recv())
            .await
            .is_err()
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), receiver_b.recv()).await,
        Ok(Some(Outbound::Packet(Packet::Publish(_))))
    ));
}

#[tokio::test]
async fn resubscribing_shared_filter_does_not_duplicate_membership() {
    let broker = Broker::new();
    let (sender_a, mut receiver_a) = mpsc::channel(4);
    let (sender_b, mut receiver_b) = mpsc::channel(4);
    let (close_a, _close_rx_a) = mpsc::channel(1);
    let (close_b, _close_rx_b) = mpsc::channel(1);
    broker.register("a", false, sender_a, close_a);
    broker.register("b", false, sender_b, close_b);
    broker.subscribe("a", "$share/workers/jobs/+", 0).unwrap();
    broker.subscribe("a", "$share/workers/jobs/+", 0).unwrap();
    broker.subscribe("b", "$share/workers/jobs/+", 0).unwrap();

    for payload in [b"one".as_slice(), b"two".as_slice()] {
        broker.publish(Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic: "jobs/42".into(),
            packet_id: None,
            payload: Bytes::copy_from_slice(payload),
            expires_at: None,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        });
    }

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), receiver_a.recv()).await,
        Ok(Some(Outbound::Packet(Packet::Publish(_))))
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), receiver_b.recv()).await,
        Ok(Some(Outbound::Packet(Packet::Publish(_))))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver_a.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn full_outbound_queue_signals_disconnect_on_control_channel() {
    let broker = Broker::new();
    let (sender, _receiver) = mpsc::channel(1);
    let (disconnect, mut disconnect_rx) = mpsc::channel(1);
    broker.register("slow", true, sender, disconnect);
    broker.subscribe("slow", "load/#", 0).unwrap();

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        broker.publish(Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic: "load/topic".into(),
            packet_id: None,
            payload: Bytes::copy_from_slice(payload),
            expires_at: None,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        });
    }

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), disconnect_rx.recv()).await,
        Ok(Some(()))
    ));
    assert_eq!(
        broker
            .metrics()
            .dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn mqtt_v5_subscription_options_control_live_and_retained_delivery() {
    let broker = Broker::new();
    let (sender, mut receiver) = mpsc::channel(8);
    let (disconnect, _disconnect_rx) = mpsc::channel(1);
    broker.register("subscriber", false, sender, disconnect);

    broker.publish_from(
        Some("publisher"),
        Publish {
            dup: false,
            qos: 1,
            retain: true,
            topic: "options/retained".into(),
            packet_id: Some(1),
            payload: Bytes::from_static(b"retained"),
            expires_at: None,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        },
    );

    let retained = broker
        .subscribe_with_options(
            "subscriber",
            "options/#",
            SubscriptionOptions {
                qos: 1,
                no_local: true,
                retain_as_published: true,
                retain_handling: 1,
                subscription_identifier: None,
            },
        )
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].retain);

    let retained_on_update = broker
        .subscribe_with_options(
            "subscriber",
            "options/#",
            SubscriptionOptions {
                qos: 1,
                no_local: true,
                retain_as_published: true,
                retain_handling: 1,
                subscription_identifier: None,
            },
        )
        .unwrap();
    assert!(retained_on_update.is_empty());

    broker.publish_from(
        Some("subscriber"),
        Publish {
            dup: false,
            qos: 1,
            retain: true,
            topic: "options/local".into(),
            packet_id: Some(2),
            payload: Bytes::from_static(b"local"),
            expires_at: None,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        },
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err()
    );

    broker.publish_from(
        Some("publisher"),
        Publish {
            dup: false,
            qos: 1,
            retain: true,
            topic: "options/remote".into(),
            packet_id: Some(3),
            payload: Bytes::from_static(b"remote"),
            expires_at: None,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        },
    );
    let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let Outbound::Packet(Packet::Publish(delivered)) = delivered else {
        panic!("expected delivered publish");
    };
    assert!(delivered.retain);

    let never_retained = broker
        .subscribe_with_options(
            "subscriber",
            "never/#",
            SubscriptionOptions {
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 2,
                subscription_identifier: None,
            },
        )
        .unwrap();
    assert!(never_retained.is_empty());
}

#[tokio::test]
async fn qos2_protocol_frames_do_not_inflate_delivered_message_metric() {
    let broker = Broker::new();
    let (sender, mut receiver) = mpsc::channel(8);
    let (disconnect, _disconnect_rx) = mpsc::channel(1);
    broker.register("metrics-sub", false, sender, disconnect);
    broker.subscribe("metrics-sub", "metrics/qos2", 2).unwrap();

    broker.publish(Publish {
        dup: false,
        qos: 2,
        retain: false,
        topic: "metrics/qos2".into(),
        packet_id: Some(7),
        payload: Bytes::from_static(b"one-message"),
        expires_at: None,
        subscription_identifiers: Vec::new(),
        topic_alias: None,
    });
    let Some(Outbound::Packet(Packet::Publish(publish))) = receiver.recv().await else {
        panic!("expected outbound QoS 2 PUBLISH");
    };
    let packet_id = publish.packet_id.unwrap();
    assert_eq!(
        broker
            .metrics()
            .delivered
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    assert!(broker.pubrec("metrics-sub", packet_id));
    assert!(matches!(
        receiver.recv().await,
        Some(Outbound::Packet(Packet::PubRel(id))) if id == packet_id
    ));
    broker.retry_due("metrics-sub", Duration::ZERO);
    assert!(matches!(
        receiver.recv().await,
        Some(Outbound::Packet(Packet::PubRel(id))) if id == packet_id
    ));
    assert_eq!(
        broker
            .metrics()
            .delivered
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn overlapping_subscriptions_merge_subscription_identifiers() {
    let broker = Broker::new();
    let (sender, mut receiver) = mpsc::channel(8);
    let (disconnect, _disconnect_rx) = mpsc::channel(1);
    broker.register("sid-client", false, sender, disconnect);

    for (filter, identifier) in [("sid/#", 7), ("sid/topic", 321), ("+/topic", 7)] {
        broker
            .subscribe_with_options(
                "sid-client",
                filter,
                SubscriptionOptions {
                    qos: 1,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: 0,
                    subscription_identifier: Some(identifier),
                },
            )
            .unwrap();
    }

    broker.publish(Publish {
        dup: false,
        qos: 1,
        retain: false,
        topic: "sid/topic".into(),
        packet_id: Some(1),
        payload: Bytes::from_static(b"identified"),
        expires_at: None,
        subscription_identifiers: Vec::new(),
        topic_alias: None,
    });

    let Some(Outbound::Packet(Packet::Publish(publish))) = receiver.recv().await else {
        panic!("expected identified PUBLISH");
    };
    assert_eq!(publish.subscription_identifiers, vec![7, 321]);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err()
    );
}
