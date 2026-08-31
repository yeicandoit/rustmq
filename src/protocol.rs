use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    V311,
    V5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Will {
    pub topic: String,
    pub payload: Bytes,
    pub qos: u8,
    pub retain: bool,
    pub delay_interval: u32,
    pub message_expiry_interval: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connect {
    pub version: ProtocolVersion,
    pub client_id: String,
    pub clean_start: bool,
    pub keep_alive: u16,
    pub session_expiry_interval: u32,
    pub receive_maximum: u16,
    pub topic_alias_maximum: u16,
    pub username: Option<String>,
    pub password: Option<Bytes>,
    pub will: Option<Will>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publish {
    pub dup: bool,
    pub qos: u8,
    pub retain: bool,
    pub topic: String,
    pub packet_id: Option<u16>,
    pub payload: Bytes,
    pub expires_at: Option<Instant>,
    pub subscription_identifiers: Vec<u32>,
    pub topic_alias: Option<u16>,
}

impl Publish {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|deadline| deadline <= Instant::now())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscription {
    pub filter: String,
    pub qos: u8,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    Connect(Connect),
    ConnAck {
        session_present: bool,
        code: u8,
        topic_alias_maximum: Option<u16>,
    },
    Publish(Publish),
    PubAck(u16),
    PubRec(u16),
    PubRel(u16),
    PubComp(u16),
    Subscribe {
        packet_id: u16,
        subscription_identifier: Option<u32>,
        filters: Vec<Subscription>,
    },
    SubAck {
        packet_id: u16,
        codes: Vec<u8>,
    },
    Unsubscribe {
        packet_id: u16,
        filters: Vec<String>,
    },
    UnsubAck {
        packet_id: u16,
        codes: Vec<u8>,
    },
    PingReq,
    PingResp,
    Disconnect {
        reason_code: u8,
        session_expiry_interval: Option<u32>,
    },
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8> {
        let v = *self.data.get(self.pos).context("truncated packet")?;
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        let a = self.u8()?;
        let b = self.u8()?;
        Ok(u16::from_be_bytes([a, b]))
    }
    fn u32(&mut self) -> Result<u32> {
        let a = self.u8()?;
        let b = self.u8()?;
        let c = self.u8()?;
        let d = self.u8()?;
        Ok(u32::from_be_bytes([a, b, c, d]))
    }
    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).context("length overflow")?;
        let value = self.data.get(self.pos..end).context("truncated packet")?;
        self.pos = end;
        Ok(value)
    }
    fn binary(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.bytes(len)
    }
    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.binary()?.to_vec()).context("invalid UTF-8")
    }
    fn varint(&mut self) -> Result<usize> {
        let mut value = 0;
        let mut multiplier = 1;
        for _ in 0..4 {
            let b = self.u8()?;
            value += usize::from(b & 0x7f) * multiplier;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            multiplier *= 128;
        }
        bail!("malformed variable integer")
    }
    fn properties(&mut self) -> Result<()> {
        let len = self.varint()?;
        self.bytes(len)?;
        Ok(())
    }
    fn property_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()?;
        self.bytes(len)
    }
    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        self.pos = self.data.len();
        rest
    }
    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

fn remaining_length(data: &[u8]) -> Result<Option<(usize, usize)>> {
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for index in 0..4 {
        let Some(&byte) = data.get(index) else {
            return Ok(None);
        };
        value = value
            .checked_add(usize::from(byte & 0x7f) * multiplier)
            .context("length overflow")?;
        if byte & 0x80 == 0 {
            return Ok(Some((value, index + 1)));
        }
        multiplier *= 128;
    }
    bail!("malformed remaining length")
}

pub fn decode_packet(
    buffer: &mut BytesMut,
    version: ProtocolVersion,
    max_size: usize,
) -> Result<Option<Packet>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let header = buffer[0];
    let Some((length, length_bytes)) = remaining_length(&buffer[1..])? else {
        return Ok(None);
    };
    if length > max_size {
        bail!("packet exceeds configured maximum");
    }
    let total = 1 + length_bytes + length;
    if buffer.len() < total {
        return Ok(None);
    }
    let frame = buffer.split_to(total).freeze();
    parse_frame(header, &frame[1 + length_bytes..], version).map(Some)
}

fn packet_id(cursor: &mut Cursor<'_>) -> Result<u16> {
    let id = cursor.u16()?;
    if id == 0 {
        bail!("packet identifier cannot be zero")
    }
    Ok(id)
}
fn parse_frame(header: u8, body: &[u8], version: ProtocolVersion) -> Result<Packet> {
    let packet_type = header >> 4;
    let flags = header & 0x0f;
    let mut c = Cursor::new(body);
    let packet = match packet_type {
        1 => parse_connect(&mut c, flags)?,
        3 => {
            let qos = (header >> 1) & 3;
            if qos == 3 {
                bail!("invalid publish QoS")
            }
            let topic = c.string()?;
            let id = if qos > 0 {
                Some(packet_id(&mut c)?)
            } else {
                None
            };
            let publish_properties = if version == ProtocolVersion::V5 {
                parse_publish_properties(c.property_bytes()?)?
            } else {
                PublishProperties::default()
            };
            Packet::Publish(Publish {
                dup: header & 8 != 0,
                qos,
                retain: header & 1 != 0,
                topic,
                packet_id: id,
                payload: Bytes::copy_from_slice(c.rest()),
                expires_at: publish_properties.expires_at,
                subscription_identifiers: publish_properties.subscription_identifiers,
                topic_alias: publish_properties.topic_alias,
            })
        }
        4 if flags == 0 => Packet::PubAck(packet_id(&mut c)?),
        5 if flags == 0 => Packet::PubRec(packet_id(&mut c)?),
        6 if flags == 2 => Packet::PubRel(packet_id(&mut c)?),
        7 if flags == 0 => Packet::PubComp(packet_id(&mut c)?),
        8 if flags == 2 => {
            let id = packet_id(&mut c)?;
            let subscription_identifier = if version == ProtocolVersion::V5 {
                parse_subscribe_properties(c.property_bytes()?)?
            } else {
                None
            };
            let mut filters = Vec::new();
            while !c.done() {
                let filter = c.string()?;
                let options = c.u8()?;
                let qos = options & 3;
                let no_local = options & 4 != 0;
                let retain_as_published = options & 8 != 0;
                let retain_handling = (options >> 4) & 3;
                if qos == 3 {
                    bail!("invalid subscription QoS")
                }
                if version == ProtocolVersion::V311 {
                    if options & 0xfc != 0 {
                        bail!("MQTT 3.1.1 subscription options contain reserved bits")
                    }
                } else if options & 0xc0 != 0 || retain_handling == 3 {
                    bail!("invalid MQTT 5 subscription options")
                }
                if no_local && filter.starts_with("$share/") {
                    bail!("No Local is forbidden for shared subscriptions")
                }
                filters.push(Subscription {
                    filter,
                    qos,
                    no_local,
                    retain_as_published,
                    retain_handling,
                });
            }
            if filters.is_empty() {
                bail!("empty subscribe")
            };
            Packet::Subscribe {
                packet_id: id,
                subscription_identifier,
                filters,
            }
        }
        10 if flags == 2 => {
            let id = packet_id(&mut c)?;
            if version == ProtocolVersion::V5 {
                c.properties()?;
            }
            let mut filters = Vec::new();
            while !c.done() {
                filters.push(c.string()?);
            }
            if filters.is_empty() {
                bail!("empty unsubscribe")
            };
            Packet::Unsubscribe {
                packet_id: id,
                filters,
            }
        }
        12 if flags == 0 && body.is_empty() => Packet::PingReq,
        14 if flags == 0 => parse_disconnect(&mut c, version)?,
        _ => bail!("unsupported or malformed MQTT packet type {packet_type}"),
    };
    Ok(packet)
}

fn parse_connect(c: &mut Cursor<'_>, flags: u8) -> Result<Packet> {
    if flags != 0 {
        bail!("invalid CONNECT flags")
    };
    let name = c.string()?;
    let level = c.u8()?;
    let version = match (name.as_str(), level) {
        ("MQTT", 4) => ProtocolVersion::V311,
        ("MQTT", 5) => ProtocolVersion::V5,
        _ => bail!("unsupported MQTT protocol"),
    };
    let connect_flags = c.u8()?;
    if connect_flags & 1 != 0 {
        bail!("reserved CONNECT flag")
    };
    let clean_start = connect_flags & 2 != 0;
    let will_flag = connect_flags & 4 != 0;
    let will_qos = (connect_flags >> 3) & 3;
    let will_retain = connect_flags & 0x20 != 0;
    if !will_flag && (will_qos != 0 || will_retain) || will_qos == 3 {
        bail!("invalid will flags")
    };
    let keep_alive = c.u16()?;
    let connect_properties = if version == ProtocolVersion::V5 {
        parse_connect_properties(c.property_bytes()?)?
    } else if clean_start {
        ConnectProperties {
            session_expiry_interval: 0,
            receive_maximum: u16::MAX,
            topic_alias_maximum: 0,
        }
    } else {
        ConnectProperties {
            session_expiry_interval: u32::MAX,
            receive_maximum: u16::MAX,
            topic_alias_maximum: 0,
        }
    };
    let client_id = c.string()?;
    if client_id.is_empty() && !clean_start {
        bail!("empty persistent client id")
    };
    let will = if will_flag {
        let will_properties = if version == ProtocolVersion::V5 {
            parse_will_properties(c.property_bytes()?)?
        } else {
            WillProperties::default()
        };
        Some(Will {
            topic: c.string()?,
            payload: Bytes::copy_from_slice(c.binary()?),
            qos: will_qos,
            retain: will_retain,
            delay_interval: will_properties.delay_interval,
            message_expiry_interval: will_properties.message_expiry_interval,
        })
    } else {
        None
    };
    let username = if connect_flags & 0x80 != 0 {
        Some(c.string()?)
    } else {
        None
    };
    let password = if connect_flags & 0x40 != 0 {
        Some(Bytes::copy_from_slice(c.binary()?))
    } else {
        None
    };
    if !c.done() {
        bail!("trailing CONNECT data")
    };
    Ok(Packet::Connect(Connect {
        version,
        client_id,
        clean_start,
        keep_alive,
        session_expiry_interval: connect_properties.session_expiry_interval,
        receive_maximum: connect_properties.receive_maximum,
        topic_alias_maximum: connect_properties.topic_alias_maximum,
        username,
        password,
        will,
    }))
}

fn parse_disconnect(c: &mut Cursor<'_>, version: ProtocolVersion) -> Result<Packet> {
    if version == ProtocolVersion::V311 {
        if !c.done() {
            bail!("MQTT 3.1.1 DISCONNECT must have an empty body")
        }
        return Ok(Packet::Disconnect {
            reason_code: 0,
            session_expiry_interval: None,
        });
    }
    if c.done() {
        return Ok(Packet::Disconnect {
            reason_code: 0,
            session_expiry_interval: None,
        });
    }
    let reason_code = c.u8()?;
    if c.done() {
        return Ok(Packet::Disconnect {
            reason_code,
            session_expiry_interval: None,
        });
    }
    let mut properties = Cursor::new(c.property_bytes()?);
    let mut session_expiry_interval = None;
    while !properties.done() {
        match properties.varint()? {
            0x11 => {
                if session_expiry_interval.is_some() {
                    bail!("duplicate Session Expiry Interval in DISCONNECT")
                }
                session_expiry_interval = Some(properties.u32()?);
            }
            0x1f | 0x1c => {
                properties.string()?;
            }
            0x26 => {
                properties.string()?;
                properties.string()?;
            }
            identifier => bail!("property {identifier:#x} is not valid in DISCONNECT"),
        }
    }
    if !c.done() {
        bail!("trailing DISCONNECT data")
    }
    Ok(Packet::Disconnect {
        reason_code,
        session_expiry_interval,
    })
}

#[derive(Default)]
struct WillProperties {
    delay_interval: u32,
    message_expiry_interval: Option<u32>,
}

fn parse_will_properties(data: &[u8]) -> Result<WillProperties> {
    let mut properties = Cursor::new(data);
    let mut result = WillProperties::default();
    let mut delay_seen = false;
    let mut payload_format_seen = false;
    let mut content_type_seen = false;
    let mut response_topic_seen = false;
    let mut correlation_data_seen = false;
    while !properties.done() {
        match properties.varint()? {
            0x01 => {
                if payload_format_seen {
                    bail!("duplicate Will Payload Format Indicator")
                }
                payload_format_seen = true;
                if properties.u8()? > 1 {
                    bail!("Will Payload Format Indicator must be 0 or 1")
                }
            }
            0x02 => {
                if result.message_expiry_interval.is_some() {
                    bail!("duplicate Will Message Expiry Interval")
                }
                result.message_expiry_interval = Some(properties.u32()?);
            }
            0x03 => {
                if content_type_seen {
                    bail!("duplicate Will Content Type")
                }
                content_type_seen = true;
                properties.string()?;
            }
            0x08 => {
                if response_topic_seen {
                    bail!("duplicate Will Response Topic")
                }
                response_topic_seen = true;
                properties.string()?;
            }
            0x09 => {
                if correlation_data_seen {
                    bail!("duplicate Will Correlation Data")
                }
                correlation_data_seen = true;
                properties.binary()?;
            }
            0x18 => {
                if delay_seen {
                    bail!("duplicate Will Delay Interval")
                }
                delay_seen = true;
                result.delay_interval = properties.u32()?;
            }
            0x26 => {
                properties.string()?;
                properties.string()?;
            }
            identifier => bail!("property {identifier:#x} is not valid in Will properties"),
        }
    }
    Ok(result)
}

fn parse_subscribe_properties(data: &[u8]) -> Result<Option<u32>> {
    let mut properties = Cursor::new(data);
    let mut subscription_identifier = None;
    while !properties.done() {
        match properties.varint()? {
            0x0b => {
                if subscription_identifier.is_some() {
                    bail!("duplicate Subscription Identifier in SUBSCRIBE")
                }
                let identifier = u32::try_from(properties.varint()?)
                    .context("Subscription Identifier exceeds u32")?;
                if identifier == 0 {
                    bail!("Subscription Identifier cannot be zero")
                }
                subscription_identifier = Some(identifier);
            }
            0x26 => {
                properties.string()?;
                properties.string()?;
            }
            identifier => bail!("property {identifier:#x} is not valid in SUBSCRIBE"),
        }
    }
    Ok(subscription_identifier)
}

#[derive(Default)]
struct PublishProperties {
    expires_at: Option<Instant>,
    subscription_identifiers: Vec<u32>,
    topic_alias: Option<u16>,
}

fn parse_publish_properties(data: &[u8]) -> Result<PublishProperties> {
    let mut properties = Cursor::new(data);
    let mut result = PublishProperties::default();
    let mut payload_format_seen = false;
    let mut content_type_seen = false;
    let mut response_topic_seen = false;
    let mut correlation_data_seen = false;
    let mut topic_alias_seen = false;
    while !properties.done() {
        match properties.varint()? {
            0x01 => {
                if payload_format_seen {
                    bail!("duplicate Payload Format Indicator")
                }
                payload_format_seen = true;
                if properties.u8()? > 1 {
                    bail!("Payload Format Indicator must be 0 or 1")
                }
            }
            0x02 => {
                if result.expires_at.is_some() {
                    bail!("duplicate Message Expiry Interval")
                }
                let seconds = properties.u32()?;
                result.expires_at = Some(Instant::now() + Duration::from_secs(u64::from(seconds)));
            }
            0x03 => {
                if content_type_seen {
                    bail!("duplicate Content Type")
                }
                content_type_seen = true;
                properties.string()?;
            }
            0x08 => {
                if response_topic_seen {
                    bail!("duplicate Response Topic")
                }
                response_topic_seen = true;
                properties.string()?;
            }
            0x09 => {
                if correlation_data_seen {
                    bail!("duplicate Correlation Data")
                }
                correlation_data_seen = true;
                properties.binary()?;
            }
            0x0b => {
                let identifier = u32::try_from(properties.varint()?)
                    .context("Subscription Identifier exceeds u32")?;
                if identifier == 0 {
                    bail!("Subscription Identifier cannot be zero")
                }
                result.subscription_identifiers.push(identifier);
            }
            0x23 => {
                if topic_alias_seen {
                    bail!("duplicate Topic Alias")
                }
                topic_alias_seen = true;
                let alias = properties.u16()?;
                if alias == 0 {
                    bail!("Topic Alias cannot be zero")
                }
                result.topic_alias = Some(alias);
            }
            0x26 => {
                properties.string()?;
                properties.string()?;
            }
            identifier => bail!("property {identifier:#x} is not valid in PUBLISH"),
        }
    }
    Ok(result)
}

struct ConnectProperties {
    session_expiry_interval: u32,
    receive_maximum: u16,
    topic_alias_maximum: u16,
}

fn parse_connect_properties(data: &[u8]) -> Result<ConnectProperties> {
    let mut properties = Cursor::new(data);
    let mut session_expiry = None;
    let mut receive_maximum = None;
    let mut topic_alias_maximum = None;
    let mut auth_method_seen = false;
    let mut auth_data_seen = false;
    while !properties.done() {
        match properties.varint()? {
            0x11 => {
                if session_expiry.is_some() {
                    bail!("duplicate Session Expiry Interval")
                }
                session_expiry = Some(properties.u32()?);
            }
            0x21 => {
                if receive_maximum.is_some() {
                    bail!("duplicate Receive Maximum")
                }
                let value = properties.u16()?;
                if value == 0 {
                    bail!("Receive Maximum cannot be zero")
                }
                receive_maximum = Some(value);
            }
            0x22 => {
                if topic_alias_maximum.is_some() {
                    bail!("duplicate Topic Alias Maximum")
                }
                topic_alias_maximum = Some(properties.u16()?);
            }
            0x17 | 0x19 => {
                if properties.u8()? > 1 {
                    bail!("boolean CONNECT property must be 0 or 1")
                }
            }
            0x15 => {
                if auth_method_seen {
                    bail!("duplicate Authentication Method")
                }
                auth_method_seen = true;
                properties.string()?;
            }
            0x16 => {
                if auth_data_seen {
                    bail!("duplicate Authentication Data")
                }
                auth_data_seen = true;
                properties.binary()?;
            }
            0x26 => {
                properties.string()?;
                properties.string()?;
            }
            0x27 => {
                if properties.u32()? == 0 {
                    bail!("Maximum Packet Size cannot be zero")
                }
            }
            identifier => bail!("property {identifier:#x} is not valid in CONNECT"),
        }
    }
    if auth_data_seen && !auth_method_seen {
        bail!("Authentication Data requires Authentication Method")
    }
    Ok(ConnectProperties {
        session_expiry_interval: session_expiry.unwrap_or(0),
        receive_maximum: receive_maximum.unwrap_or(u16::MAX),
        topic_alias_maximum: topic_alias_maximum.unwrap_or(0),
    })
}

fn put_varint(mut value: usize, out: &mut Vec<u8>) -> Result<()> {
    if value > 268_435_455 {
        bail!("packet too large")
    };
    loop {
        let mut b = u8::try_from(value % 128).expect("value modulo 128 fits in u8");
        value /= 128;
        if value > 0 {
            b |= 0x80;
        };
        out.push(b);
        if value == 0 {
            return Ok(());
        }
    }
}
fn put_string(value: &str, out: &mut Vec<u8>) -> Result<()> {
    let len = u16::try_from(value.len()).context("string too long")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn finish(header: u8, body: Vec<u8>) -> Result<Bytes> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(header);
    put_varint(body.len(), &mut out)?;
    out.extend(body);
    Ok(out.into())
}

pub fn encode_packet(packet: &Packet, version: ProtocolVersion) -> Result<Bytes> {
    let mut body = Vec::new();
    let (header, empty) = match packet {
        Packet::ConnAck {
            session_present,
            code,
            topic_alias_maximum,
        } => {
            body.push(u8::from(*session_present));
            body.push(*code);
            if version == ProtocolVersion::V5 {
                if let Some(maximum) = topic_alias_maximum {
                    body.push(3);
                    body.push(0x22);
                    body.extend_from_slice(&maximum.to_be_bytes());
                } else {
                    body.push(0);
                }
            };
            (0x20, false)
        }
        Packet::Publish(p) => {
            put_string(&p.topic, &mut body)?;
            if p.qos > 0 {
                body.extend_from_slice(
                    &p.packet_id.context("QoS publish missing id")?.to_be_bytes(),
                );
            };
            if version == ProtocolVersion::V5 {
                let mut properties = Vec::new();
                if let Some(deadline) = p.expires_at {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                    let seconds = u32::try_from(seconds).unwrap_or(u32::MAX);
                    properties.push(0x02);
                    properties.extend_from_slice(&seconds.to_be_bytes());
                }
                for identifier in &p.subscription_identifiers {
                    if *identifier == 0 {
                        bail!("Subscription Identifier cannot be zero")
                    }
                    properties.push(0x0b);
                    put_varint(
                        usize::try_from(*identifier)
                            .context("Subscription Identifier does not fit usize")?,
                        &mut properties,
                    )?;
                }
                if let Some(alias) = p.topic_alias {
                    if alias == 0 {
                        bail!("Topic Alias cannot be zero")
                    }
                    properties.push(0x23);
                    properties.extend_from_slice(&alias.to_be_bytes());
                }
                put_varint(properties.len(), &mut body)?;
                body.extend(properties);
            };
            body.extend_from_slice(&p.payload);
            (
                0x30 | (u8::from(p.dup) << 3) | (p.qos << 1) | u8::from(p.retain),
                false,
            )
        }
        Packet::PubAck(id) => {
            body.extend_from_slice(&id.to_be_bytes());
            (0x40, false)
        }
        Packet::PubRec(id) => {
            body.extend_from_slice(&id.to_be_bytes());
            (0x50, false)
        }
        Packet::PubRel(id) => {
            body.extend_from_slice(&id.to_be_bytes());
            (0x62, false)
        }
        Packet::PubComp(id) => {
            body.extend_from_slice(&id.to_be_bytes());
            (0x70, false)
        }
        Packet::SubAck { packet_id, codes } => {
            body.extend_from_slice(&packet_id.to_be_bytes());
            if version == ProtocolVersion::V5 {
                body.push(0);
            };
            body.extend(codes);
            (0x90, false)
        }
        Packet::UnsubAck { packet_id, codes } => {
            body.extend_from_slice(&packet_id.to_be_bytes());
            if version == ProtocolVersion::V5 {
                body.push(0);
                body.extend(codes);
            };
            (0xb0, false)
        }
        Packet::PingResp => (0xd0, true),
        Packet::Disconnect {
            reason_code,
            session_expiry_interval,
        } => {
            if version == ProtocolVersion::V5
                && (*reason_code != 0 || session_expiry_interval.is_some())
            {
                body.push(*reason_code);
                if let Some(expiry) = session_expiry_interval {
                    body.push(5);
                    body.push(0x11);
                    body.extend_from_slice(&expiry.to_be_bytes());
                } else {
                    body.push(0);
                }
                (0xe0, false)
            } else {
                (0xe0, true)
            }
        }
        _ => bail!("encoding this packet direction is unsupported"),
    };
    if empty {
        finish(header, Vec::new())
    } else {
        finish(header, body)
    }
}
