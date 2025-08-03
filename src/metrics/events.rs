#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketEvent {
    ClientInvalidResponse,
    ClientReceiveFailed,
    ClientResponseReceived,
    ClientSendFailed,
    ClientRequestSent,
    ServerPacketTooShort,
    ServerReceiveFailed,
    ServerRequestReceived,
    ServerSendFailed,
    ServerResponseSent,
    ServerUnsupportedVersion,
}

impl PacketEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketEvent::ClientInvalidResponse => "client_invalid_response",
            PacketEvent::ClientReceiveFailed => "client_receive_failed",
            PacketEvent::ClientResponseReceived => "client_response_received",
            PacketEvent::ClientSendFailed => "client_send_failed",
            PacketEvent::ClientRequestSent => "client_request_sent",
            PacketEvent::ServerPacketTooShort => "server_packet_too_short",
            PacketEvent::ServerReceiveFailed => "server_receive_failed",
            PacketEvent::ServerRequestReceived => "server_request_received",
            PacketEvent::ServerSendFailed => "server_send_failed",
            PacketEvent::ServerResponseSent => "server_response_sent",
            PacketEvent::ServerUnsupportedVersion => "server_unsupported_version",
        }
    }
}
