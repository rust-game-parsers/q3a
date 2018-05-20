#[macro_use]
extern crate nom;
extern crate atoi;

use nom::{rest, Context, ErrorKind};
use std::collections::HashMap;
use std::ffi::CString;

named!(pub read_cstring_cons<&[u8], CString>, do_parse!(
    s: map_res!(take_till!(|v| v == 0), CString::new) >>
    take!(1) >>
    (s)
));

named!(pub read_string_rest<&[u8], String>, do_parse!(
    s: map!(rest, |b| String::from_utf8_lossy(b).to_string()) >>
    (s)
));

static KV_SEPARATOR: u8 = 0x5C;
static KV_SEPARATOR_S: &'static str = "\\";

named!(parse_kv_word<&[u8], String>, do_parse!(
    tag!(KV_SEPARATOR_S) >>
    data: take_till!(|c| c == KV_SEPARATOR || c == b'\n') >>
    (String::from_utf8_lossy(&data).to_string())
));

named!(parse_kv_pair<&[u8], (String, String)>, do_parse!(
    key: parse_kv_word >>
    value: parse_kv_word >>
    (key, value)
));

named!(parse_kv_pairs<&[u8], HashMap<String, String>>, do_parse!(
    pairs: many_till!( parse_kv_pair, tag!("\n") ) >>
    (pairs.0.into_iter().collect::<_>())
));

pub struct ChallengeResponseData {
    pub id: String,
}

impl ChallengeResponseData {
    named!(from_bytes<&[u8], Self>,
        do_parse!(
            id: read_string_rest >>
            (Self { id })
        )
    );
}

pub struct Info {
    pub info: HashMap<String, String>,
}

impl Info {
    named!(from_bytes<&[u8], Self>, do_parse!(
        info: parse_kv_pairs >>
        (Self { info })
    ));
}

pub type InfoResponseData = Info;
pub type ConnectData = Info;

pub struct GetStatusData {
    pub challenge: String,
}

impl GetStatusData {
    named!(from_bytes<&[u8], Self>,
        do_parse!(
            challenge: read_string_rest >>
            (Self { challenge })
        )
    );
}

#[derive(Clone, Debug, PartialEq)]
pub struct Player {
    pub score: i32,
    pub ping: i32,
    pub name: String,
}

impl Player {
    named!(pub from_bytes<&[u8], Self>, do_parse!(
        score: map_opt!(take_until_and_consume!(" "), atoi::atoi::<i32>) >>
        ping: map_opt!(take_until_and_consume!(" "), atoi::atoi::<i32>) >>
        name: map!(delimited!(tag!("\""), take_until!("\""), tag!("\"")), |b| String::from_utf8_lossy(b).to_string()) >>
        tag!("\n") >>
        (Self { score, ping, name })
    ));

    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{} {} \"{}\"\n", self.score, self.ping, self.name).into_bytes()
    }
}

pub struct StatusResponseData {
    pub challenge: String,
    pub players: Vec<Player>,
}

impl StatusResponseData {
    named!(pub from_bytes<&[u8], Self>, do_parse!(
        challenge: map_res!(parse_kv_pairs, |mut info: HashMap<String, String>| {
            info.remove("challenge").ok_or_else(|| nom::Err::Failure(Context::Code("No challenge in infostring", ErrorKind::Custom(999))))
        }) >>
        players: map!(many_till!(Player::from_bytes, tag!("\n")), |(players, _)| players) >>
        (Self { challenge, players })
    ));
}

pub enum Packet {
    ChallengeRequest,
    ChallengeResponse(ChallengeResponseData),
    Connect(ConnectData),
    ConnectResponse,
    GetStatus(GetStatusData),
    InfoResponse(InfoResponseData),
    StatusResponse(StatusResponseData),
}

pub enum PacketType {
    ChallengeRequest,
    ChallengeResponse,
    Connect,
    ConnectResponse,
    GetStatus,
    InfoResponse,
    StatusResponse,
}

impl Packet {
    named!(pub from_bytes<&[u8], Packet>,
        do_parse!(
            tag!(&[255, 255, 255, 255]) >>
            packet_type: alt!(
                tag!("connect") => { |_| PacketType::Connect } |
                tag!("getStatus") => { |_| PacketType::GetStatus } |
                tag!("getchallenge") => { |_| PacketType::ChallengeRequest } |
                tag!("infoResponse") => { |_| PacketType::InfoResponse } |
                tag!("statusResponse") => { |_| PacketType::StatusResponse } |
                tag!("connectResponse") => { |_| PacketType::ConnectResponse } |
                tag!("challengeResponse") => { |_| PacketType::ChallengeResponse }
            ) >>
            packet: switch!(value!(packet_type),
                PacketType::GetStatus => map!(GetStatusData::from_bytes, Packet::GetStatus) |
                PacketType::ChallengeRequest => value!(Packet::ChallengeRequest) |
                PacketType::InfoResponse => map!(InfoResponseData::from_bytes, Packet::InfoResponse) |
                PacketType::StatusResponse => map!(StatusResponseData::from_bytes, Packet::StatusResponse) |
                PacketType::Connect => map!(ConnectData::from_bytes, Packet::Connect) |
                PacketType::ConnectResponse => value!(Packet::ConnectResponse) |
                PacketType::ChallengeResponse => map!(ChallengeResponseData::from_bytes, Packet::ChallengeResponse)
            ) >>
            (packet)
        )
    );

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.append(&mut vec![255, 255, 255, 255]);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kv_pairs() {
        let fixture =
            "\\voip\\opus\\g_needpass\\0\\pure\\1\\gametype\\0\\sv_maxclients\\8\n".to_string();
        let expectation = [
            ("voip", "opus"),
            ("g_needpass", "0"),
            ("pure", "1"),
            ("gametype", "0"),
            ("sv_maxclients", "8"),
        ].iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<String, String>>();

        let result = parse_kv_pairs(fixture.as_bytes()).unwrap().1;

        assert_eq!(expectation, result);
    }

    fn player_fixtures<'a>() -> (&'a [u8], Player) {
        let b = "9000 30 \"Grunt\"\n".as_bytes();
        let p = Player {
            score: 9000,
            ping: 30,
            name: "Grunt".to_string(),
        };
        (b, p)
    }

    #[test]
    fn parse_player_string() {
        let (fixture, expectation) = player_fixtures();

        let result = Player::from_bytes(fixture).unwrap().1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn write_player_string() {
        let (expectation, fixture) = player_fixtures();

        let result = Player::to_bytes(&fixture);

        assert_eq!(expectation.to_vec(), result);
    }
}
