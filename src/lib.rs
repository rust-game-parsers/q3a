#[macro_use]
extern crate maplit;
#[macro_use]
extern crate nom;
extern crate atoi;

use nom::{rest, types::CompleteByteSlice, Context, ErrorKind};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::fmt::Display;
use std::net::SocketAddrV4;

named!(pub read_cstring_cons<CompleteByteSlice, CString>, do_parse!(
    s: map_res!(take_till!(|v| v == 0), |b: CompleteByteSlice| CString::new(*b)) >>
    take!(1) >>
    (s)
));

named!(pub read_string_rest<CompleteByteSlice, String>, do_parse!(
    s: map!(rest, |b| String::from_utf8_lossy(*b).to_string()) >>
    (s)
));

static KV_SEPARATOR: u8 = 0x5C;
static KV_SEPARATOR_S: &'static str = "\\";

named!(parse_kv_word<CompleteByteSlice, String>, do_parse!(
    tag!(KV_SEPARATOR_S) >>
    data: take_till!(|c| c == KV_SEPARATOR || c == b'\n') >>
    (String::from_utf8_lossy(&data).to_string())
));

named!(parse_kv_pair<CompleteByteSlice, (String, String)>, do_parse!(
    key: parse_kv_word >>
    value: parse_kv_word >>
    (key, value)
));

named!(parse_kv_pairs<CompleteByteSlice, HashMap<String, String>>, do_parse!(
    pairs: many_till!( parse_kv_pair, eof!() ) >>
    (pairs.0.into_iter().collect::<_>())
));

fn write_kv_pairs<K, V>(pairs: &mut Iterator<Item = (K, V)>) -> Vec<u8>
where
    K: AsRef<str> + Display + Ord,
    V: AsRef<str> + Display + Ord,
{
    pairs
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .fold(Vec::new(), |mut out, (k, v)| {
            out.extend_from_slice(&mut format!("\\{}", k).as_bytes());
            out.extend_from_slice(&mut format!("\\{}", v).as_bytes());

            out
        })
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChallengeResponseData {
    pub id: String,
}

impl ChallengeResponseData {
    named!(from_bytes<CompleteByteSlice, Self>,
        do_parse!(
            id: read_string_rest >>
            (Self { id })
        )
    );
}

#[derive(Clone, Debug, PartialEq)]
pub struct Info {
    pub info: HashMap<String, String>,
}

impl Info {
    named!(from_bytes<CompleteByteSlice, Self>, do_parse!(
        info: parse_kv_pairs >>
        (Self { info })
    ));

    fn to_bytes(&self) -> Vec<u8> {
        write_kv_pairs(&mut self.info.iter())
    }
}

pub type InfoResponseData = Info;
pub type ConnectData = Info;
pub type GetMOTDData = Info;

#[derive(Clone, Debug, PartialEq)]
pub struct GetStatusData {
    pub challenge: String,
}

impl GetStatusData {
    named!(from_bytes<CompleteByteSlice, Self>,
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
    named!(from_bytes<CompleteByteSlice, Self>, do_parse!(
        score: map_opt!(take_until_and_consume!(" "), |b: CompleteByteSlice| atoi::atoi::<i32>(*b)) >>
        ping: map_opt!(take_until_and_consume!(" "), |b: CompleteByteSlice| atoi::atoi::<i32>(*b)) >>
        name: map!(delimited!(tag!("\""), take_until!("\""), tag!("\"")), |b| String::from_utf8_lossy(*b).to_string()) >>
        tag!("\n") >>
        (Self { score, ping, name })
    ));

    fn to_bytes(&self) -> Vec<u8> {
        format!("{} {} \"{}\"\n", self.score, self.ping, self.name).into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StatusResponseData {
    pub challenge: String,
    pub players: Vec<Player>,
}

impl StatusResponseData {
    named!(from_bytes<CompleteByteSlice, Self>, do_parse!(
        challenge: map_res!(parse_kv_pairs, |mut info: HashMap<String, String>| {
            info.remove("challenge").ok_or_else(|| nom::Err::Failure(Context::Code("No challenge in infostring", ErrorKind::Custom(999))))
        }) >>
        players: map!(many_till!(Player::from_bytes, tag!("\n")), |(players, _)| players) >>
        (Self { challenge, players })
    ));

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push('\n' as u8);
        out.append(&mut Info {
            info: hashmap! { "challenge".to_string() => self.challenge.clone() },
        }.to_bytes());
        out.push('\n' as u8);

        for player in self.players.iter() {
            out.append(&mut player.to_bytes());
        }

        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MasterQueryExtra {
    Empty,
    Full,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MasterQueryOptions {
    pub version: u8,
    pub extra: HashSet<MasterQueryExtra>,
}

pub type ServerList = HashSet<SocketAddrV4>;

#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    ChallengeRequest,
    ChallengeResponse(ChallengeResponseData),
    Connect(ConnectData),
    ConnectResponse,
    GetMOTD(GetMOTDData),
    GetServers(MasterQueryOptions),
    GetServersResponse(ServerList),
    GetStatus(GetStatusData),
    InfoResponse(InfoResponseData),
    StatusResponse(StatusResponseData),
}

#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    ChallengeRequest,
    ChallengeResponse,
    Connect,
    ConnectResponse,
    GetMOTD,
    GetServers,
    GetServersResponse,
    GetStatus,
    InfoResponse,
    StatusResponse,
}

impl Packet {
    pub fn get_type(&self) -> PacketType {
        use self::Packet::*;

        match *self {
            ChallengeRequest => PacketType::ChallengeRequest,
            ChallengeResponse(_) => PacketType::ChallengeResponse,
            Connect(_) => PacketType::Connect,
            ConnectResponse => PacketType::ConnectResponse,
            GetMOTD(_) => PacketType::GetMOTD,
            GetServers(_) => PacketType::GetServers,
            GetServersResponse(_) => PacketType::GetServersResponse,
            GetStatus(_) => PacketType::GetStatus,
            InfoResponse(_) => PacketType::InfoResponse,
            StatusResponse(_) => PacketType::StatusResponse,
        }
    }

    named!(pub from_bytes<CompleteByteSlice, Packet>,
        do_parse!(
            tag!(<&[u8]>::from(&[255, 255, 255, 255])) >>
            packet_type: alt!(
                tag!("connect") => { |_| PacketType::Connect } |
                tag!("getmotd") => { |_| PacketType::GetMOTD } |
                tag!("getStatus") => { |_| PacketType::GetStatus } |
                tag!("getchallenge") => { |_| PacketType::ChallengeRequest } |
                tag!("infoResponse") => { |_| PacketType::InfoResponse } |
                tag!("statusResponse") => { |_| PacketType::StatusResponse } |
                tag!("connectResponse") => { |_| PacketType::ConnectResponse } |
                tag!("challengeResponse") => { |_| PacketType::ChallengeResponse }
            ) >>
            tag!("\n") >>
            packet: switch!(value!(packet_type),
                PacketType::ChallengeRequest => value!(Packet::ChallengeRequest) |
                PacketType::ChallengeResponse => map!(ChallengeResponseData::from_bytes, Packet::ChallengeResponse) |
                PacketType::Connect => map!(ConnectData::from_bytes, Packet::Connect) |
                PacketType::ConnectResponse => value!(Packet::ConnectResponse) |
                PacketType::GetMOTD => map!(GetMOTDData::from_bytes, Packet::GetMOTD) |
                PacketType::GetStatus => map!(GetStatusData::from_bytes, Packet::GetStatus) |
                PacketType::InfoResponse => map!(InfoResponseData::from_bytes, Packet::InfoResponse) |
                PacketType::StatusResponse => map!(StatusResponseData::from_bytes, Packet::StatusResponse)
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

    fn kv_pair_fixtures() -> (String, HashMap<String, String>) {
        let b = "\\g_needpass\\0\\gametype\\0\\pure\\1\\sv_maxclients\\8\\voip\\opus".to_string();
        let v = [
            ("g_needpass", "0"),
            ("pure", "1"),
            ("gametype", "0"),
            ("sv_maxclients", "8"),
            ("voip", "opus"),
        ].iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<String, String>>();

        (b, v)
    }

    #[test]
    fn test_parse_kv_pairs() {
        let (fixture, expectation) = kv_pair_fixtures();

        let result = parse_kv_pairs(CompleteByteSlice(fixture.as_bytes()))
            .unwrap()
            .1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn test_write_kv_pairs() {
        let (expectation, fixture) = kv_pair_fixtures();

        let result = write_kv_pairs(&mut fixture.into_iter());

        assert_eq!(expectation.into_bytes(), result);
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

        let result = Player::from_bytes(CompleteByteSlice(fixture)).unwrap().1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn write_player_string() {
        let (expectation, fixture) = player_fixtures();

        let result = Player::to_bytes(&fixture);

        assert_eq!(expectation.to_vec(), result);
    }

    fn inforesponse_fixtures() -> (Vec<u8>, Packet) {
        (
            include_bytes!("test_payload/inforesponse.raw").to_vec(),
            Packet::InfoResponse(InfoResponseData {
                info: [
                    ("game", "cpma"),
                    ("voip", "opus"),
                    ("g_needpass", "0"),
                    ("pure", "0"),
                    ("gametype", "9"),
                    ("sv_maxclients", "16"),
                    ("g_humanplayers", "0"),
                    ("clients", "0"),
                    ("mapname", "cpm16"),
                    (
                        "hostname",
                        "v2c - CPMA 1.48/CPM FFA/1V1/2V2/TDM/CTF/CTFS/NTF/HM - #1",
                    ),
                    ("protocol", "68"),
                    ("gamename", "Quake3Arena"),
                ].iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<_>(),
            }),
        )
    }

    #[test]
    fn parse_inforesponse() {
        let (input, expectation) = inforesponse_fixtures();

        let result = Packet::from_bytes(CompleteByteSlice(&input)).unwrap().1;

        assert_eq!(expectation, result);
    }
}
