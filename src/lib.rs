extern crate atoi;
extern crate failure;
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate nom;

use nom::{rest, types::CompleteByteSlice, Context, ErrorKind};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::fmt;
use std::fmt::Display;
use std::io::Write;
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

fn write_kv_pairs<K, V>(
    pairs: &mut Iterator<Item = (K, V)>,
    out: &mut Write,
) -> Result<(), failure::Error>
where
    K: AsRef<str> + Display + Ord,
    V: AsRef<str> + Display + Ord,
{
    for (k, v) in pairs.collect::<BTreeMap<_, _>>().into_iter() {
        out.write_all(&mut format!("\\{}", k).as_bytes())?;
        out.write_all(&mut format!("\\{}", v).as_bytes())?;
    }

    Ok(())
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

    fn write_bytes(&self, out: &mut Write) -> Result<(), failure::Error> {
        write_kv_pairs(&mut self.info.iter(), out)
    }
}

pub type InfoResponseData = Info;
pub type ConnectData = Info;
pub type GetMOTDData = Info;

#[derive(Clone, Debug, PartialEq)]
pub struct RequestData {
    pub challenge: String,
}

impl RequestData {
    named!(from_bytes<CompleteByteSlice, Self>,
        do_parse!(
            challenge: read_string_rest >>
            (Self { challenge })
        )
    );

    fn write_bytes(&self, out: &mut Write) -> Result<(), failure::Error> {
        out.write_all(format!(" {}", &self.challenge).as_bytes())?;
        Ok(())
    }
}

pub type GetInfoData = RequestData;
pub type GetStatusData = RequestData;

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

    fn write_bytes(&self, out: &mut Write) -> Result<(), failure::Error> {
        out.write_all(&['\n' as u8])?;
        Info {
            info: hashmap! { "challenge".to_string() => self.challenge.clone() },
        }.write_bytes(out)?;
        out.write_all(&['\n' as u8])?;

        for player in self.players.iter() {
            out.write_all(&mut player.to_bytes())?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MasterQueryExtra {
    Empty,
    Full,
}

impl Display for MasterQueryExtra {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use MasterQueryExtra::*;

        write!(
            fmt,
            "{}",
            match self {
                Empty => "empty",
                Full => "full",
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MasterQueryOptions {
    pub version: u8,
    pub extra: HashSet<MasterQueryExtra>,
}

impl MasterQueryOptions {
    fn write_bytes(&self, out: &mut Write) -> Result<(), failure::Error> {
        out.write_all(&mut format!(" {}", self.version).into_bytes())?;
        for extra in self.extra.iter() {
            out.write_all(&mut extra.to_string().into_bytes())?;
        }
        Ok(())
    }
}

pub type ServerList = HashSet<SocketAddrV4>;

#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    ChallengeRequest,
    ChallengeResponse(ChallengeResponseData),
    Connect(ConnectData),
    ConnectResponse,
    GetInfo(GetInfoData),
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
    GetInfo,
    GetMOTD,
    GetServers,
    GetServersResponse,
    GetStatus,
    InfoResponse,
    StatusResponse,
}

impl Packet {
    pub fn get_type(&self) -> PacketType {
        use Packet::*;

        match *self {
            ChallengeRequest => PacketType::ChallengeRequest,
            ChallengeResponse(_) => PacketType::ChallengeResponse,
            Connect(_) => PacketType::Connect,
            ConnectResponse => PacketType::ConnectResponse,
            GetInfo(_) => PacketType::GetInfo,
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
                tag!("getinfo") => { |_| PacketType::GetInfo } |
                tag!("getmotd") => { |_| PacketType::GetMOTD } |
                tag!("getstatus") => { |_| PacketType::GetStatus } |
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
                PacketType::GetInfo => map!(GetInfoData::from_bytes, Packet::GetInfo) |
                PacketType::GetMOTD => map!(GetMOTDData::from_bytes, Packet::GetMOTD) |
                PacketType::GetStatus => map!(GetStatusData::from_bytes, Packet::GetStatus) |
                PacketType::InfoResponse => map!(InfoResponseData::from_bytes, Packet::InfoResponse) |
                PacketType::StatusResponse => map!(StatusResponseData::from_bytes, Packet::StatusResponse)
            ) >>
            (packet)
        )
    );

    pub fn write_bytes(&self, out: &mut Write) -> Result<(), failure::Error> {
        use Packet::*;

        out.write_all(&mut vec![255, 255, 255, 255])?;
        match self {
            GetServers(opts) => {
                out.write_all("getservers".as_bytes())?;
                opts.write_bytes(out)?;
            }
            GetInfo(data) => {
                out.write_all("getinfo".as_bytes())?;
                data.write_bytes(out)?;
            }
            GetStatus(data) => {
                out.write_all("getstatus".as_bytes())?;
                data.write_bytes(out)?;
            }
            StatusResponse(data) => {
                out.write_all("statusResponse".as_bytes())?;
                data.write_bytes(out)?;
            }
            _ => {
                unimplemented!()
            }
        }

        Ok(())
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

        let mut result = Vec::new();
        write_kv_pairs(&mut fixture.into_iter(), &mut result).unwrap();

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
