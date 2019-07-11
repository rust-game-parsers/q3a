use {
    byteorder::{NetworkEndian, WriteBytesExt},
    nom::{bytes::complete::*, combinator::rest, number::complete::*, *},
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        ffi::CString,
        fmt::{self, Display},
        io::Write,
        net::{Ipv4Addr, SocketAddrV4},
        str::FromStr,
    },
};

named!(pub read_cstring_cons<&[u8], CString>, do_parse!(
    s: map_res!(take_till!(|v| v == 0), CString::new) >>
    take!(1) >>
    (s)
));

named!(pub read_string_rest<&[u8], String>, do_parse!(
    s: map!(rest, |b| String::from_utf8_lossy(b).to_string()) >>
    (s)
));

const KV_SEPARATOR: u8 = 0x5C;
const KV_SEPARATOR_S: &str = "\\";

fn parse_kv_word(i: &[u8]) -> nom::IResult<&[u8], String> {
    let (i, _) = tag(KV_SEPARATOR_S)(i)?;
    let (i, data) = take_till(|c| c == KV_SEPARATOR || c == b'\n')(i)?;

    Ok((i, String::from_utf8_lossy(&data).to_string()))
}

named!(parse_kv_pair(&[u8]) -> (String, String), do_parse!(
    key: parse_kv_word >>
    value: parse_kv_word >>
    (key, value)
));

named!(parse_kv_pairs(&[u8]) -> HashMap<String, String>, do_parse!(
    pairs: many_till!( parse_kv_pair, eof!() ) >>
    (pairs.0.into_iter().collect::<_>())
));

named!(parse_kv_pairs_till_nl(&[u8]) -> HashMap<String, String>, do_parse!(
    pairs: many_till!( parse_kv_pair, tag!("\n") ) >>
    (pairs.0.into_iter().collect::<_>())
));

fn write_kv_pairs<K, V>(
    pairs: &mut dyn Iterator<Item = (K, V)>,
    out: &mut dyn Write,
) -> Result<(), failure::Error>
where
    K: AsRef<str> + Display + Ord,
    V: AsRef<str> + Display + Ord,
{
    for (k, v) in pairs.collect::<BTreeMap<_, _>>() {
        out.write_all(format!("\\{}", k).as_bytes())?;
        out.write_all(format!("\\{}", v).as_bytes())?;
    }

    Ok(())
}

named!(parse_ip_addr<&[u8], SocketAddrV4>, do_parse!(
    a: be_u8 >>
    b: be_u8 >>
    c: be_u8 >>
    d: be_u8 >>
    port: be_u16 >>
    tag!(KV_SEPARATOR_S) >>
    (SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
));

named!(parse_ip_addrs<&[u8], HashSet<SocketAddrV4>>, do_parse!(
    tag!(KV_SEPARATOR_S) >>
    data: many_till!( parse_ip_addr, tag!("EOT") ) >>
    (data.0.into_iter().collect::<_>())
));

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub struct Info {
    pub info: HashMap<String, String>,
}

impl Info {
    named!(from_bytes<&[u8], Self>, do_parse!(
        tag!("\n") >>
        info: parse_kv_pairs >>
        (Self { info })
    ));

    fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
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
    named!(from_bytes<&[u8], Self>,
        do_parse!(
            challenge: read_string_rest >>
            (Self { challenge })
        )
    );

    fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
        out.write_all(format!(" {}", &self.challenge).as_bytes())?;
        Ok(())
    }
}

pub type GetInfoData = RequestData;
pub type GetStatusData = RequestData;

#[derive(Clone, Debug, PartialEq)]
pub struct Player {
    pub score: u32,
    pub ping: u32,
    pub name: String,
}

impl Player {
    named!(from_bytes(&[u8]) -> Self,
      do_parse!(
        score: map_res!(take_until!(" "), |b: &[u8]| u32::from_str(&String::from_utf8_lossy(b))) >> tag!(" ") >>
        ping: map_res!(take_until!(" "), |b: &[u8]| u32::from_str(&String::from_utf8_lossy(b))) >> tag!(" ") >>
        name: map!(delimited!(tag!("\""), take_until!("\""), tag!("\"")), |b| String::from_utf8_lossy(b).to_string()) >>
        tag!("\n") >>
        (Self { score, ping, name })
      )
    );

    fn to_bytes(&self) -> Vec<u8> {
        format!("{} {} \"{}\"\n", self.score, self.ping, self.name).into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StatusResponseData {
    pub info: HashMap<String, String>,
    pub players: Vec<Player>,
}

impl StatusResponseData {
    named!(from_bytes<&[u8], Self>, do_parse!(
        tag!("\n") >>
        info: parse_kv_pairs_till_nl >>
        players: map!(many_till!(Player::from_bytes, eof!()), |(players, _)| players) >>
        (Self { info, players })
    ));

    fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
        out.write_all(b"\n")?;
        Info {
            info: self.info.clone(),
        }
        .write_bytes(out)?;
        out.write_all(b"\n")?;

        for player in &self.players {
            out.write_all(&player.to_bytes())?;
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
pub struct GetServersData {
    pub request_tag: Option<String>,
    pub version: u32,
    pub extra: HashSet<MasterQueryExtra>,
}

impl GetServersData {
    named!(from_bytes<&[u8], Self>, do_parse!(
        tag!(" ") >>
        version: map_res!(take_until!(" "), |b: &[u8]| u32::from_str(&String::from_utf8_lossy(b))) >>
        empty: map!(opt!(complete!(tag!(" empty"))), |v| v.is_some()) >>
        full: map!(opt!(complete!(tag!(" full"))), |v| v.is_some()) >>
        (Self {
            version,
            request_tag: None,
            extra: {
                let mut out = HashSet::new();
                for (flag, v) in &[(empty, MasterQueryExtra::Empty), (full, MasterQueryExtra::Full)] {
                    if *flag {
                        out.insert(*v);
                    }
                }
                out
            },
        })
    ));

    fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
        if let Some(request_tag) = &self.request_tag {
            out.write_all(&format!(" {}", request_tag).into_bytes())?;
        }
        out.write_all(&format!(" {}", self.version).into_bytes())?;
        for extra in &self.extra {
            out.write_all(&format!(" {}", extra).into_bytes())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetServersResponseData {
    pub data: HashSet<SocketAddrV4>,
}

impl GetServersResponseData {
    named!(from_bytes<&[u8], Self>, do_parse!(
        data: parse_ip_addrs >>
        (Self { data })
    ));

    fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
        for server in &self.data {
            out.write_all(&[KV_SEPARATOR])?;
            out.write_all(&server.ip().octets())?;
            out.write_u16::<NetworkEndian>(server.port())?
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    ChallengeRequest,
    ChallengeResponse(ChallengeResponseData),
    Connect(ConnectData),
    ConnectResponse,
    GetInfo(GetInfoData),
    GetMOTD(GetMOTDData),
    GetServers(GetServersData),
    GetServersResponse(GetServersResponseData),
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

    named!(pub from_bytes<&[u8], Packet>,
        do_parse!(
            tag!(<&[u8]>::from(&[255, 255, 255, 255])) >>
            packet_type: alt!(
                tag!("connect") => { |_| PacketType::Connect } |
                tag!("getinfo") => { |_| PacketType::GetInfo } |
                tag!("getmotd") => { |_| PacketType::GetMOTD } |
                tag!("getstatus") => { |_| PacketType::GetStatus } |
                tag!("getserversResponse") => { |_| PacketType::GetServersResponse } |
                tag!("getservers") => { |_| PacketType::GetServers } |
                tag!("getchallenge") => { |_| PacketType::ChallengeRequest } |
                tag!("infoResponse") => { |_| PacketType::InfoResponse } |
                tag!("statusResponse") => { |_| PacketType::StatusResponse } |
                tag!("connectResponse") => { |_| PacketType::ConnectResponse } |
                tag!("challengeResponse") => { |_| PacketType::ChallengeResponse }
            ) >>
            packet: switch!(value!(packet_type),
                PacketType::ChallengeRequest => value!(Packet::ChallengeRequest) |
                PacketType::ChallengeResponse => map!(ChallengeResponseData::from_bytes, Packet::ChallengeResponse) |
                PacketType::Connect => map!(ConnectData::from_bytes, Packet::Connect) |
                PacketType::ConnectResponse => value!(Packet::ConnectResponse) |
                PacketType::GetInfo => map!(GetInfoData::from_bytes, Packet::GetInfo) |
                PacketType::GetMOTD => map!(GetMOTDData::from_bytes, Packet::GetMOTD) |
                PacketType::GetServers => map!(GetServersData::from_bytes, Packet::GetServers) |
                PacketType::GetServersResponse => map!(GetServersResponseData::from_bytes, Packet::GetServersResponse) |
                PacketType::GetStatus => map!(GetStatusData::from_bytes, Packet::GetStatus) |
                PacketType::InfoResponse => map!(InfoResponseData::from_bytes, Packet::InfoResponse) |
                PacketType::StatusResponse => map!(StatusResponseData::from_bytes, Packet::StatusResponse)
            ) >>
            (packet)
        )
    );

    pub fn write_bytes(&self, out: &mut dyn Write) -> Result<(), failure::Error> {
        use Packet::*;

        out.write_all(&[255, 255, 255, 255])?;
        match self {
            GetServers(data) => {
                out.write_all(b"getservers")?;
                data.write_bytes(out)?;
            }
            GetServersResponse(data) => {
                out.write_all(b"getserversResponse")?;
                data.write_bytes(out)?;
            }
            GetInfo(data) => {
                out.write_all(b"getinfo")?;
                data.write_bytes(out)?;
            }
            GetStatus(data) => {
                out.write_all(b"getstatus")?;
                data.write_bytes(out)?;
            }
            StatusResponse(data) => {
                out.write_all(b"statusResponse")?;
                data.write_bytes(out)?;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use maplit::hashset;

    fn kv_pair_fixtures() -> (String, HashMap<String, String>) {
        let b = "\\g_needpass\\0\\gametype\\0\\pure\\1\\sv_maxclients\\8\\voip\\opus".to_string();
        let v = [
            ("g_needpass", "0"),
            ("pure", "1"),
            ("gametype", "0"),
            ("sv_maxclients", "8"),
            ("voip", "opus"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<HashMap<String, String>>();

        (b, v)
    }

    #[test]
    fn test_parse_kv_pairs() {
        let (fixture, expectation) = kv_pair_fixtures();

        let result = parse_kv_pairs(fixture.as_bytes()).unwrap().1;

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

        let result = Player::from_bytes(fixture).unwrap().1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn write_player_string() {
        let (expectation, fixture) = player_fixtures();

        let result = Player::to_bytes(&fixture);

        assert_eq!(expectation.to_vec(), result);
    }

    fn pkt_fixtures() -> Vec<(Vec<u8>, Packet)> {
        vec![
            (
                b"\xff\xff\xff\xffinfoResponse\n\\game\\cpma\\voip\\opus\\g_needpass\\0\\pure\\0\\gametype\\9\\sv_maxclients\\16\\g_humanplayers\\0\\clients\\0\\mapname\\cpm16\\hostname\\v2c - CPMA 1.48/CPM FFA/1V1/2V2/TDM/CTF/CTFS/NTF/HM - #1\\protocol\\68\\gamename\\Quake3Arena".to_vec(),
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
                    ]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<_>(),
                }),
            ),
            (
                b"\xff\xff\xff\xffgetservers 68 empty full".to_vec(),
                Packet::GetServers(GetServersData {
                    request_tag: None,
                    version: 68,
                    extra: hashset! {
                        MasterQueryExtra::Empty,
                        MasterQueryExtra::Full,
                    },
                }),
            ),
            (
                b"\xff\xff\xff\xffgetserversResponse\\\xb2\x3e\xca\xdb\x6d\x38\\\xbc\x28\x47\xd5\x6d\x42\\\x18\xa6\xfc\xd1\x6d\x3e\\EOT".to_vec(),
                Packet::GetServersResponse(GetServersResponseData {
                    data: vec![
                        "178.62.202.219:27960",
                        "188.40.71.213:27970",
                        "24.166.252.209:27966",
                    ]
                    .into_iter()
                    .map(|v| SocketAddrV4::from_str(v).unwrap())
                    .collect(),
                }),
            ),
            (
                b"\xff\xff\xff\xffstatusResponse\n\\challenge\\RGS\\dmflags\\8\\fraglimit\\20\\timelimit\\15\\sv_privateClients\\0\\sv_hostname\\games.on.net #5 Q3A (NSW)\\sv_maxclients\\16\\sv_punkbuster\\0\\sv_maxRate\\0\\sv_minPing\\0\\sv_maxPing\\500\\sv_floodProtect\\0\\sv_allowDownload\\1\\bot_minplayers\\2\\g_needpass\\0\\capturelimit\\8\\g_maxGameClients\\0\\g_gametype\\0\\version\\Q3 1.32c win-x86 May  8 2006\\protocol\\68\\mapname\\q3dm8\\.Administrator\\Wishful Thinking!\\.Website\\www.games.on.net\\.Location\\Sydney, Australia\\.TeamSpeak3\\ts3.wishfulthinkings.net\\sv_dlURL\\http://cdn.wishfulthinkings.net\\gamename\\baseq3\n8 0 \"Xaero\"\n".to_vec(),
                Packet::StatusResponse(StatusResponseData {
                    info: [
                        ("g_needpass", "0"),
                        (".Administrator", "Wishful Thinking!"),
                        ("sv_punkbuster", "0"),
                        ("sv_maxPing", "500"),
                        ("sv_privateClients", "0"),
                        ("sv_hostname", "games.on.net #5 Q3A (NSW)"),
                        ("version", "Q3 1.32c win-x86 May  8 2006"),
                        ("sv_dlURL", "http://cdn.wishfulthinkings.net"),
                        ("g_maxGameClients", "0"),
                        ("fraglimit", "20"),
                        ("capturelimit", "8"),
                        ("mapname", "q3dm8"),
                        ("dmflags", "8"),
                        ("sv_allowDownload", "1"),
                        ("timelimit", "15"),
                        ("sv_maxRate", "0"),
                        (".TeamSpeak3", "ts3.wishfulthinkings.net"),
                        ("sv_floodProtect", "0"),
                        ("sv_maxclients", "16"),
                        (".Location", "Sydney, Australia"),
                        ("protocol", "68"),
                        ("sv_minPing", "0"),
                        ("g_gametype", "0"),
                        (".Website", "www.games.on.net"),
                        ("challenge", "RGS"),
                        ("bot_minplayers", "2"),
                        ("gamename", "baseq3"),
                    ]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<_>(),
                    players: vec![Player {
                        name: "Xaero".to_string(),
                        ping: 0,
                        score: 8,
                    }],
                }),
            ),
        ]
    }

    #[test]
    fn parse() {
        for (input, expectation) in &pkt_fixtures() {
            let result = Packet::from_bytes(input).unwrap().1;

            assert_eq!(*expectation, result);
        }
    }
}
